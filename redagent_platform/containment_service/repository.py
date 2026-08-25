"""Transactional PostgreSQL truth for compat_101 stop controls and hard quotas."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, or_, select, text, update

from redagent_platform.containment_service.control import activation_requires_dual_control
from redagent_platform.containment_service.contracts import (
    ContainmentOutcome,
    ControlScopeKind,
    PhaseReceipt,
    QuotaPolicy,
    StopApproval,
    StopRequest,
    aggregate_containment,
    canonical_stop_hash,
)
from redagent_platform.containment_service.quota import QuotaDecision, evaluate_quota
from redagent_platform.persistence.models import metadata


class ContainmentRepositoryConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class QuotaReservationResult:
    decision: QuotaDecision
    containment_control_id: str | None


@dataclass(frozen=True)
class QuotaAdjustmentResult:
    allowed: bool
    reason_code: str
    remaining_reserved: int
    containment_control_id: str | None


class ContainmentRepository:
    """All mutating methods require the caller's surrounding DB transaction."""

    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.actor_user_id = actor_user_id
        self.correlation_id = correlation_id

    async def request_stop(self, request: StopRequest) -> dict[str, object]:
        if request.tenant_id != self.tenant_id or request.initiated_by != self.actor_user_id:
            raise ContainmentRepositoryConflict("containment_request_actor_scope_mismatch")
        await self._context()
        await self._lock(f"stop-request:{request.idempotency_key}")
        table = metadata.tables["containment_controls"]
        request_hash = canonical_stop_hash(request)
        existing = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.idempotency_key == request.idempotency_key,
                )
            )
        ).mappings().one_or_none()
        if existing is not None:
            if str(existing["request_hash"]) != request_hash:
                raise ContainmentRepositoryConflict("containment_request_idempotency_mismatch")
            return dict(existing)
        immediate = not activation_requires_dual_control(request.scope.kind)
        row = {
            "id": f"containment-{uuid4().hex}", "tenant_id": self.tenant_id,
            "stop_id": request.stop_id, "scope_kind": request.scope.kind.value,
            "scope_id": request.scope.scope_id,
            "control_mode": "job_cancel" if immediate else "emergency_stop",
            "request_hash": request_hash, "idempotency_key": request.idempotency_key,
            "reason_hash": hashlib.sha256(request.reason.strip().encode()).hexdigest(),
            "initiated_by_user_id": request.initiated_by, "approved_by_user_id": None,
            "control_state": "active" if immediate else "pending_approval",
            "requested_at": request.requested_at,
            "activated_at": request.requested_at if immediate else None,
            "ack_deadline": request.requested_at + timedelta(seconds=10),
            "recovered_at": None, "version": 1,
            "created_at": request.requested_at, "updated_at": request.requested_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit_outbox(
            "containment.stop.requested", request.stop_id,
            {"scope": request.scope.canonical_key, "state": row["control_state"], "request_hash": request_hash},
            request.requested_at,
        )
        return row

    async def approve_stop(
        self,
        approval: StopApproval,
    ) -> dict[str, object]:
        if approval.tenant_id != self.tenant_id:
            raise ContainmentRepositoryConflict("stop_approval_tenant_mismatch")
        await self._context()
        await self._lock(f"stop-approval:{approval.stop_id}")
        controls = metadata.tables["containment_controls"]
        row = (
            await self.session.execute(
                select(controls).where(
                    controls.c.tenant_id == self.tenant_id,
                    controls.c.stop_id == approval.stop_id,
                ).with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            raise ContainmentRepositoryConflict("stop_control_not_found")
        # CRITICAL: broad control activation must preserve distinct-person approval.
        if str(row["initiated_by_user_id"]) == approval.approver_user_id:
            raise ContainmentRepositoryConflict("stop_approval_separation_required")
        if str(row["request_hash"]) != approval.request_hash:
            raise ContainmentRepositoryConflict("stop_approval_request_hash_mismatch")
        if approval.approved_at < row["requested_at"]:
            raise ContainmentRepositoryConflict("stop_approval_time_invalid")
        approvals = metadata.tables["containment_approvals"]
        existing = (
            await self.session.execute(
                select(approvals).where(
                    approvals.c.tenant_id == self.tenant_id,
                    approvals.c.approval_id == approval.approval_id,
                )
            )
        ).mappings().one_or_none()
        if existing is not None:
            if str(existing["request_hash"]) != approval.request_hash:
                raise ContainmentRepositoryConflict("stop_approval_replay_mismatch")
            return dict(row)
        if row["control_state"] != "pending_approval" or int(row["version"]) != approval.expected_version:
            raise ContainmentRepositoryConflict("stop_approval_stale")
        await self.session.execute(insert(approvals).values(
            id=f"containment-approval-{uuid4().hex}", tenant_id=self.tenant_id,
            control_id=row["id"], approval_id=approval.approval_id,
            approver_user_id=approval.approver_user_id, request_hash=approval.request_hash,
            approval_state="approved", approved_at=approval.approved_at,
            version=1, created_at=approval.approved_at, updated_at=approval.approved_at,
        ))
        await self.session.execute(
            update(controls).where(controls.c.id == row["id"]).values(
                approved_by_user_id=approval.approver_user_id,
                control_state="active", activated_at=approval.approved_at,
                version=int(row["version"]) + 1, updated_at=approval.approved_at,
            )
        )
        await self._audit_outbox(
            "containment.stop.activated", approval.stop_id,
            {"scope": f'{row["scope_kind"]}:{row["scope_id"] or "*"}', "request_hash": approval.request_hash},
            approval.approved_at,
        )
        return {
            **dict(row), "approved_by_user_id": approval.approver_user_id,
            "control_state": "active", "activated_at": approval.approved_at,
            "version": int(row["version"]) + 1, "updated_at": approval.approved_at,
        }

    async def active_control(
        self,
        *,
        campaign_id: str | None,
        job_id: str,
        capability_id: str,
    ) -> dict[str, object] | None:
        await self._context()
        table = metadata.tables["containment_controls"]
        predicates = [
            table.c.scope_kind == ControlScopeKind.GLOBAL.value,
            (table.c.scope_kind == ControlScopeKind.TENANT.value) & (table.c.scope_id == self.tenant_id),
            (table.c.scope_kind == ControlScopeKind.JOB.value) & (table.c.scope_id == job_id),
            (table.c.scope_kind == ControlScopeKind.CAPABILITY.value) & (table.c.scope_id == capability_id),
        ]
        if campaign_id is not None:
            predicates.append(
                (table.c.scope_kind == ControlScopeKind.CAMPAIGN.value) & (table.c.scope_id == campaign_id)
            )
        row = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.control_state == "active",
                    or_(*predicates),
                ).order_by(table.c.activated_at.asc()).limit(1)
            )
        ).mappings().one_or_none()
        return dict(row) if row is not None else None

    async def job_containment_status(self, job_id: str) -> dict[str, object] | None:
        """Return metadata-only latest stop/action/phase state for one exact job."""
        await self._context()
        controls = metadata.tables["containment_controls"]
        actions = metadata.tables["containment_job_actions"]
        row = (
            await self.session.execute(
                select(
                    controls.c.id.label("control_id"), controls.c.stop_id,
                    controls.c.control_state, controls.c.requested_at, controls.c.ack_deadline,
                    actions.c.id.label("action_id"), actions.c.action_state, actions.c.outcome,
                ).join(
                    actions,
                    (actions.c.control_id == controls.c.id)
                    & (actions.c.tenant_id == controls.c.tenant_id),
                    isouter=True,
                ).where(
                    controls.c.tenant_id == self.tenant_id,
                    or_(actions.c.job_id == job_id, (
                        (controls.c.scope_kind == ControlScopeKind.JOB.value)
                        & (controls.c.scope_id == job_id)
                    )),
                ).order_by(controls.c.requested_at.desc()).limit(1)
            )
        ).mappings().one_or_none()
        if row is None:
            return None
        action_id = row.get("action_id")
        phase_rows = []
        risks = []
        incidents = []
        if action_id is not None:
            phase_rows = list((await self.session.execute(select(
                metadata.tables["containment_phase_receipts"]
            ).where(
                metadata.tables["containment_phase_receipts"].c.tenant_id == self.tenant_id,
                metadata.tables["containment_phase_receipts"].c.action_id == action_id,
            ).order_by(metadata.tables["containment_phase_receipts"].c.created_at.asc()))).mappings().all())
            risks = list((await self.session.scalars(select(
                metadata.tables["containment_residual_risks"].c.risk_code
            ).where(
                metadata.tables["containment_residual_risks"].c.tenant_id == self.tenant_id,
                metadata.tables["containment_residual_risks"].c.action_id == action_id,
            ))).all())
            incidents = list((await self.session.scalars(select(
                metadata.tables["containment_incidents"].c.incident_id
            ).where(
                metadata.tables["containment_incidents"].c.tenant_id == self.tenant_id,
                metadata.tables["containment_incidents"].c.action_id == action_id,
                metadata.tables["containment_incidents"].c.incident_state == "open",
            ))).all())
        return {
            "job_id": job_id,
            "stop_id": str(row["stop_id"]),
            "control_id": str(row["control_id"]),
            "control_state": str(row["control_state"]),
            "requested_at": row["requested_at"],
            "ack_deadline": row["ack_deadline"],
            "action_state": str(row["action_state"]) if row.get("action_state") is not None else "not_started",
            "outcome": str(row["outcome"]) if row.get("outcome") is not None else None,
            "containment_complete": row.get("outcome") == ContainmentOutcome.CONTAINED.value,
            "phases": [
                {
                    "phase": str(item["phase"]), "state": str(item["phase_state"]),
                    "reason_code": str(item["reason_code"]),
                    "duration_ms": int(item["duration_ms"]), "occurred_at": item["occurred_at"],
                }
                for item in phase_rows
            ],
            "residual_risk_codes": [str(item) for item in risks],
            "open_incident_ids": [str(item) for item in incidents],
        }

    async def list_controls(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, object]]:
        await self._context()
        table = metadata.tables["containment_controls"]
        rows = (
            await self.session.execute(
                select(table).where(table.c.tenant_id == self.tenant_id)
                .order_by(table.c.requested_at.desc()).limit(limit).offset(offset)
            )
        ).mappings().all()
        return [_public_control(row) for row in rows]

    async def get_control(self, control_id: str) -> dict[str, object] | None:
        await self._context()
        table = metadata.tables["containment_controls"]
        row = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.id == control_id,
            ))
        ).mappings().one_or_none()
        return _public_control(row) if row is not None else None

    async def recover_control(
        self,
        *,
        control_id: str,
        review_id: str,
        expected_version: int,
        occurred_at: datetime,
    ) -> dict[str, object]:
        """Recover only a clean terminal control under a third-person review."""
        await self._context()
        await self._lock(f"containment-recovery:{control_id}")
        controls = metadata.tables["containment_controls"]
        control = (
            await self.session.execute(select(controls).where(
                controls.c.tenant_id == self.tenant_id,
                controls.c.id == control_id,
            ).with_for_update())
        ).mappings().one_or_none()
        if control is None:
            raise ContainmentRepositoryConflict("containment_control_not_found")
        if self.actor_user_id in {
            str(control["initiated_by_user_id"]),
            str(control["approved_by_user_id"]) if control["approved_by_user_id"] else "",
        }:
            raise ContainmentRepositoryConflict("containment_recovery_separation_required")
        approvals = metadata.tables["containment_approvals"]
        replay = (
            await self.session.execute(select(approvals).where(
                approvals.c.tenant_id == self.tenant_id,
                approvals.c.approval_id == review_id,
            ))
        ).mappings().one_or_none()
        if replay is not None:
            if replay["control_id"] != control_id or replay["approval_state"] != "recovery_review":
                raise ContainmentRepositoryConflict("containment_recovery_replay_mismatch")
            return _public_control(control)
        if control["control_state"] != "active" or int(control["version"]) != expected_version:
            raise ContainmentRepositoryConflict("containment_recovery_stale")
        actions = metadata.tables["containment_job_actions"]
        action_rows = (
            await self.session.execute(select(actions.c.id, actions.c.action_state).where(
                actions.c.tenant_id == self.tenant_id,
                actions.c.control_id == control_id,
            ).with_for_update())
        ).all()
        if any(row.action_state != "completed" for row in action_rows):
            raise ContainmentRepositoryConflict("containment_recovery_actions_incomplete")
        if not action_rows and await self._control_has_nonterminal_jobs(control):
            raise ContainmentRepositoryConflict("containment_recovery_actions_missing")
        action_ids = [row.id for row in action_rows]
        risks = metadata.tables["containment_residual_risks"]
        incidents = metadata.tables["containment_incidents"]
        open_risk = await self.session.scalar(select(risks.c.id).where(
            risks.c.tenant_id == self.tenant_id,
            risks.c.action_id.in_(action_ids),
            risks.c.risk_state == "open",
        ).limit(1))
        open_incident = await self.session.scalar(select(incidents.c.id).where(
            incidents.c.tenant_id == self.tenant_id,
            incidents.c.control_id == control_id,
            incidents.c.incident_state == "open",
        ).limit(1))
        if open_risk is not None or open_incident is not None:
            raise ContainmentRepositoryConflict("containment_recovery_prerequisites_open")
        await self.session.execute(insert(approvals).values(
            id=f"containment-approval-{uuid4().hex}", tenant_id=self.tenant_id,
            control_id=control_id, approval_id=review_id,
            approver_user_id=self.actor_user_id, request_hash=control["request_hash"],
            approval_state="recovery_review", approved_at=occurred_at,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        next_version = int(control["version"]) + 1
        await self.session.execute(update(controls).where(controls.c.id == control_id).values(
            control_state="recovered", recovered_at=occurred_at,
            version=next_version, updated_at=occurred_at,
        ))
        await self._audit_outbox(
            "containment.stop.recovered", str(control["stop_id"]),
            {"control_id": control_id, "review_id": review_id}, occurred_at,
        )
        return _public_control({
            **dict(control), "control_state": "recovered", "recovered_at": occurred_at,
            "version": next_version, "updated_at": occurred_at,
        })

    async def _control_has_nonterminal_jobs(self, control) -> bool:
        jobs = metadata.tables["jobs"]
        scope_kind = str(control["scope_kind"])
        scope_id = control["scope_id"]
        predicate = {
            ControlScopeKind.GLOBAL.value: True,
            ControlScopeKind.TENANT.value: scope_id == self.tenant_id,
            ControlScopeKind.JOB.value: jobs.c.id == scope_id,
            ControlScopeKind.CAMPAIGN.value: jobs.c.campaign_id == scope_id,
            ControlScopeKind.CAPABILITY.value: jobs.c.request["capability"].as_string() == scope_id,
        }[scope_kind]
        if predicate is False:
            return False
        return await self.session.scalar(select(jobs.c.id).where(
            jobs.c.tenant_id == self.tenant_id,
            jobs.c.orchestration_state.not_in(("succeeded", "failed", "cancelled")),
            predicate,
        ).limit(1)) is not None

    async def quota_status(self, *, occurred_at: datetime) -> list[dict[str, object]]:
        await self._context()
        policies = metadata.tables["quota_policies"]
        usage = metadata.tables["quota_usage"]
        policy_rows = (
            await self.session.execute(select(policies).where(
                policies.c.tenant_id == self.tenant_id,
                policies.c.policy_state == "active",
                policies.c.active_from <= occurred_at,
                policies.c.active_until > occurred_at,
            ).order_by(policies.c.policy_id, policies.c.policy_revision.desc()))
        ).mappings().all()
        result: list[dict[str, object]] = []
        for policy in policy_rows:
            usage_row = (
                await self.session.execute(select(usage).where(
                    usage.c.tenant_id == self.tenant_id,
                    usage.c.policy_record_id == policy["id"],
                    usage.c.window_start <= occurred_at,
                    usage.c.window_end > occurred_at,
                ).order_by(usage.c.window_start.desc()).limit(1))
            ).mappings().one_or_none()
            reserved = int(usage_row["reserved_amount"]) if usage_row else 0
            consumed = int(usage_row["consumed_amount"]) if usage_row else 0
            result.append({
                "policy_record_id": str(policy["id"]),
                "policy_id": str(policy["policy_id"]),
                "revision": int(policy["policy_revision"]),
                "dimension": str(policy["dimension"]),
                "extension_name": str(policy["extension_name"]) if policy["extension_name"] else None,
                "scope_kind": str(policy["scope_kind"]),
                "scope_id": str(policy["scope_id"]) if policy["scope_id"] else None,
                "hard_limit": int(policy["hard_limit"]),
                "reserved": reserved,
                "consumed": consumed,
                "remaining": max(0, int(policy["hard_limit"]) - reserved - consumed),
                "window_start": usage_row["window_start"] if usage_row else None,
                "window_end": usage_row["window_end"] if usage_row else None,
            })
        return result

    async def reconcile_overdue_controls(self, *, occurred_at: datetime) -> dict[str, object]:
        """Open one stable incident for every overdue active control/action."""
        await self._context()
        controls = metadata.tables["containment_controls"]
        actions = metadata.tables["containment_job_actions"]
        incidents = metadata.tables["containment_incidents"]
        control_rows = (
            await self.session.execute(select(controls).where(
                controls.c.tenant_id == self.tenant_id,
                controls.c.control_state == "active",
                controls.c.ack_deadline < occurred_at,
            ).with_for_update(skip_locked=True))
        ).mappings().all()
        opened: list[str] = []
        for control in control_rows:
            action_rows = (
                await self.session.execute(select(actions).where(
                    actions.c.tenant_id == self.tenant_id,
                    actions.c.control_id == control["id"],
                ))
            ).mappings().all()
            candidates: list[tuple[str | None, str, str]] = []
            if not action_rows:
                candidates.append((None, "containment_acknowledgement_timeout", "containment_action_not_started"))
            else:
                for action in action_rows:
                    if action["action_state"] == "running" and action["updated_at"] < control["ack_deadline"]:
                        candidates.append((str(action["id"]), "containment_stalled", "containment_heartbeat_lost"))
            for action_id, kind, reason in candidates:
                identity = f"{self.tenant_id}:{control['id']}:{action_id or '*'}:{kind}"
                incident_id = f"incident-{hashlib.sha256(identity.encode()).hexdigest()[:32]}"
                existing = await self.session.scalar(select(incidents.c.incident_id).where(
                    incidents.c.tenant_id == self.tenant_id,
                    incidents.c.incident_id == incident_id,
                ).limit(1))
                if existing is not None:
                    continue
                await self.session.execute(insert(incidents).values(
                    id=f"containment-incident-row-{uuid4().hex}", tenant_id=self.tenant_id,
                    incident_id=incident_id, control_id=control["id"], action_id=action_id,
                    incident_kind=kind, severity="critical", incident_state="open",
                    reason_code=reason, opened_at=occurred_at, resolved_at=None,
                    version=1, created_at=occurred_at, updated_at=occurred_at,
                ))
                if action_id is not None:
                    await self.session.execute(update(actions).where(actions.c.id == action_id).values(
                        action_state="incident_open", version=actions.c.version + 1, updated_at=occurred_at,
                    ))
                opened.append(incident_id)
                await self._audit_outbox(
                    "containment.incident.opened", incident_id,
                    {"control_id": str(control["id"]), "kind": kind, "reason_code": reason},
                    occurred_at,
                )
        return {"inspected_controls": len(control_rows), "incident_ids": opened}

    async def begin_action(
        self,
        *,
        control_id: str,
        job_id: str,
        runner_registration_id: str | None,
        occurred_at: datetime,
        stop_id: str | None = None,
    ) -> dict[str, object]:
        await self._context()
        await self._lock(f"containment-action:{control_id}:{job_id}")
        controls = metadata.tables["containment_controls"]
        control = (
            await self.session.execute(select(controls).where(
                controls.c.tenant_id == self.tenant_id,
                controls.c.id == control_id,
                controls.c.control_state == "active",
            ))
        ).mappings().one_or_none()
        if control is None:
            raise ContainmentRepositoryConflict("containment_control_not_active")
        if stop_id is not None and control["stop_id"] != stop_id:
            raise ContainmentRepositoryConflict("containment_control_stop_mismatch")
        if control["scope_kind"] == ControlScopeKind.JOB.value and control["scope_id"] != job_id:
            raise ContainmentRepositoryConflict("containment_action_job_scope_mismatch")
        table = metadata.tables["containment_job_actions"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.control_id == control_id,
                table.c.job_id == job_id,
            ))
        ).mappings().one_or_none()
        if existing is not None:
            return dict(existing)
        row = {
            "id": f"containment-action-{uuid4().hex}", "tenant_id": self.tenant_id,
            "control_id": control_id, "job_id": job_id,
            "runner_registration_id": runner_registration_id, "action_state": "running",
            "acknowledged_at": occurred_at, "completed_at": None,
            "outcome": None, "duration_ms": None, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        return row

    async def record_phase(self, action_id: str, receipt: PhaseReceipt) -> dict[str, object]:
        await self._context()
        table = metadata.tables["containment_phase_receipts"]
        receipt_hash = _phase_hash(action_id, receipt)
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.action_id == action_id,
                table.c.phase == receipt.phase.value,
            ))
        ).mappings().one_or_none()
        if existing is not None:
            if str(existing["receipt_hash"]) != receipt_hash:
                raise ContainmentRepositoryConflict("containment_phase_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"containment-phase-{uuid4().hex}", "tenant_id": self.tenant_id,
            "action_id": action_id, "phase": receipt.phase.value,
            "phase_state": receipt.state, "reason_code": receipt.reason_code,
            "receipt_hash": receipt_hash, "duration_ms": receipt.duration_ms,
            "occurred_at": receipt.occurred_at, "version": 1,
            "created_at": receipt.occurred_at, "updated_at": receipt.occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        return row

    async def list_phase_receipts(self, action_id: str) -> tuple[PhaseReceipt, ...]:
        await self._context()
        table = metadata.tables["containment_phase_receipts"]
        rows = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id,
            table.c.action_id == action_id,
        ).order_by(table.c.created_at, table.c.phase))).mappings().all()
        return tuple(
            PhaseReceipt(
                phase=_phase(str(row["phase"])), state=str(row["phase_state"]),
                reason_code=str(row["reason_code"]), occurred_at=row["occurred_at"],
                duration_ms=int(row["duration_ms"]),
            )
            for row in rows
        )

    async def complete_action(self, action_id: str, *, occurred_at: datetime) -> dict[str, object]:
        await self._context()
        actions = metadata.tables["containment_job_actions"]
        action = (
            await self.session.execute(select(actions).where(
                actions.c.tenant_id == self.tenant_id, actions.c.id == action_id,
            ).with_for_update())
        ).mappings().one_or_none()
        if action is None:
            raise ContainmentRepositoryConflict("containment_action_not_found")
        receipts_table = metadata.tables["containment_phase_receipts"]
        rows = (
            await self.session.execute(select(receipts_table).where(
                receipts_table.c.tenant_id == self.tenant_id,
                receipts_table.c.action_id == action_id,
            ))
        ).mappings().all()
        receipts = tuple(
            PhaseReceipt(
                phase=_phase(str(row["phase"])), state=str(row["phase_state"]),
                reason_code=str(row["reason_code"]), occurred_at=row["occurred_at"],
                duration_ms=int(row["duration_ms"]),
            )
            for row in rows
        )
        assessment = aggregate_containment(receipts)
        if action["completed_at"] is not None and action["outcome"] is not None:
            # CRITICAL: Temporal may retry after commit but before receiving the result;
            # terminal replay must never duplicate audit/outbox or advance the version.
            if str(action["outcome"]) != assessment.outcome.value:
                raise ContainmentRepositoryConflict("containment_terminal_replay_mismatch")
            return {
                "action_id": action_id,
                "outcome": assessment.outcome.value,
                "residual_risks": assessment.residual_risks,
            }
        duration_ms = sum(item.duration_ms for item in receipts)
        await self.session.execute(update(actions).where(actions.c.id == action_id).values(
            action_state="completed" if assessment.outcome is ContainmentOutcome.CONTAINED else "incident_open",
            completed_at=occurred_at, outcome=assessment.outcome.value,
            duration_ms=duration_ms, version=int(action["version"]) + 1, updated_at=occurred_at,
        ))
        if assessment.residual_risks:
            await self._record_risks_and_incident(action, assessment.residual_risks, occurred_at)
        await self._audit_outbox(
            "containment.action.assessed", str(action["job_id"]),
            {"action_id": action_id, "outcome": assessment.outcome.value, "risk_codes": list(assessment.residual_risks)},
            occurred_at,
        )
        return {"action_id": action_id, "outcome": assessment.outcome.value, "residual_risks": assessment.residual_risks}

    async def register_quota_policy(self, policy: QuotaPolicy, *, occurred_at: datetime) -> dict[str, object]:
        if policy.tenant_id != self.tenant_id:
            raise ContainmentRepositoryConflict("quota_policy_tenant_mismatch")
        await self._context()
        table = metadata.tables["quota_policies"]
        scope_key = _quota_scope_key(policy)
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.policy_id == policy.policy_id,
                table.c.policy_revision == policy.revision,
                table.c.dimension == policy.dimension.value,
                table.c.scope_key == scope_key,
            ))
        ).mappings().one_or_none()
        row = {
            "id": f"quota-policy-{uuid4().hex}", "tenant_id": self.tenant_id,
            "policy_id": policy.policy_id, "policy_revision": policy.revision,
            "dimension": policy.dimension.value, "extension_name": policy.extension_name,
            "scope_kind": policy.scope.kind.value, "scope_id": policy.scope.scope_id,
            "scope_key": scope_key,
            "hard_limit": policy.hard_limit, "window_seconds": policy.window_seconds,
            "active_from": policy.active_from, "active_until": policy.active_until,
            "policy_state": "active", "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        if existing is not None:
            if _quota_identity(existing) != _quota_identity(row):
                raise ContainmentRepositoryConflict("quota_policy_revision_immutable")
            return dict(existing)
        await self.session.execute(insert(table).values(**row))
        return row

    async def reserve_quota(
        self,
        *,
        policy_record_id: str,
        operation_id: str,
        requested: int,
        occurred_at: datetime,
    ) -> QuotaReservationResult:
        await self._context()
        await self._lock(f"quota:{policy_record_id}")
        policies = metadata.tables["quota_policies"]
        row = (
            await self.session.execute(select(policies).where(
                policies.c.tenant_id == self.tenant_id,
                policies.c.id == policy_record_id,
            ).with_for_update())
        ).mappings().one_or_none()
        if row is None or row["policy_state"] != "active":
            raise ContainmentRepositoryConflict("quota_policy_required")
        policy = _quota_contract(row)
        usage_scope_key = str(row["scope_key"])
        operation_hash = _quota_operation_hash(policy_record_id, "reserve", requested)
        existing = await self._quota_operation(operation_id)
        if existing is not None:
            if str(existing["request_hash"]) != operation_hash:
                raise ContainmentRepositoryConflict("quota_operation_replay_mismatch")
            return QuotaReservationResult(
                QuotaDecision(
                    bool(existing["decision"] == "allowed"), str(existing["reason_code"]),
                    int(existing["remaining_after"]), bool(existing["decision"] == "denied"),
                ),
                str(existing["containment_control_id"]) if existing["containment_control_id"] else None,
            )
        window_start, window_end = _quota_window(policy, occurred_at)
        usage = await self._locked_usage(policy_record_id, usage_scope_key, window_start)
        reserved = int(usage["reserved_amount"]) if usage else 0
        consumed = int(usage["consumed_amount"]) if usage else 0
        decision = evaluate_quota(
            policy, reserved=reserved, consumed=consumed,
            requested=requested, occurred_at=occurred_at,
        )
        control_id = None
        reservation_record_id = None
        if decision.allowed:
            if usage is None:
                usage_id = f"quota-usage-{uuid4().hex}"
                await self.session.execute(insert(metadata.tables["quota_usage"]).values(
                    id=usage_id, tenant_id=self.tenant_id,
                    policy_record_id=policy_record_id, scope_key=usage_scope_key,
                    window_start=window_start, window_end=window_end,
                    reserved_amount=requested, consumed_amount=0, version=1,
                    created_at=occurred_at, updated_at=occurred_at,
                ))
            else:
                usage_id = str(usage["id"])
                await self.session.execute(update(metadata.tables["quota_usage"]).where(
                    metadata.tables["quota_usage"].c.id == usage["id"],
                ).values(
                    reserved_amount=reserved + requested,
                    version=int(usage["version"]) + 1, updated_at=occurred_at,
                ))
            reservation_record_id = f"quota-reservation-{uuid4().hex}"
            await self.session.execute(insert(metadata.tables["quota_reservations"]).values(
                id=reservation_record_id, tenant_id=self.tenant_id,
                reservation_id=operation_id, policy_record_id=policy_record_id,
                usage_id=usage_id, reserved_amount=requested,
                consumed_amount=0, released_amount=0, reservation_state="reserved",
                expires_at=window_end, version=1,
                created_at=occurred_at, updated_at=occurred_at,
            ))
        else:
            control_id = await self._activate_quota_control(policy, operation_id, occurred_at)
        await self.session.execute(insert(metadata.tables["quota_operations"]).values(
            id=f"quota-operation-{uuid4().hex}", tenant_id=self.tenant_id,
            operation_id=operation_id, policy_record_id=policy_record_id,
            reservation_record_id=reservation_record_id,
            request_hash=operation_hash, operation_kind="reserve", amount=requested,
            remaining_after=decision.remaining,
            decision="allowed" if decision.allowed else "denied",
            reason_code=decision.reason_code, containment_control_id=control_id,
            occurred_at=occurred_at, version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        if not decision.allowed:
            await self._audit_outbox(
                "quota.hard_limit.exceeded", policy.policy_id,
                {"dimension": policy.dimension.value, "scope": policy.scope.canonical_key, "operation_id": operation_id},
                occurred_at,
            )
        return QuotaReservationResult(decision, control_id)

    async def adjust_quota(
        self,
        *,
        reservation_id: str,
        operation_id: str,
        operation_kind: str,
        amount: int,
        occurred_at: datetime,
    ) -> QuotaAdjustmentResult:
        if operation_kind not in {"consume", "release"}:
            raise ContainmentRepositoryConflict("quota_adjustment_kind_invalid")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise ContainmentRepositoryConflict("quota_adjustment_amount_invalid")
        await self._context()
        await self._lock(f"quota-reservation:{reservation_id}")
        reservations = metadata.tables["quota_reservations"]
        reservation = (
            await self.session.execute(select(reservations).where(
                reservations.c.tenant_id == self.tenant_id,
                reservations.c.reservation_id == reservation_id,
            ).with_for_update())
        ).mappings().one_or_none()
        if reservation is None:
            raise ContainmentRepositoryConflict("quota_reservation_not_found")
        operation_hash = _quota_operation_hash(str(reservation["id"]), operation_kind, amount)
        existing = await self._quota_operation(operation_id)
        if existing is not None:
            if str(existing["request_hash"]) != operation_hash:
                raise ContainmentRepositoryConflict("quota_operation_replay_mismatch")
            return QuotaAdjustmentResult(
                existing["decision"] == "allowed", str(existing["reason_code"]),
                int(existing["remaining_after"]),
                str(existing["containment_control_id"]) if existing["containment_control_id"] else None,
            )
        available = (
            int(reservation["reserved_amount"])
            - int(reservation["consumed_amount"])
            - int(reservation["released_amount"])
        )
        policy_row = (
            await self.session.execute(select(metadata.tables["quota_policies"]).where(
                metadata.tables["quota_policies"].c.tenant_id == self.tenant_id,
                metadata.tables["quota_policies"].c.id == reservation["policy_record_id"],
            ))
        ).mappings().one()
        policy = _quota_contract(policy_row)
        expired = occurred_at >= reservation["expires_at"]
        allowed = not expired and reservation["reservation_state"] in {"reserved", "partially_consumed"} and amount <= available
        reason_code = f"quota_{operation_kind}_recorded" if allowed else (
            "quota_reservation_expired" if expired else "quota_reservation_insufficient"
        )
        control_id = None
        remaining_after = available
        if allowed:
            usage = (
                await self.session.execute(select(metadata.tables["quota_usage"]).where(
                    metadata.tables["quota_usage"].c.tenant_id == self.tenant_id,
                    metadata.tables["quota_usage"].c.id == reservation["usage_id"],
                ).with_for_update())
            ).mappings().one()
            remaining_after = available - amount
            consumed_amount = int(reservation["consumed_amount"]) + (amount if operation_kind == "consume" else 0)
            released_amount = int(reservation["released_amount"]) + (amount if operation_kind == "release" else 0)
            state = (
                "consumed" if remaining_after == 0 and operation_kind == "consume"
                else "released" if remaining_after == 0
                else "partially_consumed"
            )
            await self.session.execute(update(reservations).where(reservations.c.id == reservation["id"]).values(
                consumed_amount=consumed_amount, released_amount=released_amount,
                reservation_state=state, version=int(reservation["version"]) + 1,
                updated_at=occurred_at,
            ))
            await self.session.execute(update(metadata.tables["quota_usage"]).where(
                metadata.tables["quota_usage"].c.id == usage["id"],
            ).values(
                reserved_amount=int(usage["reserved_amount"]) - amount,
                consumed_amount=int(usage["consumed_amount"]) + (amount if operation_kind == "consume" else 0),
                version=int(usage["version"]) + 1, updated_at=occurred_at,
            ))
        else:
            control_id = await self._activate_quota_control(policy, operation_id, occurred_at)
        await self.session.execute(insert(metadata.tables["quota_operations"]).values(
            id=f"quota-operation-{uuid4().hex}", tenant_id=self.tenant_id,
            operation_id=operation_id, policy_record_id=reservation["policy_record_id"],
            reservation_record_id=reservation["id"], request_hash=operation_hash,
            operation_kind=operation_kind, amount=amount, remaining_after=remaining_after,
            decision="allowed" if allowed else "denied", reason_code=reason_code,
            containment_control_id=control_id, occurred_at=occurred_at,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        return QuotaAdjustmentResult(allowed, reason_code, remaining_after, control_id)

    async def expire_quota_reservations(self, *, occurred_at: datetime) -> int:
        await self._context()
        reservations = metadata.tables["quota_reservations"]
        rows = (
            await self.session.execute(select(reservations).where(
                reservations.c.tenant_id == self.tenant_id,
                reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
                reservations.c.expires_at <= occurred_at,
            ).with_for_update(skip_locked=True))
        ).mappings().all()
        for reservation in rows:
            remaining = (
                int(reservation["reserved_amount"])
                - int(reservation["consumed_amount"])
                - int(reservation["released_amount"])
            )
            if remaining:
                usage = metadata.tables["quota_usage"]
                await self.session.execute(update(usage).where(
                    usage.c.tenant_id == self.tenant_id, usage.c.id == reservation["usage_id"],
                ).values(
                    reserved_amount=usage.c.reserved_amount - remaining,
                    version=usage.c.version + 1, updated_at=occurred_at,
                ))
            await self.session.execute(update(reservations).where(
                reservations.c.id == reservation["id"],
            ).values(
                released_amount=int(reservation["released_amount"]) + remaining,
                reservation_state="expired", version=int(reservation["version"]) + 1,
                updated_at=occurred_at,
            ))
            operation_id = f"expire-{hashlib.sha256(str(reservation['reservation_id']).encode()).hexdigest()[:32]}"
            existing = await self._quota_operation(operation_id)
            if existing is None:
                await self.session.execute(insert(metadata.tables["quota_operations"]).values(
                    id=f"quota-operation-{uuid4().hex}", tenant_id=self.tenant_id,
                    operation_id=operation_id, policy_record_id=reservation["policy_record_id"],
                    reservation_record_id=reservation["id"],
                    request_hash=_quota_operation_hash(str(reservation["id"]), "expire", remaining),
                    operation_kind="expire", amount=remaining, remaining_after=0,
                    decision="allowed", reason_code="quota_reservation_expired",
                    containment_control_id=None, occurred_at=occurred_at,
                    version=1, created_at=occurred_at, updated_at=occurred_at,
                ))
        return len(rows)

    async def _activate_quota_control(self, policy: QuotaPolicy, operation_id: str, occurred_at: datetime) -> str:
        table = metadata.tables["containment_controls"]
        control_id = f"containment-{uuid4().hex}"
        stop_id = f"quota-{operation_id}"[:64]
        request_hash = _quota_operation_hash(policy.policy_id, policy.dimension.value, policy.hard_limit)
        await self.session.execute(insert(table).values(
            id=control_id, tenant_id=self.tenant_id, stop_id=stop_id,
            scope_kind=policy.scope.kind.value, scope_id=policy.scope.scope_id,
            control_mode="quota_breach", request_hash=request_hash,
            idempotency_key=f"quota:{operation_id}", reason_hash=hashlib.sha256(b"hard_quota_exceeded").hexdigest(),
            initiated_by_user_id="quota-service", approved_by_user_id=None,
            control_state="active", requested_at=occurred_at, activated_at=occurred_at,
            ack_deadline=occurred_at + timedelta(seconds=10), recovered_at=None,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        return control_id

    async def _locked_usage(self, policy_id: str, scope_key: str, window_start: datetime):
        table = metadata.tables["quota_usage"]
        return (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.policy_record_id == policy_id,
                table.c.scope_key == scope_key,
                table.c.window_start == window_start,
            ).with_for_update())
        ).mappings().one_or_none()

    async def _quota_operation(self, operation_id: str):
        table = metadata.tables["quota_operations"]
        return (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.operation_id == operation_id,
            ))
        ).mappings().one_or_none()

    async def _record_risks_and_incident(self, action, risks: tuple[str, ...], occurred_at: datetime) -> None:
        risk_table = metadata.tables["containment_residual_risks"]
        for risk in risks:
            await self.session.execute(insert(risk_table).values(
                id=f"containment-risk-{uuid4().hex}", tenant_id=self.tenant_id,
                action_id=action["id"], risk_code=risk[:100], risk_state="open",
                details_hash=hashlib.sha256(risk.encode()).hexdigest(),
                dispositioned_by_user_id=None, dispositioned_at=None,
                version=1, created_at=occurred_at, updated_at=occurred_at,
            ))
        await self.session.execute(insert(metadata.tables["containment_incidents"]).values(
            id=f"containment-incident-row-{uuid4().hex}", tenant_id=self.tenant_id,
            incident_id=f"incident-{uuid4().hex}", control_id=action["control_id"], action_id=action["id"],
            incident_kind="containment_incomplete", severity="high", incident_state="open",
            reason_code="containment_residual_risk", opened_at=occurred_at, resolved_at=None,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))

    async def _context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id},
        )

    async def _lock(self, scope: str) -> None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": f"{self.tenant_id}:{scope}"},
        )

    async def _audit_outbox(
        self, event_type: str, subject_id: str, details: dict[str, object], occurred_at: datetime,
    ) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, action=event_type,
            subject_type="containment", subject_id=subject_id[:64],
            correlation_id=self.correlation_id, details=details,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id,
            event_type=event_type, aggregate_id=subject_id[:64], payload=details,
            published=False, version=1, created_at=occurred_at, updated_at=occurred_at,
        ))


class QuotaRepository:
    """Narrow hard-quota facade kept separate from operator stop workflows."""

    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self._repository = ContainmentRepository(
            session, tenant_id=tenant_id, actor_user_id=actor_user_id,
            correlation_id=correlation_id,
        )

    async def register_policy(self, policy: QuotaPolicy, *, occurred_at: datetime) -> dict[str, object]:
        return await self._repository.register_quota_policy(policy, occurred_at=occurred_at)

    async def reserve(
        self,
        *,
        policy_record_id: str,
        operation_id: str,
        amount: int,
        occurred_at: datetime,
    ) -> QuotaReservationResult:
        return await self._repository.reserve_quota(
            policy_record_id=policy_record_id, operation_id=operation_id,
            requested=amount, occurred_at=occurred_at,
        )

    async def consume(
        self, *, reservation_id: str, operation_id: str, amount: int, occurred_at: datetime,
    ) -> QuotaAdjustmentResult:
        return await self._repository.adjust_quota(
            reservation_id=reservation_id, operation_id=operation_id,
            operation_kind="consume", amount=amount, occurred_at=occurred_at,
        )

    async def release(
        self, *, reservation_id: str, operation_id: str, amount: int, occurred_at: datetime,
    ) -> QuotaAdjustmentResult:
        return await self._repository.adjust_quota(
            reservation_id=reservation_id, operation_id=operation_id,
            operation_kind="release", amount=amount, occurred_at=occurred_at,
        )

    async def expire(self, *, occurred_at: datetime) -> int:
        return await self._repository.expire_quota_reservations(occurred_at=occurred_at)


def _phase(value: str):
    from redagent_platform.containment_service.contracts import ContainmentPhase

    return ContainmentPhase(value)


def _phase_hash(action_id: str, receipt: PhaseReceipt) -> str:
    payload = {
        "action_id": action_id, "phase": receipt.phase.value, "state": receipt.state,
        "reason_code": receipt.reason_code, "occurred_at": receipt.occurred_at.isoformat(),
        "duration_ms": receipt.duration_ms,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _quota_operation_hash(policy_id: str, kind: str, amount: int) -> str:
    return hashlib.sha256(f"{policy_id}:{kind}:{amount}".encode()).hexdigest()


def _quota_scope_key(policy: QuotaPolicy) -> str:
    if policy.extension_name is None:
        return policy.scope.canonical_key
    return f"{policy.scope.canonical_key}#extension:{policy.extension_name}"


def _quota_identity(row) -> tuple[object, ...]:
    return tuple(row[name] for name in (
        "policy_id", "policy_revision", "dimension", "extension_name", "scope_key",
        "hard_limit", "window_seconds", "active_from", "active_until",
    ))


def _quota_contract(row) -> QuotaPolicy:
    from redagent_platform.containment_service.contracts import ControlScope, QuotaDimension

    return QuotaPolicy(
        policy_id=str(row["policy_id"]), tenant_id=str(row["tenant_id"]),
        revision=int(row["policy_revision"]), dimension=QuotaDimension(str(row["dimension"])),
        scope=ControlScope(ControlScopeKind(str(row["scope_kind"])), row["scope_id"]),
        hard_limit=int(row["hard_limit"]), window_seconds=int(row["window_seconds"]),
        active_from=row["active_from"], active_until=row["active_until"],
        extension_name=row["extension_name"],
    )


def _quota_window(policy: QuotaPolicy, occurred_at: datetime) -> tuple[datetime, datetime]:
    elapsed = max(0, int((occurred_at - policy.active_from).total_seconds()))
    offset = (elapsed // policy.window_seconds) * policy.window_seconds
    start = policy.active_from + timedelta(seconds=offset)
    return start, min(start + timedelta(seconds=policy.window_seconds), policy.active_until)


def _public_control(row) -> dict[str, object]:
    """Return metadata only; reason hashes and idempotency keys remain internal."""
    return {
        "control_id": str(row["id"]),
        "stop_id": str(row["stop_id"]),
        "scope_kind": str(row["scope_kind"]),
        "scope_id": str(row["scope_id"]) if row["scope_id"] is not None else None,
        "control_mode": str(row["control_mode"]),
        "request_hash": str(row["request_hash"]),
        "initiated_by_user_id": str(row["initiated_by_user_id"]),
        "approved_by_user_id": (
            str(row["approved_by_user_id"]) if row["approved_by_user_id"] is not None else None
        ),
        "control_state": str(row["control_state"]),
        "requested_at": row["requested_at"],
        "activated_at": row["activated_at"],
        "ack_deadline": row["ack_deadline"],
        "recovered_at": row["recovered_at"],
        "version": int(row["version"]),
    }
