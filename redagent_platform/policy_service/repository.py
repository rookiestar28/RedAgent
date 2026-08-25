"""Transactional PostgreSQL recorder for compat_099 decisions and PEP receipts."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import insert, select, text, update

from redagent_platform.persistence.models import metadata
from redagent_platform.policy_service.contracts import PolicyDecision, PolicyDecisionInput
from redagent_platform.policy_service.lifecycle import (
    BundleAcknowledgement,
    BundleRevision,
    PolicyLifecycleError,
    activate_bundle,
)


class PolicyDecisionConflict(RuntimeError):
    pass


class TransactionalPolicyDecisionRecorder:
    def __init__(self, session_factory) -> None:
        self.session_factory = session_factory

    async def persist_decision_and_receipt(
        self,
        request: PolicyDecisionInput,
        decision: PolicyDecision,
        *,
        operation: str,
    ) -> str:
        async with self.session_factory() as session, session.begin():
            await session.execute(
                text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
                {"tenant": request.tenant_id},
            )
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"policy-decision:{request.tenant_id}:{decision.decision_id}"},
            )
            decisions = metadata.tables["policy_decisions"]
            existing = (
                await session.execute(
                    select(decisions).where(
                        decisions.c.tenant_id == request.tenant_id,
                        decisions.c.opa_decision_id == decision.decision_id,
                    )
                )
            ).mappings().one_or_none()
            if existing is None:
                decision_row_id = f"policy-decision-{uuid4().hex}"
                resource_version = request.attributes.get("resource_version")
                await session.execute(insert(decisions).values(
                    id=decision_row_id,
                    tenant_id=request.tenant_id,
                    opa_decision_id=decision.decision_id,
                    bundle_revision=decision.bundle_revision,
                    input_hash=decision.input_hash,
                    boundary=request.boundary.value,
                    action=request.action,
                    subject_id=request.subject_id,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    resource_version=resource_version if isinstance(resource_version, int) else None,
                    allowed=decision.allowed,
                    reason_code=decision.reason_code,
                    obligations=[item.value for item in decision.obligations],
                    issued_at=decision.issued_at,
                    valid_until=decision.valid_until,
                    correlation_id=request.correlation_id,
                    version=1,
                    created_at=decision.issued_at,
                    updated_at=decision.issued_at,
                ))
            else:
                if not _same_decision(existing, request, decision):
                    raise PolicyDecisionConflict("policy_decision_replay_mismatch")
                decision_row_id = str(existing["id"])

            receipts = metadata.tables["policy_boundary_receipts"]
            existing_receipt = (
                await session.execute(
                    select(receipts).where(
                        receipts.c.tenant_id == request.tenant_id,
                        receipts.c.boundary == request.boundary.value,
                        receipts.c.aggregate_id == request.resource_id,
                        receipts.c.operation == operation,
                    )
                )
            ).mappings().one_or_none()
            if existing_receipt is not None:
                if (
                    str(existing_receipt["decision_id"]) != decision_row_id
                    or str(existing_receipt["input_hash"]) != decision.input_hash
                ):
                    raise PolicyDecisionConflict("policy_boundary_receipt_replay_mismatch")
                return str(existing_receipt["id"])

            receipt_id = f"policy-receipt-{uuid4().hex}"
            await session.execute(insert(receipts).values(
                id=receipt_id,
                tenant_id=request.tenant_id,
                decision_id=decision_row_id,
                boundary=request.boundary.value,
                aggregate_type=request.resource_type,
                aggregate_id=request.resource_id,
                operation=operation,
                input_hash=decision.input_hash,
                enforcement_outcome="allowed" if decision.allowed else "denied",
                enforced_at=decision.issued_at,
                version=1,
                created_at=decision.issued_at,
                updated_at=decision.issued_at,
            ))
            await _audit_outbox(session, request, decision, receipt_id)
            return receipt_id


def _same_decision(row, request: PolicyDecisionInput, decision: PolicyDecision) -> bool:
    return (
        str(row["bundle_revision"]) == decision.bundle_revision
        and str(row["input_hash"]) == decision.input_hash
        and str(row["boundary"]) == request.boundary.value
        and str(row["action"]) == request.action
        and str(row["subject_id"]) == request.subject_id
        and str(row["resource_type"]) == request.resource_type
        and str(row["resource_id"]) == request.resource_id
        and bool(row["allowed"]) is decision.allowed
        and str(row["reason_code"]) == decision.reason_code
        and tuple(row["obligations"]) == tuple(item.value for item in decision.obligations)
    )


async def _audit_outbox(session, request: PolicyDecisionInput, decision: PolicyDecision, receipt_id: str) -> None:
    outcome = "allowed" if decision.allowed else "denied"
    details = {
        "boundary": request.boundary.value,
        "action": request.action,
        "resource_type": request.resource_type,
        "resource_id": request.resource_id,
        "decision_id": decision.decision_id,
        "bundle_revision": decision.bundle_revision,
        "input_hash": decision.input_hash,
        "reason_code": decision.reason_code,
        "receipt_id": receipt_id,
        "outcome": outcome,
    }
    event_type = f"policy.decision.{outcome}"
    await session.execute(insert(metadata.tables["audit_events"]).values(
        id=f"audit-{uuid4().hex}", tenant_id=request.tenant_id,
        actor_user_id=request.subject_id, action=event_type,
        subject_type="policy_decision", subject_id=decision.decision_id,
        correlation_id=request.correlation_id, details=details, version=1,
        created_at=decision.issued_at, updated_at=decision.issued_at,
    ))
    await session.execute(insert(metadata.tables["outbox_events"]).values(
        id=f"outbox-{uuid4().hex}", tenant_id=request.tenant_id,
        event_type=event_type, aggregate_id=decision.decision_id,
        payload=details, published=False, version=1,
        created_at=decision.issued_at, updated_at=decision.issued_at,
    ))


class PolicyAdministrationRepository:
    """Repository-only bundle registration and convergent promotion boundary."""

    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.actor_user_id = actor_user_id
        self.correlation_id = correlation_id

    async def register_bundle(self, bundle: BundleRevision, *, occurred_at: datetime) -> dict[str, object]:
        await self._context()
        table = metadata.tables["policy_bundle_revisions"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.revision_name == bundle.revision,
            ))
        ).mappings().one_or_none()
        if existing is not None:
            if str(existing["artifact_sha256"]) != bundle.artifact_sha256:
                raise PolicyDecisionConflict("policy_bundle_revision_immutable")
            return dict(existing)
        row = {
            "id": f"policy-bundle-{uuid4().hex}", "tenant_id": self.tenant_id,
            "revision_name": bundle.revision, "source_sha256": bundle.source_sha256,
            "artifact_sha256": bundle.artifact_sha256, "artifact_size": bundle.artifact_size,
            "manifest_roots": list(bundle.manifest_roots), "rego_version": bundle.rego_version,
            "signing_key_id": bundle.signing_key_id, "signing_scope": bundle.signing_scope,
            "signing_algorithm": bundle.signing_algorithm, "author_user_id": bundle.author_user_id,
            "reviewer_user_id": bundle.reviewer_user_id,
            "test_evidence_sha256": bundle.test_evidence_sha256,
            "coverage_basis_points": bundle.coverage_basis_points,
            "conformance_sha256": bundle.conformance_sha256,
            "bundle_status": bundle.status, "supersedes_revision": None,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        return row

    async def record_agent_status(
        self, *, agent_id: str, boundary: str, active_revision: str,
        artifact_sha256: str, bundle_state: str, error_code: str | None,
        occurred_at: datetime,
    ) -> dict[str, object]:
        if boundary not in {"api", "workflow", "evidence", "secret", "runner"}:
            raise PolicyDecisionConflict("policy_agent_boundary_invalid")
        await self._context()
        table = metadata.tables["policy_agent_status"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.agent_id == agent_id,
            ).with_for_update())
        ).mappings().one_or_none()
        values = {
            "boundary": boundary, "active_revision": active_revision,
            "artifact_sha256": artifact_sha256, "bundle_state": bundle_state,
            "last_seen_at": occurred_at, "error_code": error_code,
            "updated_at": occurred_at,
        }
        if existing is None:
            row = {
                "id": f"policy-agent-{uuid4().hex}", "tenant_id": self.tenant_id,
                "agent_id": agent_id, **values, "version": 1, "created_at": occurred_at,
            }
            await self.session.execute(insert(table).values(**row))
            return row
        await self.session.execute(update(table).where(table.c.id == existing["id"]).values(
            **values, version=table.c.version + 1,
        ))
        return {**dict(existing), **values, "version": int(existing["version"]) + 1}

    async def promote(
        self, *, revision: str, expected_version: int, idempotency_key: str,
        reason: str, rollback: bool, occurred_at: datetime,
    ) -> dict[str, object]:
        await self._context()
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"policy-promotion:{self.tenant_id}"},
        )
        promotions = metadata.tables["policy_bundle_promotions"]
        replay = (
            await self.session.execute(select(promotions).where(
                promotions.c.tenant_id == self.tenant_id,
                promotions.c.idempotency_key == idempotency_key,
            ))
        ).mappings().one_or_none()
        if replay is not None:
            if str(replay["bundle_revision"]) != revision:
                raise PolicyDecisionConflict("policy_promotion_idempotency_mismatch")
            return dict(replay)
        bundles = metadata.tables["policy_bundle_revisions"]
        candidate = (
            await self.session.execute(select(bundles).where(
                bundles.c.tenant_id == self.tenant_id,
                bundles.c.revision_name == revision,
            ).with_for_update())
        ).mappings().one_or_none()
        if candidate is None or int(candidate["version"]) != expected_version:
            raise PolicyDecisionConflict("policy_bundle_version_conflict")
        if self.actor_user_id == candidate["author_user_id"]:
            raise PolicyDecisionConflict("policy_promotion_separation_required")
        current = (
            await self.session.execute(select(promotions).where(
                promotions.c.tenant_id == self.tenant_id,
                promotions.c.promotion_state.in_(("promoted", "rollback_promoted")),
            ).order_by(promotions.c.promoted_at.desc()).limit(1))
        ).mappings().one_or_none()
        current_revision = str(current["bundle_revision"]) if current is not None else "bootstrap-none"
        agents = metadata.tables["policy_agent_status"]
        statuses = (
            await self.session.execute(select(agents).where(agents.c.tenant_id == self.tenant_id))
        ).mappings().all()
        if {str(row["boundary"]) for row in statuses} != {"api", "workflow", "evidence", "secret", "runner"}:
            raise PolicyDecisionConflict("policy_bundle_agent_convergence_required")
        bundle = _bundle_from_row(candidate)
        acknowledgements = tuple(
            BundleAcknowledgement(
                agent_id=str(row["agent_id"]), active_revision=str(row["active_revision"]),
                artifact_sha256=str(row["artifact_sha256"]), bundle_state=str(row["bundle_state"]),
                status_fresh=occurred_at - row["last_seen_at"] <= timedelta(minutes=2),
            )
            for row in statuses
        )
        try:
            activation = activate_bundle(
                bundle, required_agents=tuple(sorted(item.agent_id for item in acknowledgements)),
                acknowledgements=acknowledgements, current_revision=current_revision, rollback=rollback,
            )
        except PolicyLifecycleError as exc:
            raise PolicyDecisionConflict(str(exc)) from exc
        row = {
            "id": f"policy-promotion-{uuid4().hex}", "tenant_id": self.tenant_id,
            "bundle_revision": activation.required_revision,
            "previous_revision": activation.previous_revision,
            "idempotency_key": idempotency_key,
            "required_agents": list(activation.acknowledged_agents),
            "acknowledged_agents": list(activation.acknowledged_agents),
            "promotion_state": "rollback_promoted" if rollback else "promoted",
            "promoted_by_user_id": self.actor_user_id, "reason": reason,
            "promoted_at": occurred_at, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(promotions).values(**row))
        await _admin_audit_outbox(
            self.session, tenant_id=self.tenant_id, actor_user_id=self.actor_user_id,
            correlation_id=self.correlation_id, revision=revision,
            event_type="policy.bundle.rollback" if rollback else "policy.bundle.promoted",
            details={"previous_revision": current_revision, "agent_count": len(statuses)},
            occurred_at=occurred_at,
        )
        return row

    async def list_decisions(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._context()
        table = metadata.tables["policy_decisions"]
        rows = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
            ).order_by(table.c.issued_at.desc(), table.c.id).limit(limit).offset(offset))
        ).mappings().all()
        return [dict(row) for row in rows]

    async def list_bundles(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._context()
        table = metadata.tables["policy_bundle_revisions"]
        rows = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
            ).order_by(table.c.created_at.desc(), table.c.id).limit(limit).offset(offset))
        ).mappings().all()
        return [dict(row) for row in rows]

    async def status(self, *, fallback_required_revision: str) -> dict[str, object]:
        await self._context()
        promotions = metadata.tables["policy_bundle_promotions"]
        latest = (
            await self.session.execute(select(promotions).where(
                promotions.c.tenant_id == self.tenant_id,
                promotions.c.promotion_state.in_(("promoted", "rollback_promoted")),
            ).order_by(promotions.c.promoted_at.desc()).limit(1))
        ).mappings().one_or_none()
        agents = metadata.tables["policy_agent_status"]
        rows = (
            await self.session.execute(select(agents).where(agents.c.tenant_id == self.tenant_id))
        ).mappings().all()
        required = str(latest["bundle_revision"]) if latest is not None else fallback_required_revision
        acknowledged = sorted(
            str(row["agent_id"])
            for row in rows
            if row["active_revision"] == required and row["bundle_state"] == "OK"
        )
        required_agents = sorted(str(row["agent_id"]) for row in rows)
        return {
            "required_revision": required,
            "previous_revision": None if latest is None else latest["previous_revision"],
            "promotion_state": "unregistered" if latest is None else latest["promotion_state"],
            "required_agents": required_agents,
            "acknowledged_agents": acknowledged,
            "converged": bool(required_agents) and acknowledged == required_agents,
        }

    async def _context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
            {"tenant": self.tenant_id},
        )


def _bundle_from_row(row) -> BundleRevision:
    return BundleRevision(
        revision=str(row["revision_name"]), source_sha256=str(row["source_sha256"]),
        artifact_sha256=str(row["artifact_sha256"]), artifact_size=int(row["artifact_size"]),
        manifest_roots=tuple(row["manifest_roots"]), rego_version=int(row["rego_version"]),
        signing_key_id=str(row["signing_key_id"]), signing_scope=str(row["signing_scope"]),
        signing_algorithm=str(row["signing_algorithm"]), author_user_id=str(row["author_user_id"]),
        reviewer_user_id=str(row["reviewer_user_id"]),
        test_evidence_sha256=str(row["test_evidence_sha256"]),
        conformance_sha256=str(row["conformance_sha256"]),
        coverage_basis_points=int(row["coverage_basis_points"]),
        signature_verified=True, status=str(row["bundle_status"]),
    )


async def _admin_audit_outbox(
    session, *, tenant_id: str, actor_user_id: str, correlation_id: str,
    revision: str, event_type: str, details: dict[str, object], occurred_at: datetime,
) -> None:
    payload = {"revision": revision, **details}
    await session.execute(insert(metadata.tables["audit_events"]).values(
        id=f"audit-{uuid4().hex}", tenant_id=tenant_id, actor_user_id=actor_user_id,
        action=event_type, subject_type="policy_bundle", subject_id=revision,
        correlation_id=correlation_id, details=payload, version=1,
        created_at=occurred_at, updated_at=occurred_at,
    ))
    await session.execute(insert(metadata.tables["outbox_events"]).values(
        id=f"outbox-{uuid4().hex}", tenant_id=tenant_id, event_type=event_type,
        aggregate_id=revision, payload=payload, published=False, version=1,
        created_at=occurred_at, updated_at=occurred_at,
    ))
