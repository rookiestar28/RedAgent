"""PostgreSQL-authoritative compat_111 ability, approval, run, and evidence state."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.persistence.models import metadata
from redagent_platform.purple_runtime.catalog import certified_abilities
from redagent_platform.purple_runtime.compiler import CompiledAbilityPlan
from redagent_platform.purple_runtime.contracts import AbilityApproval, AbilityAuthorization, LabBinding, manifest_sha256


class PurpleRepositoryConflict(RuntimeError):
    """Stable compat_111 persistence or dispatch denial."""


class PurpleRuntimeRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session; self.tenant_id = _id(tenant_id); self.actor_user_id = _id(actor_user_id); self.correlation_id = _id(correlation_id)

    async def certify_foundation(self, *, occurred_at: datetime) -> dict[str, object]:
        _aware(occurred_at); await self._context(); await self._lock("purple-foundation")
        ability = certified_abilities()["r111-file-stage-marker-v1"]; digest = manifest_sha256(ability)
        adapter = await self._immutable("purple_adapter_artifacts", {"adapter_id": ability.adapter_id, "adapter_sha256": ability.adapter_sha256},
            {"adapter_id": ability.adapter_id, "adapter_sha256": ability.adapter_sha256, "owned": True,
             "external_execution_allowed": False, "artifact_state": "certified-local-lab"}, occurred_at, "adapter")
        for external in ("apache-caldera", "atomic-red-team", "stratus-red-team", "openaev"):
            external_digest = _digest(external)
            await self._immutable("purple_adapter_artifacts", {"adapter_id": external, "adapter_sha256": external_digest},
                {"adapter_id": external, "adapter_sha256": external_digest, "owned": False,
                 "external_execution_allowed": False, "artifact_state": "disabled-reference-only"}, occurred_at, "adapter")
        row = await self._immutable("purple_abilities", {"ability_id": ability.ability_id, "ability_sha256": digest},
            {"ability_id": ability.ability_id, "ability_sha256": digest, "adapter_record_id": adapter["id"],
             "attack_version": ability.attack_version, "attack_technique_id": ability.attack_technique_id,
             "platform": ability.platform, "content_sha256": ability.content_sha256, "network_allowed": False,
             "subprocess_allowed": False, "ability_state": "certified-local-lab"}, occurred_at, "ability")
        for index, phase in enumerate(ability.phases):
            await self._immutable("purple_ability_phases", {"ability_record_id": row["id"], "phase_order": index},
                {"ability_record_id": row["id"], "phase_order": index, "phase_kind": phase.value,
                 "operation_id": f"owned-marker-{phase.value}", "operation_sha256": _digest([ability.adapter_sha256, phase.value])}, occurred_at, "phase")
        detection = await self._immutable("purple_detection_expectations", {"ability_record_id": row["id"], "analytic_id": ability.detection.analytic_id},
            {"ability_record_id": row["id"], "strategy_id": ability.detection.strategy_id,
             "analytic_id": ability.detection.analytic_id, "event_schema": ability.detection.event_schema,
             "collector_id": ability.detection.collector_id, "expectation_sha256": _digest(ability.detection.__dict__)}, occurred_at, "detection")
        await self._audit("purple.foundation.certified", ability.ability_id,
            {"ability_sha256": digest, "external_execution_allowed": False, "production_qualified": False}, occurred_at)
        return {"adapter": adapter, "ability": row, "detection": detection}

    async def register_lab(self, *, lab: LabBinding, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"purple-lab:{_id(lab.binding_id)}")
        if not lab.disposable or lab.production or lab.egress_allowed:
            raise PurpleRepositoryConflict("purple_lab_boundary_invalid")
        return await self._immutable("purple_lab_bindings", {"binding_id": lab.binding_id},
            {"binding_id": lab.binding_id, "target_id": lab.target_id, "runner_id": lab.runner_id,
             "snapshot_sha256": lab.snapshot_sha256, "telemetry_collector_id": lab.telemetry_collector_id,
             "disposable": True, "production": False, "egress_allowed": False,
             "binding_state": "active-disposable-owned", "expires_at": lab.expires_at}, occurred_at, "lab")

    async def store_approval(self, *, approval: AbilityApproval, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"purple-approval:{_id(approval.approval_id)}")
        ability = await self._find("purple_abilities", {"ability_id": approval.ability_id, "ability_sha256": approval.ability_sha256})
        lab = await self._find("purple_lab_bindings", {"binding_id": approval.lab_binding_id})
        if ability is None or lab is None or ability["ability_state"] != "certified-local-lab" or lab["snapshot_sha256"] != approval.lab_snapshot_sha256:
            raise PurpleRepositoryConflict("purple_exact_foundation_required")
        adapter = await self._find("purple_adapter_artifacts", {"id": ability["adapter_record_id"]})
        if adapter is None or not adapter["owned"] or adapter["external_execution_allowed"] or adapter["adapter_sha256"] != approval.adapter_sha256:
            raise PurpleRepositoryConflict("purple_owned_adapter_required")
        return await self._immutable("purple_approvals", {"approval_id": approval.approval_id},
            {"approval_id": approval.approval_id, "ability_record_id": ability["id"], "lab_binding_record_id": lab["id"],
             "ability_sha256": approval.ability_sha256, "adapter_sha256": approval.adapter_sha256,
             "lab_snapshot_sha256": approval.lab_snapshot_sha256, "requester_id": approval.requester_id,
             "approver_id": approval.approver_id, "executor_id": approval.executor_id, "approval_state": "approved-exact",
             "approved_at": approval.approved_at, "expires_at": approval.expires_at}, occurred_at, "approval")

    async def store_plan(self, *, plan_id: str, compiled: CompiledAbilityPlan, approval: AbilityApproval,
                         authorization: AbilityAuthorization, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"purple-plan:{_id(plan_id)}")
        ability = await self._find("purple_abilities", {"ability_id": compiled.ability_id, "ability_sha256": compiled.ability_sha256})
        lab = await self._find("purple_lab_bindings", {"binding_id": compiled.lab_binding_id})
        approved = await self._find("purple_approvals", {"approval_id": approval.approval_id})
        if ability is None or lab is None or approved is None or approved["ability_sha256"] != compiled.ability_sha256 or approved["lab_snapshot_sha256"] != compiled.lab_snapshot_sha256:
            raise PurpleRepositoryConflict("purple_exact_approval_required")
        return await self._immutable("purple_execution_plans", {"plan_id": plan_id},
            {"plan_id": plan_id, "ability_record_id": ability["id"], "lab_binding_record_id": lab["id"],
             "approval_record_id": approved["id"], "policy_decision_id": authorization.policy_decision_id,
             "roe_revision": authorization.roe_revision, "reservation_id": authorization.reservation_id,
             "lease_id": authorization.lease_id, "kill_switch_id": authorization.kill_switch_id,
             "quota_id": authorization.quota_id, "plan_sha256": compiled.plan_sha256,
             "plan_state": "compiled-owned-lab", "expires_at": authorization.expires_at}, occurred_at, "plan")

    async def create_run(self, *, run_id: str, plan_id: str, job_id: str, runner_id: str, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"purple-run:{_id(run_id)}")
        existing = await self._find("purple_runs", {"run_id": run_id})
        if existing:
            return existing
        plan = await self._find("purple_execution_plans", {"plan_id": plan_id})
        lab = await self._find("purple_lab_bindings", {"id": plan["lab_binding_record_id"]}) if plan else None
        if plan is None or lab is None or plan["expires_at"] <= occurred_at or lab["runner_id"] != runner_id:
            raise PurpleRepositoryConflict("purple_active_exact_plan_required")
        row = self._owned("run", occurred_at) | {"run_id": run_id, "plan_record_id": plan["id"], "job_id": _id(job_id),
            "runner_id": _id(runner_id), "run_state": "dispatch_pending", "dispatch_blocked": False,
            "detection_observed": False, "cleanup_complete": False, "teardown_verified": False, "failure_code": None}
        await self.session.execute(insert(metadata.tables["purple_runs"]).values(**row))
        await self._audit("purple.run.accepted", run_id, {"plan_id": plan_id, "lab_only": True}, occurred_at)
        return row

    async def request_kill(self, *, run_id: str, expected_version: int, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"purple-run:{_id(run_id)}"); row = await self._find("purple_runs", {"run_id": run_id})
        if row is None:
            raise PurpleRepositoryConflict("purple_run_not_found")
        if row["version"] != expected_version:
            raise PurpleRepositoryConflict("purple_run_version_conflict")
        values = {"run_state": "kill_requested", "dispatch_blocked": True, "version": int(row["version"]) + 1, "updated_at": occurred_at}
        await self.session.execute(update(metadata.tables["purple_runs"]).where(metadata.tables["purple_runs"].c.id == row["id"]).values(**values))
        await self._audit("purple.run.kill_requested", run_id, {"dispatch_blocked_first": True, "revoke_lease_first": True}, occurred_at)
        return row | values

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context(); result: dict[str, list[dict[str, object]]] = {}
        for key, name in (("abilities", "purple_abilities"), ("detections", "purple_detection_expectations"),
                          ("labs", "purple_lab_bindings"), ("approvals", "purple_approvals"),
                          ("plans", "purple_execution_plans"), ("runs", "purple_runs"),
                          ("telemetry", "purple_telemetry_events"), ("cleanups", "purple_cleanup_receipts"),
                          ("teardowns", "purple_teardown_receipts"), ("rehearsals", "purple_rehearsal_receipts")):
            table = metadata.tables[name]
            rows = (await self.session.execute(select(table).where(table.c.tenant_id == self.tenant_id).order_by(table.c.created_at.desc()).limit(100))).mappings().all()
            result[key] = [dict(item) for item in rows]
        capabilities = metadata.tables["execution_capability_manifests"]
        capability_rows = (await self.session.execute(select(capabilities).where(
            capabilities.c.tenant_id == self.tenant_id,
            capabilities.c.capability_id == "purple-lab",
            capabilities.c.capability_status == "certified",
        ))).mappings().all()
        registrations = metadata.tables["runner_registrations"]
        runner_rows = (await self.session.execute(select(registrations).where(
            registrations.c.tenant_id == self.tenant_id,
        ).order_by(registrations.c.last_seen_at.desc()).limit(100))).mappings().all()
        jobs = metadata.tables["jobs"]
        job_rows = (await self.session.execute(select(jobs).where(
            jobs.c.tenant_id == self.tenant_id,
        ).order_by(jobs.c.created_at.desc()).limit(100))).mappings().all()
        reservations = metadata.tables["quota_reservations"]
        reservation_rows = (await self.session.execute(select(reservations).where(
            reservations.c.tenant_id == self.tenant_id,
            reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
        ).order_by(reservations.c.created_at.desc()).limit(100))).mappings().all()
        compatible = {
            (f"{row['adapter_id']}:{row['adapter_version']}", str(row["image_digest"]))
            for row in capability_rows
        }
        # CRITICAL: option visibility is read-only; compile/run handlers retain exact authorization authority.
        result["lab_options"] = [row for row in result["labs"] if row["binding_state"] == "active-disposable-owned"]
        result["approval_options"] = [row for row in result["approvals"] if row["approval_state"] == "approved-exact"]
        result["runner_options"] = [dict(row) for row in runner_rows if any(
            adapter in row["adapter_allowlist"] and image in row["image_allowlist"]
            for adapter, image in compatible
        )]
        result["job_options"] = [dict(row) for row in job_rows if (
            isinstance(row["request"], dict) and row["request"].get("capability") == "purple-lab"
        )]
        result["reservation_options"] = [dict(row) for row in reservation_rows]
        return result

    async def _immutable(self, table_name: str, where: dict[str, object], values: dict[str, object], occurred_at: datetime, prefix: str) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing:
            if any(existing[name] != value for name, value in values.items()):
                raise PurpleRepositoryConflict(f"purple_{prefix}_immutable")
            return existing
        row = self._owned(prefix, occurred_at) | values
        await self.session.execute(insert(metadata.tables[table_name]).values(**row)); return row

    async def _find(self, table_name: str, where: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]
        clauses = [table.c.tenant_id == self.tenant_id] + [getattr(table.c, key) == value for key, value in where.items()]
        row = (await self.session.execute(select(table).where(*clauses))).mappings().one_or_none()
        return dict(row) if row else None

    def _owned(self, prefix: str, occurred_at: datetime) -> dict[str, object]:
        return {"id": f"purple-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id, "version": 1,
                "created_at": occurred_at, "updated_at": occurred_at}

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": f"{self.tenant_id}:{scope}"})

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        owned = {"tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables["audit_events"]).values(id=f"audit-{uuid4().hex}", actor_user_id=self.actor_user_id,
            action=event, subject_type="purple_lab", subject_id=subject[:64], correlation_id=self.correlation_id, details=details, **owned))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(id=f"outbox-{uuid4().hex}", event_type=event,
            aggregate_id=subject[:64], payload=details, published=False, **owned))


def _id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not all(char.isalnum() or char in "._:-" for char in value):
        raise PurpleRepositoryConflict("purple_identifier_invalid")
    return value


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PurpleRepositoryConflict("purple_time_invalid")


def _digest(value: object) -> str:
    import hashlib
    import json
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
