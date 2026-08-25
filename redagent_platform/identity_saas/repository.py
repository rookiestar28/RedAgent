"""PostgreSQL-authoritative compat_109 identity profile, plan, run, and cleanup truth."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.identity_saas.compiler import CompiledIdentityPlan
from redagent_platform.identity_saas.contracts import IdentityAuthorization
from redagent_platform.identity_saas.profiles import adapter_declarations, emulator_profiles
from redagent_platform.persistence.models import metadata


class IdentityRepositoryConflict(RuntimeError):
    """Stable compat_109 persistence/revalidation denial."""


class IdentitySaasRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session; self.tenant_id = _id(tenant_id); self.actor_user_id = _id(actor_user_id); self.correlation_id = _id(correlation_id)

    async def certify_foundation(self, *, source_sha256: str, occurred_at: datetime) -> dict[str, object]:
        _sha(source_sha256); _aware(occurred_at); await self._context(); await self._lock("identity-foundation")
        enabled = await self._immutable("identity_adapter_artifacts", {"adapter_id": "redagent-identity-emulator", "artifact_sha256": source_sha256},
            {"adapter_id": "redagent-identity-emulator", "artifact_sha256": source_sha256, "execution_enabled": True, "production_qualified": False}, occurred_at, "adapter")
        for declaration in adapter_declarations():
            digest = _digest(declaration.source_url)
            await self._immutable("identity_adapter_artifacts", {"adapter_id": declaration.adapter_id, "artifact_sha256": digest},
                {"adapter_id": declaration.adapter_id, "artifact_sha256": digest, "execution_enabled": False, "production_qualified": False}, occurred_at, "adapter")
        for provider, profile in emulator_profiles().items():
            profile_row = await self._immutable("identity_provider_profiles", {"profile_id": profile.profile_id, "profile_sha256": _digest(_profile_material(profile))},
                {"profile_id": profile.profile_id, "provider": provider.value, "profile_sha256": _digest(_profile_material(profile)), "emulator_only": True,
                 "limits": {"calls": profile.max_calls, "pages": profile.max_pages, "resources": profile.max_resources, "bytes": profile.max_bytes, "timeout": profile.timeout_seconds},
                 "retention_days": profile.snapshot_retention_days, "profile_state": "certified-local-lab"}, occurred_at, "profile")
            scopes = tuple(item.permission_scope for item in profile.operations); roles = tuple(item.effective_role_permission for item in profile.operations)
            for operation in profile.operations:
                await self._immutable("identity_operation_manifests", {"profile_record_id": profile_row["id"], "operation_id": operation.operation_id},
                    {"profile_record_id": profile_row["id"], "operation_id": operation.operation_id, "method": operation.method, "api_version": operation.api_version,
                     "permission_scope": operation.permission_scope, "role_permission": operation.effective_role_permission,
                     "selected_fields": list(operation.selected_fields), "data_class": operation.data_class.value, "graph_eligible": operation.graph_eligible}, occurred_at, "operation")
            await self._immutable("identity_tenant_bindings", {"binding_id": f"r109-{provider.value}-binding-v1"},
                {"binding_id": f"r109-{provider.value}-binding-v1", "profile_record_id": profile_row["id"], "provider_tenant_id": profile.tenant_id,
                 "audience": profile.audience, "consent_mode": profile.consent_mode.value, "scopes": list(scopes), "role_permissions": list(roles),
                 "permission_digest": _digest([scopes, roles]), "binding_state": "active-local-emulator"}, occurred_at, "binding")
        baseline = await self._immutable("identity_baseline_artifacts", {"baseline_id": "r109-identity-baseline-v1", "baseline_sha256": "5" * 64},
            {"baseline_id": "r109-identity-baseline-v1", "baseline_version": "1.0.0", "baseline_sha256": "5" * 64,
             "schema_sha256": "6" * 64, "baseline_state": "certified-local-lab"}, occurred_at, "baseline")
        await self._audit("identity.foundation.certified", "r109-identity-foundation", {"production_qualified": False, "external_execution": False}, occurred_at)
        return {"adapter": enabled, "baseline": baseline}

    async def store_plan(self, *, plan_id: str, binding_id: str, compiled: CompiledIdentityPlan, authorization: IdentityAuthorization, occurred_at: datetime) -> dict[str, object]:
        key = _id(plan_id); await self._context(); await self._lock(f"identity-plan:{key}")
        profiles = metadata.tables["identity_provider_profiles"]; bindings = metadata.tables["identity_tenant_bindings"]; baselines = metadata.tables["identity_baseline_artifacts"]
        row = (await self.session.execute(select(profiles.c.id.label("profile_record_id"), bindings.c.id.label("binding_record_id"), bindings.c.provider_tenant_id,
            bindings.c.audience, bindings.c.consent_mode, bindings.c.scopes, bindings.c.role_permissions).join(bindings, bindings.c.profile_record_id == profiles.c.id).where(
            profiles.c.tenant_id == self.tenant_id, profiles.c.profile_id == compiled.profile_id, profiles.c.profile_state == "certified-local-lab", profiles.c.emulator_only.is_(True),
            bindings.c.tenant_id == self.tenant_id, bindings.c.binding_id == _id(binding_id), bindings.c.binding_state == "active-local-emulator"))).mappings().one_or_none()
        baseline = (await self.session.execute(select(baselines.c.id).where(baselines.c.tenant_id == self.tenant_id, baselines.c.baseline_id == "r109-identity-baseline-v1", baselines.c.baseline_state == "certified-local-lab"))).one_or_none()
        if row is None or baseline is None or (row["provider_tenant_id"], row["audience"], row["consent_mode"]) != (compiled.tenant_id, compiled.audience, compiled.consent_mode):
            raise IdentityRepositoryConflict("identity_exact_binding_required")
        if tuple(row["scopes"]) != compiled.scopes or tuple(row["role_permissions"]) != compiled.effective_role_permissions:
            raise IdentityRepositoryConflict("identity_permission_revalidation_required")
        result = await self._immutable("identity_collection_plans", {"plan_id": key}, {"plan_id": key, "profile_record_id": row["profile_record_id"],
            "binding_record_id": row["binding_record_id"], "baseline_record_id": baseline.id, "policy_decision_id": authorization.policy_decision_id,
            "reservation_id": authorization.reservation_id, "credential_lease_id": authorization.credential_lease_id, "plan_sha256": compiled.plan_sha256,
            "plan_state": "compiled-local-lab", "expires_at": authorization.expires_at}, occurred_at, "plan")
        await self._audit("identity.plan.compiled", key, {"profile_id": compiled.profile_id, "binding_id": binding_id, "plan_sha256": compiled.plan_sha256}, occurred_at)
        return result

    async def create_run(self, *, run_id: str, plan_id: str, job_id: str, runner_id: str, occurred_at: datetime) -> dict[str, object]:
        key = _id(run_id); await self._context(); await self._lock(f"identity-run:{key}")
        existing = await self._find("identity_collection_runs", {"run_id": key})
        if existing: return existing
        plan = await self._find("identity_collection_plans", {"plan_id": _id(plan_id)})
        if plan is None or plan["plan_state"] != "compiled-local-lab" or plan["expires_at"] <= occurred_at: raise IdentityRepositoryConflict("identity_active_plan_required")
        row = self._owned("run", occurred_at) | {"run_id": key, "plan_record_id": plan["id"], "job_id": _id(job_id), "runner_id": _id(runner_id),
            "run_state": "dispatch_pending", "complete": False, "partial_reasons": [], "snapshot_sha256": None}
        await self.session.execute(insert(metadata.tables["identity_collection_runs"]).values(**row)); await self._audit("identity.run.accepted", key, {"plan_id": plan_id}, occurred_at); return row

    async def request_cancel(self, *, run_id: str, expected_version: int, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"identity-run:{_id(run_id)}"); row = await self._find("identity_collection_runs", {"run_id": run_id})
        if row is None: raise IdentityRepositoryConflict("identity_run_not_found")
        if row["run_state"] in {"cancelled", "succeeded", "failed"}: return row
        if row["version"] != expected_version: raise IdentityRepositoryConflict("identity_run_version_conflict")
        values = {"run_state": "cancel_requested", "version": int(row["version"]) + 1, "updated_at": occurred_at}
        await self.session.execute(update(metadata.tables["identity_collection_runs"]).where(metadata.tables["identity_collection_runs"].c.id == row["id"]).values(**values))
        await self._audit("identity.run.cancel_requested", run_id, {"block_requests_first": True, "revoke_lease_first": True}, occurred_at); return row | values

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context(); result = {}
        for key, table_name in (("profiles", "identity_provider_profiles"), ("bindings", "identity_tenant_bindings"), ("plans", "identity_collection_plans"),
            ("runs", "identity_collection_runs"), ("evaluations", "identity_baseline_evaluations"), ("exceptions", "identity_exception_annotations"),
            ("graphs", "identity_graph_approvals"), ("cleanups", "identity_cleanup_receipts")):
            table = metadata.tables[table_name]; rows = (await self.session.execute(select(table).where(table.c.tenant_id == self.tenant_id).order_by(table.c.created_at.desc()).limit(100))).mappings().all(); result[key] = [dict(item) for item in rows]
        capabilities = metadata.tables["execution_capability_manifests"]
        capability_rows = (await self.session.execute(select(capabilities).where(
            capabilities.c.tenant_id == self.tenant_id,
            capabilities.c.capability_id == "identity-posture",
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
        leases = metadata.tables["secret_leases"]
        lease_rows = (await self.session.execute(select(leases).where(
            leases.c.tenant_id == self.tenant_id,
            leases.c.capability == "identity-posture",
        ).order_by(leases.c.issued_at.desc()).limit(100))).mappings().all()
        compatible = {
            (f"{row['adapter_id']}:{row['adapter_version']}", str(row["image_digest"]))
            for row in capability_rows
        }
        # CRITICAL: option visibility is read-only; mutation handlers remain the authority for compile/run state.
        result["binding_options"] = [row for row in result["bindings"] if row["binding_state"] == "active-local-emulator"]
        result["runner_options"] = [dict(row) for row in runner_rows if any(
            adapter in row["adapter_allowlist"] and image in row["image_allowlist"]
            for adapter, image in compatible
        )]
        result["job_options"] = [dict(row) for row in job_rows if (
            isinstance(row["request"], dict) and row["request"].get("capability") == "identity-posture"
        )]
        result["reservation_options"] = [dict(row) for row in reservation_rows]
        result["lease_options"] = [dict(row) for row in lease_rows]
        return result

    async def _immutable(self, table_name: str, where: dict[str, object], values: dict[str, object], occurred_at: datetime, prefix: str) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing:
            if any(existing[name] != value for name, value in values.items()): raise IdentityRepositoryConflict(f"identity_{prefix}_immutable")
            return existing
        row = self._owned(prefix, occurred_at) | values; await self.session.execute(insert(metadata.tables[table_name]).values(**row)); return row

    async def _find(self, table_name: str, where: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]; clauses = [table.c.tenant_id == self.tenant_id] + [getattr(table.c, key) == value for key, value in where.items()]
        row = (await self.session.execute(select(table).where(*clauses))).mappings().one_or_none(); return dict(row) if row else None

    def _owned(self, prefix: str, occurred_at: datetime) -> dict[str, object]: return {"id": f"identity-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
    async def _context(self) -> None: await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})
    async def _lock(self, scope: str) -> None: await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": f"{self.tenant_id}:{scope}"})
    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        owned = {"tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables["audit_events"]).values(id=f"audit-{uuid4().hex}", actor_user_id=self.actor_user_id, action=event, subject_type="identity_assessment", subject_id=subject[:64], correlation_id=self.correlation_id, details=details, **owned))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(id=f"outbox-{uuid4().hex}", event_type=event, aggregate_id=subject[:64], payload=details, published=False, **owned))


def _profile_material(profile: object) -> dict[str, object]:
    value = asdict(profile)  # type: ignore[arg-type]
    value["provider"] = profile.provider.value  # type: ignore[attr-defined]
    value["consent_mode"] = profile.consent_mode.value  # type: ignore[attr-defined]
    for operation in value["operations"]: operation["data_class"] = operation["data_class"].value
    return value


def _id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not all(char.isalnum() or char in "._:-" for char in value): raise IdentityRepositoryConflict("identity_identifier_invalid")
    return value
def _sha(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value): raise IdentityRepositoryConflict("identity_sha256_invalid")
def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None: raise IdentityRepositoryConflict("identity_time_invalid")
def _digest(value: object) -> str: return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
