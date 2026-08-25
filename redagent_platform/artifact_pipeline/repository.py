"""PostgreSQL-authoritative compat_110 artifact pipeline state."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.artifact_pipeline.compiler import CompiledArtifactPlan
from redagent_platform.artifact_pipeline.contracts import ArtifactAuthorization
from redagent_platform.artifact_pipeline.profiles import certified_profiles
from redagent_platform.persistence.models import metadata


class ArtifactRepositoryConflict(RuntimeError):
    """Stable compat_110 persistence or dispatch denial."""


class ArtifactPipelineRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session; self.tenant_id = _id(tenant_id); self.actor_user_id = _id(actor_user_id); self.correlation_id = _id(correlation_id)

    async def certify_foundation(self, *, source_sha256: str, occurred_at: datetime) -> dict[str, object]:
        _sha(source_sha256); _aware(occurred_at); await self._context(); await self._lock("artifact-foundation")
        adapter = await self._immutable("artifact_adapter_artifacts", {"adapter_id": "redagent-canonical-artifact", "artifact_sha256": source_sha256},
            {"adapter_id": "redagent-canonical-artifact", "artifact_sha256": source_sha256, "execution_enabled": True, "production_qualified": False, "legal_state": "internal-owned"}, occurred_at, "adapter")
        for name in ("syft-grype", "gitleaks", "semgrep", "scorecard", "mobsf"):
            digest = _digest(name); await self._immutable("artifact_adapter_artifacts", {"adapter_id": name, "artifact_sha256": digest},
                {"adapter_id": name, "artifact_sha256": digest, "execution_enabled": False, "production_qualified": False, "legal_state": "external-review-pending"}, occurred_at, "adapter")
        for profile in certified_profiles().values():
            await self._immutable("artifact_pipeline_profiles", {"profile_id": profile.profile_id, "profile_sha256": _digest(asdict(profile))},
                {"profile_id": profile.profile_id, "artifact_kind": profile.artifact_kind.value, "profile_sha256": _digest(asdict(profile)),
                 "stages": [item.value for item in profile.stages], "limits": {"files": profile.max_files, "bytes": profile.max_bytes, "depth": profile.max_depth, "ratio": profile.max_expansion_ratio, "timeout": profile.timeout_seconds},
                 "zero_execution": True, "profile_state": "certified-local-lab"}, occurred_at, "profile")
        rules = await self._immutable("artifact_rule_bundles", {"bundle_id": "r110-rules-v1", "bundle_sha256": "3" * 64},
            {"bundle_id": "r110-rules-v1", "bundle_kind": "owned-static", "bundle_version": "1.0.0", "bundle_sha256": "3" * 64, "schema_sha256": "4" * 64, "bundle_state": "certified-local-lab"}, occurred_at, "rules")
        database = await self._immutable("artifact_database_snapshots", {"database_id": "r110-database-v1", "database_sha256": "5" * 64},
            {"database_id": "r110-database-v1", "database_kind": "synthetic-vulnerability-license", "database_version": "1.0.0", "database_sha256": "5" * 64, "schema_sha256": "6" * 64, "database_state": "certified-local-lab"}, occurred_at, "database")
        await self._audit("artifact.foundation.certified", "r110-artifact-foundation", {"zero_execution": True, "external_execution": False}, occurred_at)
        return {"adapter": adapter, "rules": rules, "database": database}

    async def register_binding(self, *, binding_id: str, compiled: CompiledArtifactPlan, declared_files: int, declared_bytes: int, expires_at: datetime, occurred_at: datetime) -> dict[str, object]:
        _aware(expires_at); _aware(occurred_at); await self._context(); await self._lock(f"artifact-binding:{_id(binding_id)}")
        if declared_files < 1 or declared_files > compiled.max_files or declared_bytes < 1 or declared_bytes > compiled.max_bytes: raise ArtifactRepositoryConflict("artifact_declared_budget_invalid")
        return await self._immutable("artifact_bindings", {"binding_id": binding_id}, {"binding_id": binding_id, "artifact_kind": compiled.artifact_kind.value,
            "artifact_sha256": compiled.artifact_sha256, "manifest_sha256": compiled.manifest_sha256, "declared_files": declared_files, "declared_bytes": declared_bytes,
            "classification": "restricted-source", "binding_state": "active-canonical-fixture", "expires_at": expires_at}, occurred_at, "binding")

    async def store_plan(self, *, plan_id: str, compiled: CompiledArtifactPlan, authorization: ArtifactAuthorization, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"artifact-plan:{_id(plan_id)}"); profiles = metadata.tables["artifact_pipeline_profiles"]
        profile = (await self.session.execute(select(profiles.c.id).where(profiles.c.tenant_id == self.tenant_id, profiles.c.profile_id == compiled.profile_id, profiles.c.zero_execution.is_(True), profiles.c.profile_state == "certified-local-lab"))).one_or_none()
        binding = await self._find("artifact_bindings", {"binding_id": compiled.artifact_binding_id}); rules = await self._find("artifact_rule_bundles", {"bundle_id": "r110-rules-v1"}); database = await self._find("artifact_database_snapshots", {"database_id": "r110-database-v1"})
        if profile is None or binding is None or rules is None or database is None or binding["artifact_sha256"] != compiled.artifact_sha256 or binding["manifest_sha256"] != compiled.manifest_sha256: raise ArtifactRepositoryConflict("artifact_exact_foundation_required")
        return await self._immutable("artifact_analysis_plans", {"plan_id": plan_id}, {"plan_id": plan_id, "profile_record_id": profile.id, "binding_record_id": binding["id"],
            "rule_bundle_id": rules["id"], "database_snapshot_id": database["id"], "policy_decision_id": authorization.policy_decision_id,
            "reservation_id": authorization.reservation_id, "artifact_lease_id": authorization.artifact_lease_id, "plan_sha256": compiled.plan_sha256,
            "plan_state": "compiled-canonical-fixture", "expires_at": authorization.expires_at}, occurred_at, "plan")

    async def create_run(self, *, run_id: str, plan_id: str, job_id: str, runner_id: str, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"artifact-run:{_id(run_id)}"); existing = await self._find("artifact_analysis_runs", {"run_id": run_id})
        if existing: return existing
        plan = await self._find("artifact_analysis_plans", {"plan_id": plan_id})
        if plan is None or plan["expires_at"] <= occurred_at: raise ArtifactRepositoryConflict("artifact_active_plan_required")
        row = self._owned("run", occurred_at) | {"run_id": run_id, "plan_record_id": plan["id"], "job_id": _id(job_id), "runner_id": _id(runner_id), "run_state": "dispatch_pending", "complete": False, "partial_reasons": [], "result_sha256": None, "untrusted_execution_count": 0}
        await self.session.execute(insert(metadata.tables["artifact_analysis_runs"]).values(**row)); await self._audit("artifact.run.accepted", run_id, {"plan_id": plan_id, "zero_execution": True}, occurred_at); return row

    async def request_cancel(self, *, run_id: str, expected_version: int, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"artifact-run:{_id(run_id)}"); row = await self._find("artifact_analysis_runs", {"run_id": run_id})
        if row is None: raise ArtifactRepositoryConflict("artifact_run_not_found")
        if row["version"] != expected_version: raise ArtifactRepositoryConflict("artifact_run_version_conflict")
        values = {"run_state": "cancel_requested", "version": int(row["version"]) + 1, "updated_at": occurred_at}; await self.session.execute(update(metadata.tables["artifact_analysis_runs"]).where(metadata.tables["artifact_analysis_runs"].c.id == row["id"]).values(**values))
        await self._audit("artifact.run.cancel_requested", run_id, {"block_reads_first": True, "revoke_lease_first": True}, occurred_at); return row | values

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context(); result = {}
        for key, name in (("profiles", "artifact_pipeline_profiles"), ("bindings", "artifact_bindings"), ("plans", "artifact_analysis_plans"), ("runs", "artifact_analysis_runs"), ("components", "artifact_components"), ("vulnerabilities", "artifact_vulnerability_observations"), ("credential_findings", "artifact_credential_findings"), ("static_findings", "artifact_static_findings"), ("mobile", "artifact_mobile_observations"), ("cleanups", "artifact_cleanup_receipts")):
            table = metadata.tables[name]; rows = (await self.session.execute(select(table).where(table.c.tenant_id == self.tenant_id).order_by(table.c.created_at.desc()).limit(100))).mappings().all(); result[key] = [dict(item) for item in rows]
        capabilities = metadata.tables["execution_capability_manifests"]
        capability_rows = (await self.session.execute(select(capabilities).where(
            capabilities.c.tenant_id == self.tenant_id,
            capabilities.c.capability_id == "artifact-posture",
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
        # CRITICAL: option visibility is read-only; mutation handlers remain the authority for compile/run state.
        result["binding_options"] = [row for row in result["bindings"] if row["binding_state"] == "active-canonical-fixture"]
        result["runner_options"] = [dict(row) for row in runner_rows if any(
            adapter in row["adapter_allowlist"] and image in row["image_allowlist"]
            for adapter, image in compatible
        )]
        result["job_options"] = [dict(row) for row in job_rows if (
            isinstance(row["request"], dict) and row["request"].get("capability") == "artifact-posture"
        )]
        result["reservation_options"] = [dict(row) for row in reservation_rows]
        return result

    async def _immutable(self, table_name: str, where: dict[str, object], values: dict[str, object], occurred_at: datetime, prefix: str) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing:
            if any(existing[name] != value for name, value in values.items()): raise ArtifactRepositoryConflict(f"artifact_{prefix}_immutable")
            return existing
        row = self._owned(prefix, occurred_at) | values; await self.session.execute(insert(metadata.tables[table_name]).values(**row)); return row
    async def _find(self, table_name: str, where: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]; clauses = [table.c.tenant_id == self.tenant_id] + [getattr(table.c, key) == value for key, value in where.items()]; row = (await self.session.execute(select(table).where(*clauses))).mappings().one_or_none(); return dict(row) if row else None
    def _owned(self, prefix: str, occurred_at: datetime) -> dict[str, object]: return {"id": f"artifact-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
    async def _context(self) -> None: await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})
    async def _lock(self, scope: str) -> None: await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": f"{self.tenant_id}:{scope}"})
    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        owned = {"tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}; await self.session.execute(insert(metadata.tables["audit_events"]).values(id=f"audit-{uuid4().hex}", actor_user_id=self.actor_user_id, action=event, subject_type="artifact_assessment", subject_id=subject[:64], correlation_id=self.correlation_id, details=details, **owned)); await self.session.execute(insert(metadata.tables["outbox_events"]).values(id=f"outbox-{uuid4().hex}", event_type=event, aggregate_id=subject[:64], payload=details, published=False, **owned))


def _id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not all(char.isalnum() or char in "._:-" for char in value): raise ArtifactRepositoryConflict("artifact_identifier_invalid")
    return value
def _sha(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value): raise ArtifactRepositoryConflict("artifact_sha256_invalid")
def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None: raise ArtifactRepositoryConflict("artifact_time_invalid")
def _digest(value: object) -> str: return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
