"""PostgreSQL-authoritative compat_108 profile, plan, snapshot, result, and cleanup truth."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.cloud_connectors.checks import SnapshotEvaluation
from redagent_platform.cloud_connectors.collector import CollectionSnapshot
from redagent_platform.cloud_connectors.compiler import CompiledCollectionPlan
from redagent_platform.cloud_connectors.contracts import CollectionAuthorization
from redagent_platform.cloud_connectors.profiles import adapter_declarations, emulator_profiles
from redagent_platform.persistence.models import metadata


class CloudRepositoryConflict(RuntimeError):
    """Stable compat_108 persistence or dispatch revalidation denial."""


class CloudRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _identifier("tenant_id", tenant_id, 64)
        self.actor_user_id = _identifier("actor_user_id", actor_user_id, 64)
        self.correlation_id = _identifier("correlation_id", correlation_id, 100)

    async def certify_foundation(self, *, source_sha256: str, occurred_at: datetime) -> dict[str, object]:
        _sha(source_sha256)
        _aware(occurred_at)
        await self._context()
        await self._lock("cloud-foundation")
        enabled = await self._immutable("cloud_adapter_artifacts", {"adapter_id": "redagent-emulator-offline", "artifact_sha256": source_sha256}, {
            "adapter_id": "redagent-emulator-offline", "adapter_version": "1.0.0-r108.1",
            "artifact_sha256": source_sha256, "license_id": "Proprietary",
            "sbom_sha256": _canonical_sha({"source": source_sha256, "runtime": "python-stdlib"}),
            "execution_enabled": True, "production_qualified": False,
        }, occurred_at, "adapter")
        for declaration in adapter_declarations():
            await self._immutable("cloud_adapter_artifacts", {"adapter_id": declaration.adapter_id, "artifact_sha256": _canonical_sha(declaration.source_url)}, {
                "adapter_id": declaration.adapter_id, "adapter_version": "reference-only",
                "artifact_sha256": _canonical_sha(declaration.source_url), "license_id": declaration.license_id,
                "sbom_sha256": _canonical_sha({"not_downloaded": declaration.source_url}),
                "execution_enabled": False, "production_qualified": False,
            }, occurred_at, "adapter")
        for provider, profile in emulator_profiles().items():
            material = _profile_material(profile)
            profile_row = await self._immutable("cloud_provider_profiles", {"profile_id": profile.profile_id, "profile_sha256": _canonical_sha(material)}, {
                "profile_id": profile.profile_id, "provider": provider.value,
                "profile_sha256": _canonical_sha(material), "emulator_only": True,
                "limits": {"api_calls": profile.max_api_calls, "pages": profile.max_pages, "resources": profile.max_resources, "response_bytes": profile.max_response_bytes, "timeout_seconds": profile.timeout_seconds},
                "profile_state": "certified-local-lab",
            }, occurred_at, "profile")
            permissions = tuple(item.action for item in profile.operations)
            data_classes = tuple(dict.fromkeys(item.data_class.value for item in profile.operations))
            for item in profile.operations:
                await self._immutable("cloud_operation_manifests", {"profile_record_id": profile_row["id"], "operation_id": item.operation_id}, {
                    "profile_record_id": profile_row["id"], "operation_id": item.operation_id,
                    "action": item.action, "resource_scope": item.resource_scope,
                    "data_class": item.data_class.value, "mutation": item.mutation, "page_cost": item.page_cost,
                }, occurred_at, "operation")
            await self._immutable("cloud_identity_bindings", {"binding_id": f"r108-{provider.value}-identity-v1"}, {
                "binding_id": f"r108-{provider.value}-identity-v1", "profile_record_id": profile_row["id"],
                "provider": provider.value, "expected_tenant": profile.expected_identity.tenant,
                "expected_parent": profile.expected_identity.parent, "permissions": list(permissions),
                "data_classes": list(data_classes), "permission_digest": _canonical_sha(list(permissions)),
                "binding_state": "active-local-emulator",
            }, occurred_at, "identity")
        await self._immutable("cloud_control_packs", {"pack_id": "r108-cloud-baseline-v1", "pack_sha256": "3" * 64}, {
            "pack_id": "r108-cloud-baseline-v1", "pack_version": "1.0.0",
            "pack_sha256": "3" * 64, "database_sha256": "4" * 64,
            "data_classes": ["resource_metadata", "security_configuration"],
            "pack_state": "certified-local-lab",
        }, occurred_at, "pack")
        await self._audit("cloud.foundation.certified", "r108-cloud-foundation", {
            "source_sha256": source_sha256, "production_qualified": False,
            "external_execution_enabled": False,
        }, occurred_at)
        return enabled

    async def store_plan(self, *, plan_id: str, binding_id: str, compiled: CompiledCollectionPlan, authorization: CollectionAuthorization, roe_version_id: str, occurred_at: datetime) -> dict[str, object]:
        key = _identifier("plan_id", plan_id, 100)
        binding_key = _identifier("binding_id", binding_id, 100)
        _identifier("roe_version_id", roe_version_id, 64)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"cloud-plan:{key}")
        profiles = metadata.tables["cloud_provider_profiles"]
        bindings = metadata.tables["cloud_identity_bindings"]
        row = (await self.session.execute(select(
            profiles.c.id.label("profile_record_id"), profiles.c.provider,
            bindings.c.id.label("binding_record_id"), bindings.c.expected_tenant,
            bindings.c.permissions, bindings.c.permission_digest,
        ).join(bindings, bindings.c.profile_record_id == profiles.c.id).where(
            profiles.c.tenant_id == self.tenant_id, profiles.c.profile_id == compiled.profile_id,
            profiles.c.profile_state == "certified-local-lab", profiles.c.emulator_only.is_(True),
            bindings.c.tenant_id == self.tenant_id, bindings.c.binding_id == binding_key,
            bindings.c.binding_state == "active-local-emulator",
        ))).mappings().one_or_none()
        if row is None or row["provider"] != compiled.provider.value or row["expected_tenant"] != compiled.expected_identity.tenant:
            raise CloudRepositoryConflict("cloud_identity_binding_required")
        if tuple(row["permissions"]) != compiled.permissions or row["permission_digest"] != _canonical_sha(list(compiled.permissions)):
            raise CloudRepositoryConflict("cloud_permission_revalidation_required")
        plan = await self._immutable("cloud_collection_plans", {"plan_id": key}, {
            "plan_id": key, "profile_record_id": row["profile_record_id"], "identity_binding_id": row["binding_record_id"],
            "policy_decision_id": authorization.policy_decision_id, "policy_revision": authorization.policy_revision,
            "reservation_id": authorization.reservation_id, "credential_lease_id": authorization.credential_lease_id,
            "plan_sha256": compiled.plan_sha256, "plan_state": "compiled-local-lab",
            "expires_at": authorization.expires_at,
        }, occurred_at, "plan")
        await self._audit("cloud.plan.compiled", key, {"plan_sha256": compiled.plan_sha256, "roe_version_id": roe_version_id, "binding_id": binding_key}, occurred_at)
        return plan

    async def create_run(self, *, run_id: str, plan_id: str, job_id: str, runner_id: str, occurred_at: datetime) -> dict[str, object]:
        run_key = _identifier("run_id", run_id, 100)
        plan_key = _identifier("plan_id", plan_id, 100)
        _identifier("job_id", job_id, 100); _identifier("runner_id", runner_id, 100); _aware(occurred_at)
        await self._context(); await self._lock(f"cloud-run:{run_key}")
        existing = await self._find("cloud_collection_runs", {"run_id": run_key})
        if existing is not None:
            return existing
        plan = await self._find("cloud_collection_plans", {"plan_id": plan_key})
        if plan is None or plan["plan_state"] != "compiled-local-lab" or plan["expires_at"] <= occurred_at:
            raise CloudRepositoryConflict("cloud_plan_active_required")
        row = {"id": f"cloud-run-{uuid4().hex}", "tenant_id": self.tenant_id, "run_id": run_key,
               "plan_record_id": plan["id"], "job_id": job_id, "runner_id": runner_id,
               "run_state": "dispatch_pending", "complete": False, "partial_reasons": [], "snapshot_sha256": None,
               "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables["cloud_collection_runs"]).values(**row))
        await self._audit("cloud.run.accepted", run_key, {"plan_id": plan_key}, occurred_at)
        return row

    async def record_evaluation(self, *, run_id: str, snapshot: CollectionSnapshot, evaluation: SnapshotEvaluation, occurred_at: datetime) -> dict[str, object]:
        run = await self._active_run(run_id)
        plans = metadata.tables["cloud_collection_plans"]
        plan_sha = (await self.session.execute(select(plans.c.plan_sha256).where(plans.c.tenant_id == self.tenant_id, plans.c.id == run["plan_record_id"]))).scalar_one()
        if plan_sha != snapshot.plan_sha256 or evaluation.snapshot_sha256 != snapshot.snapshot_sha256:
            raise CloudRepositoryConflict("cloud_snapshot_plan_mismatch")
        for index in range(snapshot.page_count):
            await self._immutable("cloud_snapshot_pages", {"run_record_id": run["id"], "operation_id": f"snapshot-page-{index}", "page_index": index}, {
                "run_record_id": run["id"], "operation_id": f"snapshot-page-{index}", "page_index": index,
                "response_sha256": _canonical_sha({"snapshot": snapshot.snapshot_sha256, "page": index}),
                "response_bytes": 0, "partial_reason": snapshot.partial_reasons[0] if snapshot.partial_reasons else None,
            }, occurred_at, "page")
        for resource in snapshot.resources:
            await self._immutable("cloud_snapshot_resources", {"run_record_id": run["id"], "operation_id": resource.operation_id, "resource_id": resource.resource_id}, {
                "run_record_id": run["id"], "operation_id": resource.operation_id, "resource_id": resource.resource_id,
                "resource_sha256": _canonical_sha({"resource_id": resource.resource_id, "attributes": resource.attributes}),
                "data_class": "security_configuration", "redaction_state": "minimized-hash-only",
            }, occurred_at, "resource")
        for index, result in enumerate(evaluation.results, start=1):
            await self._immutable("cloud_check_results", {"result_id": f"{run_id}:result:{index}"}, {
                "run_record_id": run["id"], "result_id": f"{run_id}:result:{index}",
                "control_pack_id": evaluation.control_pack_id, "check_id": result.check_id,
                "resource_id": result.resource_id, "passed": result.passed, "severity": result.severity,
                "evidence_instance_id": None,
            }, occurred_at, "result")
        await self._immutable("cloud_cleanup_receipts", {"receipt_id": f"{run_id}:cleanup"}, {
            "run_record_id": run["id"], "receipt_id": f"{run_id}:cleanup", "lease_revoked": True,
            "new_requests_blocked": True, "residual_resource_count": 0,
            "inventory_sha256": _canonical_sha([]), "completed_at": occurred_at,
        }, occurred_at, "cleanup")
        values = {"run_state": "succeeded", "complete": snapshot.complete,
                  "partial_reasons": list(snapshot.partial_reasons), "snapshot_sha256": snapshot.snapshot_sha256,
                  "version": int(run["version"]) + 1, "updated_at": occurred_at}
        await self.session.execute(update(metadata.tables["cloud_collection_runs"]).where(metadata.tables["cloud_collection_runs"].c.id == run["id"]).values(**values))
        await self._audit("cloud.run.completed", run_id, {"complete": snapshot.complete, "partial_reasons": list(snapshot.partial_reasons), "residual": 0}, occurred_at)
        return {**run, **values}

    async def request_cancel(self, *, run_id: str, expected_version: int, occurred_at: datetime) -> dict[str, object]:
        run = await self._active_run(run_id)
        if run["run_state"] in {"cancelled", "succeeded", "failed"}:
            return run
        if run["version"] != expected_version:
            raise CloudRepositoryConflict("cloud_run_version_conflict")
        values = {"run_state": "cancel_requested", "version": int(run["version"]) + 1, "updated_at": occurred_at}
        await self.session.execute(update(metadata.tables["cloud_collection_runs"]).where(metadata.tables["cloud_collection_runs"].c.id == run["id"]).values(**values))
        await self._audit("cloud.run.cancel_requested", run_id, {"block_requests_first": True, "revoke_lease_first": True}, occurred_at)
        return {**run, **values}

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context()
        result: dict[str, list[dict[str, object]]] = {}
        for key, name in (("profiles", "cloud_provider_profiles"), ("bindings", "cloud_identity_bindings"), ("plans", "cloud_collection_plans"), ("runs", "cloud_collection_runs"), ("results", "cloud_check_results"), ("cleanups", "cloud_cleanup_receipts")):
            table = metadata.tables[name]
            rows = (await self.session.execute(select(table).where(table.c.tenant_id == self.tenant_id).order_by(table.c.created_at.desc()).limit(100))).mappings().all()
            result[key] = [dict(row) for row in rows]
        capabilities = metadata.tables["execution_capability_manifests"]
        capability_rows = (await self.session.execute(select(capabilities).where(
            capabilities.c.tenant_id == self.tenant_id,
            capabilities.c.capability_id == "cloud-posture",
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
            leases.c.capability == "cloud-posture",
        ).order_by(leases.c.issued_at.desc()).limit(100))).mappings().all()
        compatible = {
            (f"{row['adapter_id']}:{row['adapter_version']}", str(row["image_digest"]))
            for row in capability_rows
        }
        # CRITICAL: option visibility is read-only; mutation handlers remain the authority for compile/run state.
        result["identity_options"] = [row for row in result["bindings"] if row["binding_state"] == "active-local-emulator"]
        result["runner_options"] = [dict(row) for row in runner_rows if any(
            adapter in row["adapter_allowlist"] and image in row["image_allowlist"]
            for adapter, image in compatible
        )]
        result["job_options"] = [dict(row) for row in job_rows if (
            isinstance(row["request"], dict) and row["request"].get("capability") == "cloud-posture"
        )]
        result["reservation_options"] = [dict(row) for row in reservation_rows]
        result["lease_options"] = [dict(row) for row in lease_rows]
        return result

    async def _active_run(self, run_id: str) -> dict[str, object]:
        key = _identifier("run_id", run_id, 100); await self._context(); await self._lock(f"cloud-run:{key}")
        row = await self._find("cloud_collection_runs", {"run_id": key})
        if row is None:
            raise CloudRepositoryConflict("cloud_run_not_found")
        return row

    async def _immutable(self, table_name: str, where: dict[str, object], values: dict[str, object], occurred_at: datetime, prefix: str) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing is not None:
            if any(existing[name] != value for name, value in values.items()):
                raise CloudRepositoryConflict(f"cloud_{prefix}_immutable")
            return existing
        row = {"id": f"cloud-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id, **values,
               "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables[table_name]).values(**row))
        return row

    async def _find(self, table_name: str, where: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]
        conditions = [table.c.tenant_id == self.tenant_id]
        conditions.extend(getattr(table.c, key) == value for key, value in where.items())
        row = (await self.session.execute(select(table).where(*conditions))).mappings().one_or_none()
        return None if row is None else dict(row)

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": f"{self.tenant_id}:{scope}"})

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id, actor_user_id=self.actor_user_id, action=event, subject_type="cloud_assessment", subject_id=subject[:64], correlation_id=self.correlation_id, details=details, version=1, created_at=occurred_at, updated_at=occurred_at))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id, event_type=event, aggregate_id=subject[:64], payload=details, published=False, version=1, created_at=occurred_at, updated_at=occurred_at))


def _profile_material(profile: object) -> dict[str, object]:
    value = asdict(profile)  # type: ignore[arg-type]
    value["provider"] = profile.provider.value  # type: ignore[attr-defined]
    value["expected_identity"]["provider"] = profile.expected_identity.provider.value  # type: ignore[index,union-attr]
    for item in value["operations"]:  # type: ignore[union-attr]
        item["data_class"] = item["data_class"].value
    return value


def _identifier(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not all(char.isalnum() or char in "._:-" for char in value):
        raise CloudRepositoryConflict(f"cloud_{name}_invalid")
    return value


def _sha(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise CloudRepositoryConflict("cloud_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CloudRepositoryConflict("cloud_time_invalid")


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
