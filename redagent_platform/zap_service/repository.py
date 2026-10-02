"""PostgreSQL-authoritative compat_104 profile, plan, run, and cleanup truth."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, or_, select, text, update

from redagent_platform.containment_service.repository import (
    ContainmentRepository,
    ContainmentRepositoryConflict,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.zap_service.compiler import CompiledZapPlan
from redagent_platform.zap_service.contracts import (
    ZAP_ADDON_INVENTORY_SHA256,
    ZAP_IMAGE_DIGEST_BY_PLATFORM,
    ZAP_VERSION,
    CURRENT_R104_TARGET_IMAGE_ID,
    R104_TARGET_SOURCE_SHA256,
    ZapAuthorization,
    ZapTargetBinding,
    canonical_profile_sha256,
    certified_profiles,
)


class ZapRepositoryConflict(RuntimeError):
    """Stable compat_104 persistence or binding conflict."""


class ZapRepository:
    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _identifier("tenant_id", tenant_id, 64)
        self.actor_user_id = _identifier("actor_user_id", actor_user_id, 64)
        self.correlation_id = _identifier("correlation_id", correlation_id, 100)

    async def ensure_certified_profiles(self, *, occurred_at: datetime) -> list[dict[str, object]]:
        _aware(occurred_at)
        await self._context()
        table = metadata.tables["zap_profile_revisions"]
        rows: list[dict[str, object]] = []
        for profile_id, profile in certified_profiles().items():
            await self._lock(f"zap-profile:{profile_id.value}:1")
            expected = profile_values(profile)
            existing = (await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.profile_id == profile_id.value,
                table.c.profile_revision == 1,
            ))).mappings().one_or_none()
            if existing is not None:
                if any(existing[name] != value for name, value in expected.items()):
                    raise ZapRepositoryConflict("zap_profile_revision_immutable")
                rows.append(dict(existing))
                continue
            row = {
                "id": f"zap-profile-{uuid4().hex}", "tenant_id": self.tenant_id,
                **expected, "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
            }
            await self.session.execute(insert(table).values(**row))
            await self._audit("zap.profile.certified", profile_id.value, {
                "profile_revision": 1, "profile_sha256": expected["profile_sha256"],
                "image_digest": expected["image_digest"],
            }, occurred_at)
            rows.append(row)
        return rows

    async def register_target_attestation(
        self, *, attestation_id: str, target: ZapTargetBinding,
        target_source_sha256: str, target_image_id: str,
        address_sha256: str, occurred_at: datetime,
    ) -> dict[str, object]:
        key = _identifier("attestation_id", attestation_id, 100)
        _sha(target_source_sha256)
        _sha(address_sha256)
        _aware(occurred_at)
        if target_source_sha256 != R104_TARGET_SOURCE_SHA256 or target_image_id != CURRENT_R104_TARGET_IMAGE_ID:
            raise ZapRepositoryConflict("zap_target_supply_chain_mismatch")
        await self._context()
        await self._lock(f"zap-target-attestation:{key}")
        table = metadata.tables["zap_target_attestations"]
        identity = {
            "attestation_id": key, "target_id": target.target_id,
            "target_source_sha256": target_source_sha256, "target_image_id": target_image_id,
            "network_id": target.network_id, "container_name": "redagent-r104-target",
            "address_sha256": address_sha256, "endpoint": target.endpoint,
            "allowed_paths": list(target.allowed_paths),
            "attestation_sha256": target.attestation_sha256,
            "non_production": True, "attestation_state": "active",
            "issued_at": target.issued_at, "expires_at": target.expires_at,
        }
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.attestation_id == key,
        ))).mappings().one_or_none()
        if existing is not None:
            if any(existing[name] != value for name, value in identity.items()):
                raise ZapRepositoryConflict("zap_target_attestation_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"zap-target-{uuid4().hex}", "tenant_id": self.tenant_id, **identity,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("zap.target.attested", target.target_id, {
            "attestation_id": key, "attestation_sha256": target.attestation_sha256,
            "target_image_id": target_image_id,
        }, occurred_at)
        return row

    async def store_plan(
        self, *, plan_id: str, compiled: CompiledZapPlan, target: ZapTargetBinding,
        authorization: ZapAuthorization, occurred_at: datetime,
    ) -> dict[str, object]:
        plan_key = _identifier("plan_id", plan_id, 100)
        _aware(occurred_at)
        if authorization.tenant_id != self.tenant_id or compiled.policy_decision_id != authorization.policy_decision_id:
            raise ZapRepositoryConflict("zap_plan_authorization_binding_mismatch")
        await self.ensure_certified_profiles(occurred_at=occurred_at)
        await self._lock(f"zap-plan:{plan_key}")
        attestations = metadata.tables["zap_target_attestations"]
        attestation = (await self.session.execute(select(attestations).where(
            attestations.c.tenant_id == self.tenant_id,
            attestations.c.target_id == target.target_id,
            attestations.c.attestation_sha256 == target.attestation_sha256,
            attestations.c.network_id == target.network_id,
            attestations.c.endpoint == target.endpoint,
            attestations.c.non_production.is_(True),
            attestations.c.attestation_state == "active",
            attestations.c.issued_at <= occurred_at,
            attestations.c.expires_at > occurred_at,
        ))).mappings().one_or_none()
        if attestation is None or tuple(attestation["allowed_paths"]) != target.allowed_paths:
            raise ZapRepositoryConflict("zap_target_attestation_active_required")
        profiles = metadata.tables["zap_profile_revisions"]
        profile = (await self.session.execute(select(profiles).where(
            profiles.c.tenant_id == self.tenant_id,
            profiles.c.profile_id == compiled.profile_id.value,
            profiles.c.profile_revision == 1,
            profiles.c.profile_state == "certified",
        ))).mappings().one()
        table = metadata.tables["zap_compiled_plans"]
        plan_json = json.loads(json.dumps(compiled.plan, sort_keys=True))
        scope_sha256 = _canonical_sha({
            "target_id": target.target_id, "attestation": target.attestation_sha256,
            "endpoint": target.endpoint, "paths": target.allowed_paths,
        })
        identity = {
            "profile_record_id": profile["id"], "plan_id": plan_key,
            "target_id": target.target_id, "target_attestation_sha256": target.attestation_sha256,
            "policy_decision_id": authorization.policy_decision_id,
            "roe_version_id": authorization.roe_version_id, "plan_sha256": compiled.plan_sha256,
            "scope_sha256": scope_sha256, "compiled_plan": plan_json,
            "expires_at": authorization.expires_at,
        }
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.plan_id == plan_key,
        ))).mappings().one_or_none()
        if existing is not None:
            if any(existing[name] != value for name, value in identity.items()):
                raise ZapRepositoryConflict("zap_plan_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"zap-plan-{uuid4().hex}", "tenant_id": self.tenant_id, **identity,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("zap.plan.compiled", plan_key, {
            "profile_id": compiled.profile_id.value, "plan_sha256": compiled.plan_sha256,
            "scope_sha256": scope_sha256,
        }, occurred_at)
        return row

    async def create_run(
        self, *, run_id: str, plan_id: str, job_id: str, runner_id: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run_key = _identifier("run_id", run_id, 100)
        plan_key = _identifier("plan_id", plan_id, 100)
        job_key = _identifier("job_id", job_id, 100)
        runner_key = _identifier("runner_id", runner_id, 100)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"zap-run:{run_key}")
        plans = metadata.tables["zap_compiled_plans"]
        plan = (await self.session.execute(select(plans).where(
            plans.c.tenant_id == self.tenant_id, plans.c.plan_id == plan_key,
            plans.c.expires_at > occurred_at,
        ))).mappings().one_or_none()
        if plan is None:
            raise ZapRepositoryConflict("zap_plan_active_required")
        jobs = metadata.tables["jobs"]
        job = (await self.session.execute(select(jobs).where(
            jobs.c.tenant_id == self.tenant_id, jobs.c.id == job_key,
        ))).mappings().one_or_none()
        if job is None or not isinstance(job["request"], dict) or job["request"].get("capability") != "zap-controlled-runtime":
            raise ZapRepositoryConflict("zap_job_capability_required")
        registrations = metadata.tables["runner_registrations"]
        runner = (await self.session.execute(select(registrations).where(
            registrations.c.tenant_id == self.tenant_id,
            registrations.c.runner_id == runner_key,
            registrations.c.registration_state == "active",
            registrations.c.expires_at > occurred_at,
        ).order_by(registrations.c.generation.desc()).limit(1))).mappings().one_or_none()
        if runner is None or "zap-service:2.17.0-r104.3" not in runner["adapter_allowlist"]:
            raise ZapRepositoryConflict("zap_runner_registration_required")
        table = metadata.tables["zap_runs"]
        identity = {
            "plan_record_id": plan["id"], "run_id": run_key,
            "job_id": job_key, "runner_id": runner_key,
        }
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.run_id == run_key,
        ))).mappings().one_or_none()
        if existing is not None:
            if any(existing[name] != value for name, value in identity.items()):
                raise ZapRepositoryConflict("zap_run_replay_mismatch")
            return dict(existing)
        containment_active = await self._containment_active(job_key)
        if containment_active:
            quota_allowed, quota_reason, denied_state = False, "zap_containment_active", "containment_denied"
        else:
            quota_allowed, quota_reason = await self._reserve_run_quotas(
                run_id=run_key, job_id=job_key, profile_record_id=str(plan["profile_record_id"]),
                occurred_at=occurred_at,
            )
            denied_state = "quota_denied"
        row = {
            "id": f"zap-run-{uuid4().hex}", "tenant_id": self.tenant_id, **identity,
            "run_state": "dispatch_pending" if quota_allowed else denied_state,
            "current_step": 0, "progress_percent": 0,
            "passive_queue_size": 0, "reason_code": "zap_run_accepted" if quota_allowed else quota_reason,
            "started_at": None, "completed_at": None if quota_allowed else occurred_at, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("zap.run.accepted", run_key, {
            "plan_id": plan_key, "job_id": job_key, "runner_id": runner_key,
            "quota_allowed": quota_allowed, "reason_code": row["reason_code"],
        }, occurred_at)
        return row

    async def _containment_active(self, job_id: str) -> bool:
        controls = metadata.tables["containment_controls"]
        row = (await self.session.execute(select(controls.c.id).where(
            controls.c.tenant_id == self.tenant_id,
            controls.c.control_state == "active",
            or_(
                controls.c.scope_kind == "global",
                (controls.c.scope_kind == "tenant") & (controls.c.scope_id == self.tenant_id),
                (controls.c.scope_kind == "job") & (controls.c.scope_id == job_id),
                (controls.c.scope_kind == "capability") & (controls.c.scope_id == "zap-controlled-runtime"),
            ),
        ).limit(1))).one_or_none()
        return row is not None

    async def _reserve_run_quotas(
        self, *, run_id: str, job_id: str, profile_record_id: str, occurred_at: datetime,
    ) -> tuple[bool, str]:
        profiles = metadata.tables["zap_profile_revisions"]
        profile = (await self.session.execute(select(profiles).where(
            profiles.c.tenant_id == self.tenant_id, profiles.c.id == profile_record_id,
        ))).mappings().one()
        requested = {
            "time_seconds": int(profile["timeout_seconds"]),
            "operations": int(profile["request_limit"]),
            "concurrency": int(profile["concurrency_limit"]),
            "data_bytes": int(profile["response_bytes_limit"]),
        }
        policies = metadata.tables["quota_policies"]
        rows = (await self.session.execute(select(policies).where(
            policies.c.tenant_id == self.tenant_id,
            policies.c.scope_kind == "job", policies.c.scope_id == job_id,
            policies.c.policy_state == "active", policies.c.dimension.in_(tuple(requested)),
            policies.c.active_from <= occurred_at, policies.c.active_until > occurred_at,
        ).order_by(policies.c.dimension, policies.c.policy_revision.desc()))).mappings().all()
        selected: dict[str, object] = {}
        for row in rows:
            selected.setdefault(str(row["dimension"]), row)
        if set(selected) != set(requested):
            raise ZapRepositoryConflict("zap_quota_policy_set_required")
        repository = ContainmentRepository(
            self.session, tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, correlation_id=self.correlation_id,
        )
        reservations: list[tuple[str, int]] = []
        try:
            for dimension, amount in requested.items():
                operation_id = f"r104:{run_id}:{dimension}"
                result = await repository.reserve_quota(
                    policy_record_id=str(selected[dimension]["id"]),
                    operation_id=operation_id, requested=amount, occurred_at=occurred_at,
                )
                if not result.decision.allowed:
                    for reservation_id, reserved_amount in reservations:
                        await repository.adjust_quota(
                            reservation_id=reservation_id,
                            operation_id=f"{reservation_id}:rollback",
                            operation_kind="release", amount=reserved_amount,
                            occurred_at=occurred_at,
                        )
                    return False, result.decision.reason_code
                reservations.append((operation_id, amount))
        except ContainmentRepositoryConflict as exc:
            raise ZapRepositoryConflict(str(exc)) from exc
        return True, "quota_reserved"

    async def request_cancel(
        self, *, run_id: str, expected_version: int, reason_code: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run_key = _identifier("run_id", run_id, 100)
        reason = _identifier("reason_code", reason_code, 100)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"zap-run:{run_key}")
        table = metadata.tables["zap_runs"]
        row = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.run_id == run_key,
        ).with_for_update())).mappings().one_or_none()
        if row is None:
            raise ZapRepositoryConflict("zap_run_not_found")
        if row["run_state"] in {
            "succeeded", "failed", "cancelled", "cleaned", "quota_denied", "containment_denied",
        }:
            return dict(row)
        if expected_version != row["version"]:
            raise ZapRepositoryConflict("zap_run_version_conflict")
        values = {
            "run_state": "cancel_requested", "reason_code": reason,
            "version": row["version"] + 1, "updated_at": occurred_at,
        }
        await self.session.execute(update(table).where(table.c.id == row["id"]).values(**values))
        await self._audit("zap.run.cancel_requested", run_key, {
            "reason_code": reason, "version": values["version"],
        }, occurred_at)
        return {**dict(row), **values}

    async def record_cancellation(
        self, *, run_id: str, receipt_id: str, native_stop_attempted: bool,
        native_stop_acknowledged: bool, lease_revoked: bool, evidence_finalized: bool,
        forced_termination: bool, occurred_at: datetime,
    ) -> dict[str, object]:
        run_key = _identifier("run_id", run_id, 100)
        receipt_key = _identifier("receipt_id", receipt_id, 100)
        _aware(occurred_at)
        if native_stop_attempted is not True or lease_revoked is not True or evidence_finalized is not True:
            raise ZapRepositoryConflict("zap_cancellation_phase_incomplete")
        if not native_stop_acknowledged and not forced_termination:
            raise ZapRepositoryConflict("zap_cancellation_containment_required")
        await self._context()
        await self._lock(f"zap-run:{run_key}")
        runs = metadata.tables["zap_runs"]
        run = (await self.session.execute(select(runs).where(
            runs.c.tenant_id == self.tenant_id, runs.c.run_id == run_key,
        ).with_for_update())).mappings().one_or_none()
        if run is None:
            raise ZapRepositoryConflict("zap_run_not_found")
        table = metadata.tables["zap_cancellation_receipts"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.receipt_id == receipt_key,
        ))).mappings().one_or_none()
        identity = {
            "run_record_id": run["id"], "receipt_id": receipt_key,
            "native_stop_attempted": native_stop_attempted,
            "native_stop_acknowledged": native_stop_acknowledged,
            "lease_revoked": lease_revoked, "evidence_finalized": evidence_finalized,
            "forced_termination": forced_termination,
            "reason_code": "zap_native_stop_acknowledged" if native_stop_acknowledged else "zap_forced_containment",
            "completed_at": occurred_at,
        }
        if existing is not None:
            if any(existing[name] != value for name, value in identity.items()):
                raise ZapRepositoryConflict("zap_cancellation_replay_mismatch")
            return dict(existing)
        await self._release_run_quotas(run_key, occurred_at)
        row = {
            "id": f"zap-cancel-{uuid4().hex}", "tenant_id": self.tenant_id, **identity,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self.session.execute(update(runs).where(runs.c.id == run["id"]).values(
            run_state="cancelled", reason_code=identity["reason_code"],
            completed_at=occurred_at, version=int(run["version"]) + 1, updated_at=occurred_at,
        ))
        await self._audit("zap.run.cancelled", run_key, {
            "native_stop_acknowledged": native_stop_acknowledged,
            "forced_termination": forced_termination, "quotas_released": True,
        }, occurred_at)
        return row

    async def record_cleanup(
        self, *, run_id: str, receipt_id: str, container_count: int, network_count: int,
        home_count: int, key_count: int, credential_count: int,
        residual_resource_count: int, inventory_sha256: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run_key = _identifier("run_id", run_id, 100)
        receipt_key = _identifier("receipt_id", receipt_id, 100)
        _sha(inventory_sha256)
        _aware(occurred_at)
        counts = (container_count, network_count, home_count, key_count, credential_count, residual_resource_count)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise ZapRepositoryConflict("zap_cleanup_counts_invalid")
        await self._context()
        await self._lock(f"zap-run:{run_key}")
        runs = metadata.tables["zap_runs"]
        run = (await self.session.execute(select(runs).where(
            runs.c.tenant_id == self.tenant_id, runs.c.run_id == run_key,
        ).with_for_update())).mappings().one_or_none()
        if run is None:
            raise ZapRepositoryConflict("zap_run_not_found")
        complete = residual_resource_count == 0 and key_count == 0 and credential_count == 0
        table = metadata.tables["zap_cleanup_receipts"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.receipt_id == receipt_key,
        ))).mappings().one_or_none()
        identity = {
            "run_record_id": run["id"], "receipt_id": receipt_key,
            "container_count": container_count, "network_count": network_count,
            "home_count": home_count, "key_count": key_count,
            "credential_count": credential_count,
            "residual_resource_count": residual_resource_count,
            "cleanup_complete": complete, "inventory_sha256": inventory_sha256,
            "completed_at": occurred_at,
        }
        if existing is not None:
            if any(existing[name] != value for name, value in identity.items()):
                raise ZapRepositoryConflict("zap_cleanup_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"zap-cleanup-{uuid4().hex}", "tenant_id": self.tenant_id, **identity,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self.session.execute(update(runs).where(runs.c.id == run["id"]).values(
            run_state="cleaned" if complete else "cleanup_failed",
            reason_code="zap_cleanup_complete" if complete else "zap_cleanup_incomplete",
            completed_at=occurred_at, version=int(run["version"]) + 1, updated_at=occurred_at,
        ))
        await self._audit("zap.run.cleaned", run_key, {
            "cleanup_complete": complete, "residual_resource_count": residual_resource_count,
        }, occurred_at)
        return row

    async def _release_run_quotas(self, run_id: str, occurred_at: datetime) -> None:
        reservations = metadata.tables["quota_reservations"]
        rows = (await self.session.execute(select(reservations).where(
            reservations.c.tenant_id == self.tenant_id,
            reservations.c.reservation_id.like(f"r104:{run_id}:%"),
            reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
        ))).mappings().all()
        repository = ContainmentRepository(
            self.session, tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, correlation_id=self.correlation_id,
        )
        for row in rows:
            available = int(row["reserved_amount"]) - int(row["consumed_amount"]) - int(row["released_amount"])
            if available > 0:
                await repository.adjust_quota(
                    reservation_id=str(row["reservation_id"]),
                    operation_id=f"{row['reservation_id']}:cancel",
                    operation_kind="release", amount=available, occurred_at=occurred_at,
                )

    async def dashboard(self) -> dict[str, object]:
        await self._context()
        profiles = (await self.session.execute(select(metadata.tables["zap_profile_revisions"]).where(
            metadata.tables["zap_profile_revisions"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["zap_profile_revisions"].c.profile_id))).mappings().all()
        plans = (await self.session.execute(select(metadata.tables["zap_compiled_plans"]).where(
            metadata.tables["zap_compiled_plans"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["zap_compiled_plans"].c.created_at.desc()).limit(100))).mappings().all()
        runs = (await self.session.execute(select(metadata.tables["zap_runs"]).where(
            metadata.tables["zap_runs"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["zap_runs"].c.created_at.desc()).limit(100))).mappings().all()
        cleanups = (await self.session.execute(select(metadata.tables["zap_cleanup_receipts"]).where(
            metadata.tables["zap_cleanup_receipts"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["zap_cleanup_receipts"].c.created_at.desc()).limit(20))).mappings().all()
        targets = (await self.session.execute(select(metadata.tables["zap_target_attestations"]).where(
            metadata.tables["zap_target_attestations"].c.tenant_id == self.tenant_id,
            metadata.tables["zap_target_attestations"].c.target_id == "r104-owned-web-fixture",
        ).order_by(metadata.tables["zap_target_attestations"].c.issued_at.desc()).limit(100))).mappings().all()
        registrations = (await self.session.execute(select(metadata.tables["runner_registrations"]).where(
            metadata.tables["runner_registrations"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["runner_registrations"].c.last_seen_at.desc()).limit(100))).mappings().all()
        # CRITICAL: project only runners already bound to the pinned ZAP adapter; UI visibility grants no authority.
        compatible_runners = [
            dict(row) for row in registrations
            if "zap-service:2.17.0-r104.3" in row["adapter_allowlist"]
        ]
        return {"profiles": [dict(row) for row in profiles], "plans": [dict(row) for row in plans],
                "runs": [dict(row) for row in runs], "cleanups": [dict(row) for row in cleanups],
                "target_options": [dict(row) for row in targets], "runner_options": compatible_runners}

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {
            "scope": f"{self.tenant_id}:{scope}",
        })

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, action=event, subject_type="zap",
            subject_id=subject[:64], correlation_id=self.correlation_id, details=details,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id,
            event_type=event, aggregate_id=subject[:64], payload=details, published=False,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))


def profile_values(profile) -> dict[str, object]:
    return {
        "profile_id": profile.profile_id.value, "profile_revision": 1,
        "image_version": ZAP_VERSION, "image_digest": ZAP_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
        "addon_inventory_sha256": ZAP_ADDON_INVENTORY_SHA256,
        "profile_sha256": canonical_profile_sha256(profile), "risk_class": profile.approval_class.value,
        "passive_rule_ids": list(profile.passive_rule_ids), "active_rule_ids": list(profile.active_rule_ids),
        "request_limit": profile.request_limit,
        "request_rate_per_second": profile.request_rate_per_second,
        "concurrency_limit": profile.concurrency, "timeout_seconds": profile.timeout_seconds,
        "response_bytes_limit": profile.response_bytes_limit, "profile_state": "certified",
    }


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _identifier(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not all(
        char.isalnum() or char in "._:-" for char in value
    ):
        raise ZapRepositoryConflict(f"zap_{name}_invalid")
    return value


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ZapRepositoryConflict("zap_time_invalid")


def _sha(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ZapRepositoryConflict("zap_sha256_invalid")
