"""PostgreSQL-authoritative compat_105 artifact, bundle, target, plan, run, and evidence truth."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, or_, select, text, update

from redagent_platform.containment_service.repository import ContainmentRepository, ContainmentRepositoryConflict
from redagent_platform.nuclei_service.compiler import CompiledNucleiPlan
from redagent_platform.nuclei_service.contracts import (
    CURRENT_NUCLEI_CRITICAL_REPORT_SHA256,
    CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
    CURRENT_NUCLEI_SBOM_SHA256,
    CURRENT_NUCLEI_VERSION,
    CURRENT_R105_TARGET_IMAGE_ID,
    R105_TARGET_SOURCE_SHA256,
    NucleiAuthorization,
    NucleiBundleManifest,
    NucleiTargetBinding,
    canonical_profile_sha256,
    certified_profiles,
)
from redagent_platform.nuclei_service.normalization import NormalizedNucleiResult
from redagent_platform.persistence.models import metadata


class NucleiRepositoryConflict(RuntimeError):
    """Stable compat_105 persistence or binding denial."""


class NucleiRepository:
    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _identifier("tenant_id", tenant_id, 64)
        self.actor_user_id = _identifier("actor_user_id", actor_user_id, 64)
        self.correlation_id = _identifier("correlation_id", correlation_id, 100)

    async def ensure_certified_foundation(
        self, *, bundle: NucleiBundleManifest, artifact_signature_sha256: str,
        artifact_provenance_sha256: str, bundle_signature_sha256: str, occurred_at: datetime,
    ) -> dict[str, object]:
        for value in (artifact_signature_sha256, artifact_provenance_sha256, bundle_signature_sha256):
            _sha(value)
        _aware(occurred_at)
        await self._context()
        await self._lock("nuclei-foundation:v1")
        engine = await self._immutable(
            "nuclei_engine_artifacts", {"engine_id": "nuclei-3.11.1-r105.2"},
            {
                "engine_id": "nuclei-3.11.1-r105.2", "engine_version": CURRENT_NUCLEI_VERSION,
                "image_digest": CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
                "signature_sha256": artifact_signature_sha256,
                "provenance_sha256": artifact_provenance_sha256,
                "sbom_sha256": CURRENT_NUCLEI_SBOM_SHA256,
                "vulnerability_review": "accepted_no_critical",
                "artifact_state": "certified-local-lab",
            }, occurred_at, "engine",
        )
        bundle_row = await self._immutable(
            "nuclei_bundle_revisions", {"bundle_id": bundle.bundle_id, "bundle_revision": bundle.revision},
            {
                "bundle_id": bundle.bundle_id, "bundle_revision": bundle.revision,
                "bundle_sha256": bundle.bundle_sha256, "signature_sha256": bundle_signature_sha256,
                "engine_version": CURRENT_NUCLEI_VERSION, "payload_file_count": 0,
                "bundle_state": "promoted-local-lab", "expires_at": bundle.expires_at,
            }, occurred_at, "bundle",
        )
        await self._immutable(
            "nuclei_bundle_files", {"bundle_record_id": bundle_row["id"], "relative_path": bundle.template_relative_path},
            {"bundle_record_id": bundle_row["id"], "relative_path": bundle.template_relative_path,
             "file_sha256": bundle.template_sha256, "size_bytes": 700, "file_kind": "nuclei-template"},
            occurred_at, "bundle-file",
        )
        await self._immutable(
            "nuclei_template_revisions", {"bundle_record_id": bundle_row["id"], "template_id": bundle.template_id},
            {"bundle_record_id": bundle_row["id"], "template_id": bundle.template_id,
             "template_sha256": bundle.template_sha256, "protocol": bundle.protocol,
             "severity": bundle.severity, "methods": [bundle.method], "paths": list(bundle.paths),
             "tags": list(bundle.tags), "matcher_names": list(bundle.expected_matcher_names),
             "template_state": "certified"}, occurred_at, "template",
        )
        review = await self._immutable(
            "nuclei_bundle_reviews", {"review_id": "r105-independent-review-v2"},
            {"bundle_record_id": bundle_row["id"], "review_id": "r105-independent-review-v2",
             "author_user_id": "redagent-r105-author", "reviewer_user_id": bundle.reviewer_user_id,
             "review_state": "approved-local-lab", "review_sha256": bundle.bundle_sha256},
            occurred_at, "review",
        )
        promotion = await self._immutable(
            "nuclei_bundle_promotions", {"promotion_id": "r105-bundle-promotion-v2"},
            {"bundle_record_id": bundle_row["id"], "promotion_id": "r105-bundle-promotion-v2",
             "promotion_sha256": bundle.bundle_sha256, "signature_sha256": bundle_signature_sha256,
             "promotion_state": "active-local-lab", "promoted_at": bundle.promoted_at},
            occurred_at, "promotion",
        )
        profile = next(iter(certified_profiles().values()))
        profile_payload = asdict(profile)
        profile_payload["profile_id"] = profile.profile_id.value
        profile_sha = _canonical_sha(profile_payload)
        profile_row = await self._immutable(
            "nuclei_profile_revisions", {"profile_id": profile.profile_id.value, "profile_revision": 1},
            {"profile_id": profile.profile_id.value, "profile_revision": 1,
             "engine_record_id": engine["id"], "bundle_record_id": bundle_row["id"],
             "profile_sha256": profile_sha, "request_limit": profile.request_limit,
             "request_rate_per_second": profile.request_rate_per_second,
             "concurrency_limit": profile.concurrency, "timeout_seconds": profile.timeout_seconds,
             "response_bytes_limit": profile.response_bytes_limit, "result_limit": profile.result_limit,
             "profile_state": "certified-local-lab"}, occurred_at, "profile",
        )
        await self._audit("nuclei.foundation.certified", bundle.bundle_id, {
            "engine_id": engine["engine_id"], "bundle_sha256": bundle.bundle_sha256,
            "profile_sha256": profile_sha, "critical_report_sha256": CURRENT_NUCLEI_CRITICAL_REPORT_SHA256,
            "production_qualified": False,
        }, occurred_at)
        return {"engine": engine, "bundle": bundle_row, "review": review,
                "promotion": promotion, "profile": profile_row}

    async def register_target_attestation(
        self, *, attestation_id: str, target: NucleiTargetBinding,
        target_source_sha256: str, target_image_id: str,
        address_sha256: str, occurred_at: datetime,
    ) -> dict[str, object]:
        key = _identifier("attestation_id", attestation_id, 100)
        _sha(target_source_sha256); _sha(address_sha256); _aware(occurred_at)
        if target_source_sha256 != R105_TARGET_SOURCE_SHA256 or target_image_id != CURRENT_R105_TARGET_IMAGE_ID:
            raise NucleiRepositoryConflict("nuclei_target_supply_chain_mismatch")
        await self._context(); await self._lock(f"nuclei-target:{key}")
        row = await self._immutable(
            "nuclei_target_attestations", {"attestation_id": key},
            {"attestation_id": key, "target_id": target.target_id,
             "target_source_sha256": target_source_sha256, "target_image_id": target_image_id,
             "network_id": target.network_id, "container_name": "redagent-r105-target",
             "address_sha256": address_sha256, "endpoint": target.endpoint,
             "allowed_paths": list(target.allowed_paths), "attestation_sha256": target.attestation_sha256,
             "non_production": True, "attestation_state": "active",
             "issued_at": target.issued_at, "expires_at": target.expires_at},
            occurred_at, "target",
        )
        await self._audit("nuclei.target.attested", target.target_id, {
            "attestation_id": key, "attestation_sha256": target.attestation_sha256,
        }, occurred_at)
        return row

    async def store_plan(
        self, *, plan_id: str, compiled: CompiledNucleiPlan, target: NucleiTargetBinding,
        authorization: NucleiAuthorization, occurred_at: datetime,
    ) -> dict[str, object]:
        key = _identifier("plan_id", plan_id, 100); _aware(occurred_at)
        await self._context(); await self._lock(f"nuclei-plan:{key}")
        profiles = metadata.tables["nuclei_profile_revisions"]
        profile = (await self.session.execute(select(profiles).where(
            profiles.c.tenant_id == self.tenant_id,
            profiles.c.profile_id == compiled.profile_id.value,
            profiles.c.profile_state == "certified-local-lab",
        ))).mappings().one_or_none()
        targets = metadata.tables["nuclei_target_attestations"]
        attestation = (await self.session.execute(select(targets).where(
            targets.c.tenant_id == self.tenant_id, targets.c.target_id == target.target_id,
            targets.c.attestation_sha256 == target.attestation_sha256,
            targets.c.attestation_state == "active", targets.c.non_production.is_(True),
            targets.c.issued_at <= occurred_at, targets.c.expires_at > occurred_at,
        ))).mappings().one_or_none()
        if profile is None:
            raise NucleiRepositoryConflict("nuclei_certified_profile_required")
        if attestation is None:
            raise NucleiRepositoryConflict("nuclei_target_attestation_required")
        scope_sha = _canonical_sha({"target_id": target.target_id,
                                    "attestation_sha256": target.attestation_sha256,
                                    "allowed_paths": target.allowed_paths})
        values = {
            "profile_record_id": profile["id"], "plan_id": key, "target_id": target.target_id,
            "target_attestation_sha256": target.attestation_sha256,
            "policy_decision_id": authorization.policy_decision_id,
            "roe_version_id": authorization.roe_version_id,
            "plan_sha256": compiled.plan_sha256, "scope_sha256": scope_sha,
            "compiled_plan": {"schema": "redagent.r105-compiled-plan/v1", "argv": list(compiled.argv),
                              "bundle_id": compiled.bundle_id,
                              "profile_id": compiled.profile_id.value,
                              "policy_revision": authorization.policy_revision},
            "expires_at": min(target.expires_at, authorization.expires_at),
        }
        row = await self._immutable("nuclei_compiled_plans", {"plan_id": key}, values, occurred_at, "plan")
        await self._audit("nuclei.plan.compiled", key, {"plan_sha256": compiled.plan_sha256,
                                                        "scope_sha256": scope_sha}, occurred_at)
        return row

    async def create_run(
        self, *, run_id: str, plan_id: str, job_id: str, runner_id: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run_key = _identifier("run_id", run_id, 100); plan_key = _identifier("plan_id", plan_id, 100)
        job_key = _identifier("job_id", job_id, 100); runner_key = _identifier("runner_id", runner_id, 100)
        _aware(occurred_at); await self._context(); await self._lock(f"nuclei-run:{run_key}")
        plans = metadata.tables["nuclei_compiled_plans"]
        plan = (await self.session.execute(select(plans).where(
            plans.c.tenant_id == self.tenant_id, plans.c.plan_id == plan_key,
            plans.c.expires_at > occurred_at,
        ))).mappings().one_or_none()
        if plan is None:
            raise NucleiRepositoryConflict("nuclei_plan_active_required")
        compiled_state = plan["compiled_plan"]
        if not isinstance(compiled_state, dict) or compiled_state.get("schema") != "redagent.r105-compiled-plan/v1":
            raise NucleiRepositoryConflict("nuclei_plan_state_invalid")
        targets = metadata.tables["nuclei_target_attestations"]
        target = (await self.session.execute(select(targets.c.id).where(
            targets.c.tenant_id == self.tenant_id, targets.c.target_id == plan["target_id"],
            targets.c.attestation_sha256 == plan["target_attestation_sha256"],
            targets.c.network_id == "redagent-r105-gateway-target",
            targets.c.non_production.is_(True), targets.c.attestation_state == "active",
            targets.c.issued_at <= occurred_at, targets.c.expires_at > occurred_at,
        ))).one_or_none()
        profiles = metadata.tables["nuclei_profile_revisions"]
        profile = (await self.session.execute(select(profiles).where(
            profiles.c.tenant_id == self.tenant_id, profiles.c.id == plan["profile_record_id"],
            profiles.c.profile_state == "certified-local-lab",
        ))).mappings().one_or_none()
        bundles = metadata.tables["nuclei_bundle_revisions"]
        bundle = None if profile is None else (await self.session.execute(select(bundles).where(
            bundles.c.tenant_id == self.tenant_id, bundles.c.id == profile["bundle_record_id"],
            bundles.c.bundle_id == compiled_state.get("bundle_id"),
            bundles.c.bundle_state == "promoted-local-lab", bundles.c.expires_at > occurred_at,
        ))).mappings().one_or_none()
        promotions = metadata.tables["nuclei_bundle_promotions"]
        promotion = None if bundle is None else (await self.session.execute(select(promotions.c.id).where(
            promotions.c.tenant_id == self.tenant_id,
            promotions.c.bundle_record_id == bundle["id"],
            promotions.c.promotion_state == "active-local-lab",
        ))).one_or_none()
        decisions = metadata.tables["policy_decisions"]
        decision = (await self.session.execute(select(decisions.c.id).where(
            decisions.c.tenant_id == self.tenant_id,
            decisions.c.opa_decision_id == plan["policy_decision_id"],
            decisions.c.bundle_revision == compiled_state.get("policy_revision"),
            decisions.c.action == "nuclei.plan.compile",
            decisions.c.resource_type == "nuclei_profile",
            decisions.c.resource_id == compiled_state.get("profile_id"),
            decisions.c.allowed.is_(True), decisions.c.valid_until > occurred_at,
        ))).one_or_none()
        roes = metadata.tables["roe_versions"]
        roe = (await self.session.execute(select(roes.c.id).where(
            roes.c.tenant_id == self.tenant_id, roes.c.id == plan["roe_version_id"],
            roes.c.status == "approved",
        ))).one_or_none()
        if target is None:
            raise NucleiRepositoryConflict("nuclei_target_revalidation_required")
        if profile is None or bundle is None or promotion is None:
            raise NucleiRepositoryConflict("nuclei_bundle_revalidation_required")
        if decision is None or roe is None:
            raise NucleiRepositoryConflict("nuclei_policy_revalidation_required")
        job = (await self.session.execute(select(metadata.tables["jobs"]).where(
            metadata.tables["jobs"].c.tenant_id == self.tenant_id,
            metadata.tables["jobs"].c.id == job_key,
        ))).mappings().one_or_none()
        if job is None or not isinstance(job["request"], dict) or job["request"].get("capability") != "nuclei-trusted-runtime":
            raise NucleiRepositoryConflict("nuclei_job_capability_required")
        registrations = metadata.tables["runner_registrations"]
        runner = (await self.session.execute(select(registrations).where(
            registrations.c.tenant_id == self.tenant_id, registrations.c.runner_id == runner_key,
            registrations.c.registration_state == "active", registrations.c.expires_at > occurred_at,
        ).order_by(registrations.c.generation.desc()).limit(1))).mappings().one_or_none()
        if (
            runner is None
            or runner["required_policy_revision"] != compiled_state.get("policy_revision")
            or "nuclei-service:3.11.1-r105.2" not in runner["adapter_allowlist"]
            or CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"] not in runner["image_allowlist"]
        ):
            raise NucleiRepositoryConflict("nuclei_runner_registration_required")
        identity = {"plan_record_id": plan["id"], "run_id": run_key,
                    "job_id": job_key, "runner_id": runner_key}
        existing = await self._find("nuclei_runs", {"run_id": run_key})
        if existing is not None:
            if any(existing[name] != value for name, value in identity.items()):
                raise NucleiRepositoryConflict("nuclei_run_replay_mismatch")
            return existing
        containment = await self._containment_active(job_key)
        if containment:
            allowed, reason, state = False, "nuclei_containment_active", "containment_denied"
        else:
            allowed, reason = await self._reserve_run_quotas(run_key, job_key, str(plan["profile_record_id"]), occurred_at)
            state = "quota_denied"
        row = {"id": f"nuclei-run-{uuid4().hex}", "tenant_id": self.tenant_id, **identity,
               "run_state": "dispatch_pending" if allowed else state, "progress_percent": 0,
               "request_count": 0, "response_bytes": 0, "result_count": 0,
               "reason_code": "nuclei_run_accepted" if allowed else reason,
               "started_at": None, "completed_at": None if allowed else occurred_at,
               "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables["nuclei_runs"]).values(**row))
        await self._audit("nuclei.run.accepted", run_key, {"plan_id": plan_key,
                                                           "quota_allowed": allowed,
                                                           "reason_code": row["reason_code"]}, occurred_at)
        return row

    async def request_cancel(self, *, run_id: str, expected_version: int,
                             reason_code: str, occurred_at: datetime) -> dict[str, object]:
        key = _identifier("run_id", run_id, 100); reason = _identifier("reason_code", reason_code, 100)
        _aware(occurred_at); await self._context(); await self._lock(f"nuclei-run:{key}")
        table = metadata.tables["nuclei_runs"]
        row = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.run_id == key,
        ).with_for_update())).mappings().one_or_none()
        if row is None:
            raise NucleiRepositoryConflict("nuclei_run_not_found")
        if row["run_state"] in {"cancelled", "cleaned", "succeeded", "failed", "quota_denied", "containment_denied"}:
            return dict(row)
        if row["version"] != expected_version:
            raise NucleiRepositoryConflict("nuclei_run_version_conflict")
        values = {"run_state": "cancel_requested", "reason_code": reason,
                  "version": int(row["version"]) + 1, "updated_at": occurred_at}
        await self.session.execute(update(table).where(table.c.id == row["id"]).values(**values))
        await self._audit("nuclei.run.cancel_requested", key, {"reason_code": reason}, occurred_at)
        return {**dict(row), **values}

    async def record_result(self, *, run_id: str, result_id: str, result: NormalizedNucleiResult,
                            evidence_instance_id: str, occurred_at: datetime) -> dict[str, object]:
        run = await self._active_run(run_id); key = _identifier("result_id", result_id, 100)
        if run["run_state"] not in {"dispatch_pending", "running", "collecting"}:
            raise NucleiRepositoryConflict("nuclei_result_run_state_invalid")
        evidence = _identifier("evidence_instance_id", evidence_instance_id, 100); _aware(occurred_at)
        existing = await self._find("nuclei_normalized_results", {
            "run_record_id": run["id"], "fingerprint": result.fingerprint,
        })
        row = await self._immutable("nuclei_normalized_results", {"run_record_id": run["id"], "fingerprint": result.fingerprint},
            {"run_record_id": run["id"], "result_id": key, "template_id": result.template_id,
             "matcher_name": result.matcher_name, "severity": result.severity,
             "affected_resource": result.affected_resource, "fingerprint": result.fingerprint,
             "source_sha256": result.source_sha256, "evidence_instance_id": evidence}, occurred_at, "result")
        if existing is not None:
            return row
        issues = metadata.tables["issue_definitions"]
        issue = (await self.session.execute(select(issues).where(
            issues.c.tenant_id == self.tenant_id, issues.c.fingerprint == result.fingerprint,
        ))).mappings().one_or_none()
        if issue is None:
            issue = {
                "id": f"issue-nuclei-{uuid4().hex}", "tenant_id": self.tenant_id,
                "fingerprint": result.fingerprint, "title": result.title, "tool": "nuclei",
                "rule_id": f"{result.template_id}:{result.matcher_name}",
                "tool_version": CURRENT_NUCLEI_VERSION, "database_version": "r105-http-header-bundle:2",
                "severity": result.severity, "confidence": "firm", "version": 1,
                "created_at": occurred_at, "updated_at": occurred_at,
            }
            await self.session.execute(insert(issues).values(**issue))
        instances = metadata.tables["finding_instances"]
        finding = (await self.session.execute(select(instances.c.id).where(
            instances.c.tenant_id == self.tenant_id,
            instances.c.issue_definition_id == issue["id"],
            instances.c.affected_resource == result.affected_resource,
            instances.c.location == result.affected_resource,
        ))).one_or_none()
        if finding is None:
            await self.session.execute(insert(instances).values(
                id=f"finding-nuclei-{uuid4().hex}", tenant_id=self.tenant_id,
                issue_definition_id=issue["id"], affected_resource=result.affected_resource,
                location=result.affected_resource, evidence_reference=evidence,
                redaction_state="redacted", version=1,
                created_at=occurred_at, updated_at=occurred_at,
            ))
        await self.session.execute(update(metadata.tables["nuclei_runs"]).where(
            metadata.tables["nuclei_runs"].c.id == run["id"]).values(
                result_count=int(run["result_count"]) + 1, updated_at=occurred_at,
                version=int(run["version"]) + 1))
        return row

    async def record_cancellation(
        self, *, run_id: str, receipt_id: str, native_stop_attempted: bool,
        native_stop_acknowledged: bool, lease_revoked: bool, evidence_finalized: bool,
        forced_termination: bool, occurred_at: datetime,
    ) -> dict[str, object]:
        if native_stop_attempted is not True or lease_revoked is not True or evidence_finalized is not True:
            raise NucleiRepositoryConflict("nuclei_cancellation_phase_incomplete")
        if not native_stop_acknowledged and not forced_termination:
            raise NucleiRepositoryConflict("nuclei_cancellation_containment_required")
        run = await self._active_run(run_id); key = _identifier("receipt_id", receipt_id, 100)
        if run["run_state"] != "cancel_requested":
            raise NucleiRepositoryConflict("nuclei_cancellation_state_invalid")
        row = await self._immutable("nuclei_cancellation_receipts", {"receipt_id": key},
            {"run_record_id": run["id"], "receipt_id": key,
             "native_stop_attempted": native_stop_attempted,
             "native_stop_acknowledged": native_stop_acknowledged,
             "lease_revoked": lease_revoked, "evidence_finalized": evidence_finalized,
             "forced_termination": forced_termination, "completed_at": occurred_at},
            occurred_at, "cancellation")
        await self._release_run_quotas(str(run["run_id"]), occurred_at)
        await self.session.execute(update(metadata.tables["nuclei_runs"]).where(
            metadata.tables["nuclei_runs"].c.id == run["id"]).values(
                run_state="cancelled",
                reason_code="nuclei_native_stop_acknowledged" if native_stop_acknowledged else "nuclei_forced_containment",
                completed_at=occurred_at, version=int(run["version"]) + 1, updated_at=occurred_at))
        await self._audit("nuclei.run.cancelled", str(run["run_id"]), {
            "native_stop_acknowledged": native_stop_acknowledged,
            "forced_termination": forced_termination, "quotas_released": True}, occurred_at)
        return row

    async def record_cleanup(self, *, run_id: str, receipt_id: str, container_count: int,
                             network_count: int, home_count: int, key_count: int,
                             residual_resource_count: int, inventory_sha256: str,
                             occurred_at: datetime) -> dict[str, object]:
        run = await self._active_run(run_id); key = _identifier("receipt_id", receipt_id, 100); _sha(inventory_sha256)
        counts = (container_count, network_count, home_count, key_count, residual_resource_count)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise NucleiRepositoryConflict("nuclei_cleanup_counts_invalid")
        complete = residual_resource_count == 0 and key_count == 0
        row = await self._immutable("nuclei_cleanup_receipts", {"receipt_id": key},
            {"run_record_id": run["id"], "receipt_id": key, "container_count": container_count,
             "network_count": network_count, "home_count": home_count, "key_count": key_count,
             "residual_resource_count": residual_resource_count, "cleanup_complete": complete,
             "inventory_sha256": inventory_sha256, "completed_at": occurred_at}, occurred_at, "cleanup")
        await self._release_run_quotas(str(run["run_id"]), occurred_at)
        await self.session.execute(update(metadata.tables["nuclei_runs"]).where(
            metadata.tables["nuclei_runs"].c.id == run["id"]).values(
                run_state="cleaned" if complete else "cleanup_failed",
                reason_code="nuclei_cleanup_complete" if complete else "nuclei_cleanup_incomplete",
                completed_at=occurred_at, version=int(run["version"]) + 1, updated_at=occurred_at))
        await self._audit("nuclei.run.cleaned", str(run["run_id"]), {
            "cleanup_complete": complete, "residual_resource_count": residual_resource_count}, occurred_at)
        return row

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context()
        result: dict[str, list[dict[str, object]]] = {}
        for key, table_name, order in (
            ("profiles", "nuclei_profile_revisions", "profile_id"),
            ("plans", "nuclei_compiled_plans", "created_at"),
            ("runs", "nuclei_runs", "created_at"),
            ("results", "nuclei_normalized_results", "created_at"),
            ("cleanups", "nuclei_cleanup_receipts", "created_at"),
        ):
            table = metadata.tables[table_name]
            rows = (await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id).order_by(getattr(table.c, order).desc()).limit(100))).mappings().all()
            result[key] = [dict(row) for row in rows]
        targets = metadata.tables["nuclei_target_attestations"]
        target_rows = (await self.session.execute(select(targets).where(
            targets.c.tenant_id == self.tenant_id,
            targets.c.target_id == "r105-owned-http-fixture",
        ).order_by(targets.c.issued_at.desc()).limit(100))).mappings().all()
        registrations = metadata.tables["runner_registrations"]
        runner_rows = (await self.session.execute(select(registrations).where(
            registrations.c.tenant_id == self.tenant_id,
        ).order_by(registrations.c.last_seen_at.desc()).limit(100))).mappings().all()
        jobs = metadata.tables["jobs"]
        job_rows = (await self.session.execute(select(jobs).where(
            jobs.c.tenant_id == self.tenant_id,
        ).order_by(jobs.c.created_at.desc()).limit(100))).mappings().all()
        # CRITICAL: option visibility is read-only; mutation handlers still revalidate every binding.
        result["target_options"] = [dict(row) for row in target_rows]
        result["runner_options"] = [dict(row) for row in runner_rows if (
            "nuclei-service:3.11.1-r105.2" in row["adapter_allowlist"]
            and CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"] in row["image_allowlist"]
        )]
        result["job_options"] = [dict(row) for row in job_rows if (
            isinstance(row["request"], dict) and row["request"].get("capability") == "nuclei-trusted-runtime"
        )]
        return result

    async def _containment_active(self, job_id: str) -> bool:
        controls = metadata.tables["containment_controls"]
        row = (await self.session.execute(select(controls.c.id).where(
            controls.c.tenant_id == self.tenant_id, controls.c.control_state == "active",
            or_(controls.c.scope_kind == "global",
                (controls.c.scope_kind == "tenant") & (controls.c.scope_id == self.tenant_id),
                (controls.c.scope_kind == "job") & (controls.c.scope_id == job_id),
                (controls.c.scope_kind == "capability") & (controls.c.scope_id == "nuclei-trusted-runtime")),
        ).limit(1))).one_or_none()
        return row is not None

    async def _reserve_run_quotas(self, run_id: str, job_id: str, profile_record_id: str,
                                  occurred_at: datetime) -> tuple[bool, str]:
        profiles = metadata.tables["nuclei_profile_revisions"]
        profile = (await self.session.execute(select(profiles).where(
            profiles.c.tenant_id == self.tenant_id, profiles.c.id == profile_record_id))).mappings().one()
        requested = {"time_seconds": int(profile["timeout_seconds"]),
                     "operations": int(profile["request_limit"]),
                     "concurrency": int(profile["concurrency_limit"]),
                     "data_bytes": int(profile["response_bytes_limit"])}
        policies = metadata.tables["quota_policies"]
        rows = (await self.session.execute(select(policies).where(
            policies.c.tenant_id == self.tenant_id, policies.c.scope_kind == "job",
            policies.c.scope_id == job_id, policies.c.policy_state == "active",
            policies.c.dimension.in_(tuple(requested)), policies.c.active_from <= occurred_at,
            policies.c.active_until > occurred_at,
        ).order_by(policies.c.dimension, policies.c.policy_revision.desc()))).mappings().all()
        selected: dict[str, object] = {}
        for row in rows:
            selected.setdefault(str(row["dimension"]), row)
        if set(selected) != set(requested):
            raise NucleiRepositoryConflict("nuclei_quota_policy_set_required")
        repository = ContainmentRepository(self.session, tenant_id=self.tenant_id,
                                            actor_user_id=self.actor_user_id,
                                            correlation_id=self.correlation_id)
        reservations: list[tuple[str, int]] = []
        try:
            for dimension, amount in requested.items():
                operation_id = f"r105:{run_id}:{dimension}"
                decision = await repository.reserve_quota(policy_record_id=str(selected[dimension]["id"]),
                                                            operation_id=operation_id, requested=amount,
                                                            occurred_at=occurred_at)
                if not decision.decision.allowed:
                    for reservation_id, reserved in reservations:
                        await repository.adjust_quota(reservation_id=reservation_id,
                            operation_id=f"{reservation_id}:rollback", operation_kind="release",
                            amount=reserved, occurred_at=occurred_at)
                    return False, decision.decision.reason_code
                reservations.append((operation_id, amount))
        except ContainmentRepositoryConflict as exc:
            raise NucleiRepositoryConflict(str(exc)) from exc
        return True, "quota_reserved"

    async def _release_run_quotas(self, run_id: str, occurred_at: datetime) -> None:
        table = metadata.tables["quota_reservations"]
        rows = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.reservation_id.like(f"r105:{run_id}:%"),
            table.c.reservation_state.in_(("reserved", "partially_consumed")),
        ))).mappings().all()
        repository = ContainmentRepository(self.session, tenant_id=self.tenant_id,
                                            actor_user_id=self.actor_user_id,
                                            correlation_id=self.correlation_id)
        for row in rows:
            available = int(row["reserved_amount"]) - int(row["consumed_amount"]) - int(row["released_amount"])
            if available > 0:
                await repository.adjust_quota(reservation_id=str(row["reservation_id"]),
                    operation_id=f"{row['reservation_id']}:cleanup", operation_kind="release",
                    amount=available, occurred_at=occurred_at)

    async def _active_run(self, run_id: str) -> dict[str, object]:
        key = _identifier("run_id", run_id, 100); await self._context(); await self._lock(f"nuclei-run:{key}")
        row = await self._find("nuclei_runs", {"run_id": key})
        if row is None:
            raise NucleiRepositoryConflict("nuclei_run_not_found")
        return row

    async def _immutable(self, table_name: str, where: dict[str, object], values: dict[str, object],
                         occurred_at: datetime, prefix: str) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing is not None:
            if any(existing[name] != value for name, value in values.items()):
                raise NucleiRepositoryConflict(f"nuclei_{prefix}_immutable")
            return existing
        row = {"id": f"nuclei-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id,
               **values, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables[table_name]).values(**row))
        return row

    async def _find(self, table_name: str, where: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]
        conditions = [table.c.tenant_id == self.tenant_id]
        conditions.extend(getattr(table.c, name) == value for name, value in where.items())
        row = (await self.session.execute(select(table).where(*conditions))).mappings().one_or_none()
        return None if row is None else dict(row)

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                                   {"scope": f"{self.tenant_id}:{scope}"})

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id, actor_user_id=self.actor_user_id,
            action=event, subject_type="nuclei", subject_id=subject[:64],
            correlation_id=self.correlation_id, details=details, version=1,
            created_at=occurred_at, updated_at=occurred_at))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id, event_type=event,
            aggregate_id=subject[:64], payload=details, published=False, version=1,
            created_at=occurred_at, updated_at=occurred_at))


def _identifier(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not all(
        char.isalnum() or char in "._:-" for char in value
    ):
        raise NucleiRepositoryConflict(f"nuclei_{name}_invalid")
    return value


def _sha(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise NucleiRepositoryConflict("nuclei_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise NucleiRepositoryConflict("nuclei_time_invalid")


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def profile_values(profile) -> dict[str, object]:
    return {
        "profile_id": profile.profile_id.value, "profile_revision": 1,
        "engine_version": CURRENT_NUCLEI_VERSION,
        "image_digest": CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
        "bundle_id": "r105-http-header-bundle", "bundle_revision": 2,
        "profile_sha256": canonical_profile_sha256(profile), "risk_class": "low",
        "allowed_protocols": list(profile.allowed_protocols),
        "allowed_methods": list(profile.allowed_methods), "allowed_paths": list(profile.allowed_paths),
        "request_limit": profile.request_limit,
        "request_rate_per_second": profile.request_rate_per_second,
        "concurrency_limit": profile.concurrency, "timeout_seconds": profile.timeout_seconds,
        "response_bytes_limit": profile.response_bytes_limit, "result_limit": profile.result_limit,
        "profile_state": "certified-local-lab",
    }
