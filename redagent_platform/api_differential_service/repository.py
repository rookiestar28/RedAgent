"""PostgreSQL-authoritative compat_106 promotion, plan, run, replay, and cleanup truth."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from sqlalchemy import insert, or_, select, text, update

from redagent_platform.api_differential_service.artifact import (
    EXPECTED_WHEEL_SHA256,
    verify_schemathesis_artifact,
)
from redagent_platform.api_differential_service.compiler import CompiledDifferentialPlan
from redagent_platform.api_differential_service.contracts import (
    ApiDifferentialAuthorization,
    ApiDifferentialTargetBinding,
    SCHEMATHESIS_VERSION,
    certified_profiles,
)
from redagent_platform.api_differential_service.minimization import MinimizedReplay
from redagent_platform.api_differential_service.oracle import DifferentialDecision, DifferentialObservation
from redagent_platform.api_differential_service.promotion import (
    ApiDifferentialPromotionError,
    verify_api_differential_promotion,
)
from redagent_platform.api_differential_service.specification import OpenApiSnapshot
from redagent_platform.containment_service.repository import ContainmentRepository, ContainmentRepositoryConflict
from redagent_platform.persistence.models import metadata


class ApiDifferentialRepositoryConflict(RuntimeError):
    """Stable compat_106 persistence or binding denial."""


class ApiDifferentialRepository:
    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _identifier("tenant_id", tenant_id, 64)
        self.actor_user_id = _identifier("actor_user_id", actor_user_id, 64)
        self.correlation_id = _identifier("correlation_id", correlation_id, 100)

    async def ensure_certified_foundation(
        self, *, workspace: Path, snapshot: OpenApiSnapshot,
        operation_manifest_sha256: str, identity_matrix_sha256: str,
        sequence_grammar_sha256: str, signature_sha256: str,
        expires_at: datetime, occurred_at: datetime,
    ) -> dict[str, object]:
        for value in (
            snapshot.spec_sha256, operation_manifest_sha256, identity_matrix_sha256,
            sequence_grammar_sha256, signature_sha256,
        ):
            _sha(value)
        _aware(occurred_at); _aware(expires_at)
        if not occurred_at < expires_at:
            raise ApiDifferentialRepositoryConflict("api_foundation_expiry_invalid")
        receipt = verify_schemathesis_artifact(workspace)
        try:
            promotion_receipt, verified_snapshot, _, verified_signature_sha256 = verify_api_differential_promotion(
                workspace, now=occurred_at,
            )
        except ApiDifferentialPromotionError as exc:
            raise ApiDifferentialRepositoryConflict(str(exc)) from exc
        expected = {
            "operation": _file_sha(workspace / "bundles/r106-api/operation-manifest.json"),
            "matrix": _file_sha(workspace / "bundles/r106-api/identity-matrix.json"),
            "grammar": _file_sha(workspace / "bundles/r106-api/sequence-grammar.json"),
        }
        if (
            verified_snapshot.spec_sha256 != snapshot.spec_sha256
            or operation_manifest_sha256 != expected["operation"]
            or identity_matrix_sha256 != expected["matrix"]
            or sequence_grammar_sha256 != expected["grammar"]
            or signature_sha256 != verified_signature_sha256
            or expires_at != promotion_receipt.expires_at
        ):
            raise ApiDifferentialRepositoryConflict("api_promotion_binding_mismatch")
        await self._context(); await self._lock("api-diff-foundation:v1")
        engine = await self._immutable(
            "api_diff_engine_artifacts", {"engine_id": "schemathesis-4.22.4-r106.1"},
            {
                "engine_id": "schemathesis-4.22.4-r106.1", "engine_version": SCHEMATHESIS_VERSION,
                "artifact_sha256": EXPECTED_WHEEL_SHA256,
                "lock_sha256": receipt["runtime_lock_sha256"], "sbom_sha256": receipt["generated_sbom_sha256"],
                "vulnerability_review": "pypi_zero_known_2026-07-11",
                "license_review_sha256": receipt["dependency_review_sha256"],
                "artifact_state": "certified-local-lab",
            }, occurred_at, "engine",
        )
        spec = await self._immutable(
            "api_diff_spec_revisions", {"spec_id": "r106-owned-api", "spec_revision": 1},
            {
                "spec_id": "r106-owned-api", "spec_revision": 1, "spec_sha256": snapshot.spec_sha256,
                "dialect": snapshot.dialect, "server_origin": snapshot.server,
                "operation_count": len(snapshot.operations), "spec_state": "promoted-local-lab",
                "expires_at": expires_at,
            }, occurred_at, "spec",
        )
        operation = await self._immutable(
            "api_diff_operation_manifests", {"spec_record_id": spec["id"]},
            {
                "spec_record_id": spec["id"], "operation_manifest_sha256": operation_manifest_sha256,
                "operations": [item.operation_id for item in snapshot.operations],
                "risk_classes": [item.risk.value for item in snapshot.operations],
                "media_types": ["application/json"], "manifest_state": "certified",
            }, occurred_at, "operation-manifest",
        )
        matrix = await self._immutable(
            "api_diff_identity_matrices", {"matrix_id": "r106-identity-matrix-v1"},
            {
                "matrix_id": "r106-identity-matrix-v1", "identity_matrix_sha256": identity_matrix_sha256,
                "identity_states": ["anonymous", "owner", "peer", "tenant_admin", "other_tenant", "expired", "revoked", "ownership_transferred"],
                "relations": ["cross_owner", "cross_tenant", "lower_role", "expired_session", "revoked_session"],
                "expectations": {"deny": ["401", "403", "404"], "filtered": "200_filtered"},
                "matrix_state": "certified",
            }, occurred_at, "matrix",
        )
        grammar = await self._immutable(
            "api_diff_sequence_grammars", {"grammar_id": "r106-sequence-grammar-v1"},
            {
                "grammar_id": "r106-sequence-grammar-v1", "sequence_grammar_sha256": sequence_grammar_sha256,
                "producer_consumer": {"create": "read", "transfer": "read"},
                "cleanup_grammar": {"order": "reverse_dependency", "required": True},
                "max_steps": 8, "grammar_state": "certified",
            }, occurred_at, "grammar",
        )
        review = await self._immutable(
            "api_diff_reviews", {"review_id": "r106-independent-review-v1"},
            {
                "review_id": "r106-independent-review-v1", "spec_record_id": spec["id"],
                "author_user_id": "redagent-r106-author", "reviewer_user_id": "redagent-r106-reviewer",
                "review_sha256": _canonical_sha({
                    "spec": snapshot.spec_sha256, "operation": operation_manifest_sha256,
                    "matrix": identity_matrix_sha256, "grammar": sequence_grammar_sha256,
                }), "review_state": "approved-local-lab",
            }, occurred_at, "review",
        )
        promotion_sha = _canonical_sha({
            "engine": EXPECTED_WHEEL_SHA256, "spec": snapshot.spec_sha256,
            "operation": operation_manifest_sha256, "matrix": identity_matrix_sha256,
            "grammar": sequence_grammar_sha256,
        })
        promotion = await self._immutable(
            "api_diff_promotions", {"promotion_id": "r106-api-diff-promotion-v1"},
            {
                "promotion_id": "r106-api-diff-promotion-v1", "spec_record_id": spec["id"],
                "engine_record_id": engine["id"], "identity_matrix_sha256": identity_matrix_sha256,
                "sequence_grammar_sha256": sequence_grammar_sha256,
                "promotion_sha256": promotion_sha, "signature_sha256": signature_sha256,
                "promotion_state": "active-local-lab", "promoted_at": occurred_at,
            }, occurred_at, "promotion",
        )
        profile = next(iter(certified_profiles().values()))
        profile_values = asdict(profile); profile_values["profile_id"] = profile.profile_id.value
        profile_row = await self._immutable(
            "api_diff_profiles", {"profile_id": profile.profile_id.value, "profile_revision": 1},
            {
                "profile_id": profile.profile_id.value, "profile_revision": 1,
                "promotion_record_id": promotion["id"], "profile_sha256": _canonical_sha(profile_values),
                "limits": {
                    "requests": profile.max_requests, "rate": profile.request_rate_per_second,
                    "concurrency": profile.concurrency, "time": profile.timeout_seconds,
                    "data": profile.total_data_bytes,
                }, "profile_state": "certified-local-lab",
            }, occurred_at, "profile",
        )
        await self._audit("api_diff.foundation.certified", "r106-owned-api", {
            "spec_sha256": snapshot.spec_sha256, "promotion_sha256": promotion_sha,
            "profile_sha256": profile_row["profile_sha256"], "production_qualified": False,
        }, occurred_at)
        return {
            "engine": engine, "spec": spec, "operation": operation, "matrix": matrix,
            "grammar": grammar, "review": review, "promotion": promotion, "profile": profile_row,
        }

    async def register_target_attestation(
        self, *, attestation_id: str, target: ApiDifferentialTargetBinding, occurred_at: datetime,
    ) -> dict[str, object]:
        key = _identifier("attestation_id", attestation_id, 100); _aware(occurred_at)
        await self._context(); await self._lock(f"api-diff-target:{key}")
        row = await self._immutable(
            "api_diff_target_attestations", {"attestation_id": key},
            {
                "attestation_id": key, "target_id": target.target_id,
                "attestation_sha256": target.attestation_sha256, "fixture_sha256": target.fixture_sha256,
                "endpoint": target.endpoint, "network_id": target.network_id,
                "non_production": target.non_production, "attestation_state": "active",
                "issued_at": target.issued_at, "expires_at": target.expires_at,
            }, occurred_at, "target",
        )
        await self._audit("api_diff.target.attested", target.target_id, {
            "attestation_id": key, "attestation_sha256": target.attestation_sha256,
        }, occurred_at)
        return row

    async def store_plan(
        self, *, plan_id: str, compiled: CompiledDifferentialPlan,
        target: ApiDifferentialTargetBinding, authorization: ApiDifferentialAuthorization,
        occurred_at: datetime,
    ) -> dict[str, object]:
        key = _identifier("plan_id", plan_id, 100); _aware(occurred_at)
        await self._context(); await self._lock(f"api-diff-plan:{key}")
        profile_table = metadata.tables["api_diff_profiles"]
        profile = (await self.session.execute(select(profile_table).where(
            profile_table.c.tenant_id == self.tenant_id,
            profile_table.c.profile_id == compiled.profile_id.value,
            profile_table.c.profile_state == "certified-local-lab",
        ))).mappings().one_or_none()
        target_table = metadata.tables["api_diff_target_attestations"]
        attestation = (await self.session.execute(select(target_table).where(
            target_table.c.tenant_id == self.tenant_id, target_table.c.target_id == target.target_id,
            target_table.c.attestation_sha256 == target.attestation_sha256,
            target_table.c.fixture_sha256 == target.fixture_sha256,
            target_table.c.endpoint == target.endpoint, target_table.c.network_id == target.network_id,
            target_table.c.non_production.is_(True), target_table.c.attestation_state == "active",
            target_table.c.issued_at <= occurred_at, target_table.c.expires_at > occurred_at,
        ))).mappings().one_or_none()
        if profile is None:
            raise ApiDifferentialRepositoryConflict("api_certified_profile_required")
        if attestation is None:
            raise ApiDifferentialRepositoryConflict("api_target_attestation_required")
        compiled_state = {
            "schema": "redagent.r106-compiled-plan/v1", "profile_id": compiled.profile_id.value,
            "policy_revision": authorization.policy_revision, "spec_sha256": compiled.spec_sha256,
            "cases": [
                {
                    "case_id": case.case_id, "operation_id": case.operation_id,
                    "relation": case.relation.value, "risk": case.risk.value,
                    "privileged_identity_handle": case.privileged_identity_handle,
                    "lower_identity_handle": case.lower_identity_handle,
                } for case in compiled.cases
            ],
        }
        row = await self._immutable(
            "api_diff_plans", {"plan_id": key},
            {
                "plan_id": key, "profile_record_id": profile["id"],
                "target_attestation_id": attestation["id"],
                "policy_decision_id": authorization.policy_decision_id,
                "roe_version_id": authorization.roe_version_id,
                "spec_sha256": compiled.spec_sha256, "plan_sha256": compiled.plan_sha256,
                "seed": compiled.seed, "compiled_plan": compiled_state,
                "expires_at": min(target.expires_at, authorization.expires_at),
            }, occurred_at, "plan",
        )
        for case in compiled.cases:
            await self._immutable(
                "api_diff_cases", {"plan_record_id": row["id"], "case_id": case.case_id},
                {
                    "plan_record_id": row["id"], "case_id": case.case_id,
                    "operation_id": case.operation_id, "identity_handle": case.lower_identity_handle,
                    "relation": case.relation.value, "risk_class": case.risk.value,
                    "case_sha256": _canonical_sha(asdict(case)), "case_state": "compiled",
                }, occurred_at, "case",
            )
        await self._audit("api_diff.plan.compiled", key, {
            "plan_sha256": compiled.plan_sha256, "case_count": len(compiled.cases),
        }, occurred_at)
        return row

    async def create_run(
        self, *, run_id: str, plan_id: str, job_id: str, runner_id: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run_key = _identifier("run_id", run_id, 100); plan_key = _identifier("plan_id", plan_id, 100)
        job_key = _identifier("job_id", job_id, 100); runner_key = _identifier("runner_id", runner_id, 100)
        _aware(occurred_at); await self._context(); await self._lock(f"api-diff-run:{run_key}")
        existing = await self._find("api_diff_runs", {"run_id": run_key})
        if existing is not None:
            if existing["job_id"] != job_key or existing["runner_id"] != runner_key:
                raise ApiDifferentialRepositoryConflict("api_run_replay_mismatch")
            return existing
        plans = metadata.tables["api_diff_plans"]
        plan = (await self.session.execute(select(plans).where(
            plans.c.tenant_id == self.tenant_id, plans.c.plan_id == plan_key,
            plans.c.expires_at > occurred_at,
        ))).mappings().one_or_none()
        if plan is None:
            raise ApiDifferentialRepositoryConflict("api_plan_active_required")
        compiled = plan["compiled_plan"]
        if not isinstance(compiled, dict) or compiled.get("schema") != "redagent.r106-compiled-plan/v1":
            raise ApiDifferentialRepositoryConflict("api_plan_state_invalid")
        target_table = metadata.tables["api_diff_target_attestations"]
        target = (await self.session.execute(select(target_table.c.id).where(
            target_table.c.tenant_id == self.tenant_id,
            target_table.c.id == plan["target_attestation_id"],
            target_table.c.network_id == "redagent-r106-gateway-target",
            target_table.c.non_production.is_(True), target_table.c.attestation_state == "active",
            target_table.c.issued_at <= occurred_at, target_table.c.expires_at > occurred_at,
        ))).one_or_none()
        profiles = metadata.tables["api_diff_profiles"]
        profile = (await self.session.execute(select(profiles).where(
            profiles.c.tenant_id == self.tenant_id, profiles.c.id == plan["profile_record_id"],
            profiles.c.profile_state == "certified-local-lab",
        ))).mappings().one_or_none()
        promotions = metadata.tables["api_diff_promotions"]
        promotion = None if profile is None else (await self.session.execute(select(promotions.c.id).where(
            promotions.c.tenant_id == self.tenant_id,
            promotions.c.id == profile["promotion_record_id"],
            promotions.c.promotion_state == "active-local-lab",
        ))).one_or_none()
        decisions = metadata.tables["policy_decisions"]
        decision = (await self.session.execute(select(decisions.c.id).where(
            decisions.c.tenant_id == self.tenant_id,
            decisions.c.opa_decision_id == plan["policy_decision_id"],
            decisions.c.bundle_revision == compiled.get("policy_revision"),
            decisions.c.action == "api_diff.plan.compile",
            decisions.c.resource_type == "api_diff_profile",
            decisions.c.resource_id == compiled.get("profile_id"),
            decisions.c.allowed.is_(True), decisions.c.valid_until > occurred_at,
        ))).one_or_none()
        roes = metadata.tables["roe_versions"]
        roe = (await self.session.execute(select(roes.c.id).where(
            roes.c.tenant_id == self.tenant_id, roes.c.id == plan["roe_version_id"], roes.c.status == "approved",
        ))).one_or_none()
        if target is None:
            raise ApiDifferentialRepositoryConflict("api_target_revalidation_required")
        if profile is None or promotion is None:
            raise ApiDifferentialRepositoryConflict("api_promotion_revalidation_required")
        if decision is None or roe is None:
            raise ApiDifferentialRepositoryConflict("api_policy_revalidation_required")
        jobs = metadata.tables["jobs"]
        job = (await self.session.execute(select(jobs).where(
            jobs.c.tenant_id == self.tenant_id, jobs.c.id == job_key,
        ))).mappings().one_or_none()
        if job is None or not isinstance(job["request"], dict) or job["request"].get("capability") != "api-authorization-differential":
            raise ApiDifferentialRepositoryConflict("api_job_capability_required")
        registrations = metadata.tables["runner_registrations"]
        runner = (await self.session.execute(select(registrations).where(
            registrations.c.tenant_id == self.tenant_id, registrations.c.runner_id == runner_key,
            registrations.c.registration_state == "active", registrations.c.expires_at > occurred_at,
        ).order_by(registrations.c.generation.desc()).limit(1))).mappings().one_or_none()
        artifact_digest = f"sha256:{EXPECTED_WHEEL_SHA256}"
        if (
            runner is None or runner["required_policy_revision"] != compiled.get("policy_revision")
            or "schemathesis:4.22.4-r106.1" not in runner["adapter_allowlist"]
            or artifact_digest not in runner["image_allowlist"]
        ):
            raise ApiDifferentialRepositoryConflict("api_runner_registration_required")
        if await self._containment_active(job_key):
            allowed, reason, state = False, "api_containment_active", "containment_denied"
        else:
            allowed, reason = await self._reserve_run_quotas(run_key, job_key, profile, occurred_at)
            state = "quota_denied"
        row = {
            "id": f"api-diff-run-{uuid4().hex}", "tenant_id": self.tenant_id,
            "run_id": run_key, "plan_record_id": plan["id"], "job_id": job_key, "runner_id": runner_key,
            "run_state": "dispatch_pending" if allowed else state, "progress_percent": 0,
            "request_count": 0, "response_bytes": 0, "finding_count": 0,
            "reason_code": "api_run_accepted" if allowed else reason,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables["api_diff_runs"]).values(**row))
        await self._audit("api_diff.run.accepted", run_key, {
            "plan_id": plan_key, "quota_allowed": allowed, "reason_code": row["reason_code"],
        }, occurred_at)
        return row

    async def record_resource(
        self, *, run_id: str, resource_id: str, resource_lineage_sha256: str,
        owner_identity_handle: str, tenant_handle: str, idempotency_key: str,
        compensation_operation: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run = await self._active_run(run_id); _sha(resource_lineage_sha256)
        return await self._immutable(
            "api_diff_resource_ledger", {"run_record_id": run["id"], "resource_id": resource_id},
            {
                "run_record_id": run["id"], "resource_id": _identifier("resource_id", resource_id, 100),
                "resource_lineage_sha256": resource_lineage_sha256,
                "owner_identity_handle": _identifier("identity_handle", owner_identity_handle, 100),
                "tenant_handle": _identifier("tenant_handle", tenant_handle, 100),
                "idempotency_key": _identifier("idempotency_key", idempotency_key, 150),
                "resource_state": "created", "compensation_operation": _identifier(
                    "compensation_operation", compensation_operation, 100,
                ),
            }, occurred_at, "resource",
        )

    async def record_observation(
        self, *, run_id: str, observation_id: str, observation: DifferentialObservation,
        decision: DifferentialDecision, evidence_instance_id: str | None,
        occurred_at: datetime,
    ) -> dict[str, object]:
        run = await self._active_run(run_id); _aware(occurred_at)
        outcome_sha = _canonical_sha(asdict(observation))
        evidence = None if evidence_instance_id is None else _identifier("evidence_instance_id", evidence_instance_id, 100)
        row = await self._immutable(
            "api_diff_observations", {"observation_id": observation_id},
            {
                "run_record_id": run["id"], "observation_id": _identifier("observation_id", observation_id, 100),
                "case_id": _identifier("case_id", observation.case_id, 150),
                "resource_lineage_sha256": observation.resource_lineage_sha256,
                "outcome_sha256": outcome_sha, "finding_type": decision.finding_type,
                "violated": decision.violated, "evidence_instance_id": evidence,
                "reason_code": decision.reason,
            }, occurred_at, "observation",
        )
        if decision.violated:
            if evidence is None or decision.finding_type not in {"bola", "bfla", "bopla"}:
                raise ApiDifferentialRepositoryConflict("api_finding_evidence_required")
            fingerprint = _canonical_sha({
                "tool": "api-differential", "rule": decision.finding_type,
                "operation": observation.operation_id, "relation": observation.relation.value,
                "lineage": observation.resource_lineage_sha256,
            })
            issue = await self._find("issue_definitions", {"fingerprint": fingerprint})
            if issue is None:
                issue = {
                    "id": f"issue-api-diff-{uuid4().hex}", "tenant_id": self.tenant_id,
                    "fingerprint": fingerprint,
                    "title": f"API {decision.finding_type.upper()} authorization differential",
                    "tool": "api-differential", "rule_id": decision.finding_type,
                    "tool_version": SCHEMATHESIS_VERSION, "database_version": "r106-matrix-v1",
                    "severity": "high", "confidence": "firm", "version": 1,
                    "created_at": occurred_at, "updated_at": occurred_at,
                }
                await self.session.execute(insert(metadata.tables["issue_definitions"]).values(**issue))
            instances = metadata.tables["finding_instances"]
            location = observation.operation_id
            existing = (await self.session.execute(select(instances.c.id).where(
                instances.c.tenant_id == self.tenant_id,
                instances.c.issue_definition_id == issue["id"],
                instances.c.affected_resource == observation.resource_lineage_sha256,
                instances.c.location == location,
            ))).one_or_none()
            if existing is None:
                await self.session.execute(insert(instances).values(
                    id=f"finding-api-diff-{uuid4().hex}", tenant_id=self.tenant_id,
                    issue_definition_id=issue["id"], affected_resource=observation.resource_lineage_sha256,
                    location=location, evidence_reference=evidence, redaction_state="redacted",
                    version=1, created_at=occurred_at, updated_at=occurred_at,
                ))
                await self.session.execute(update(metadata.tables["api_diff_runs"]).where(
                    metadata.tables["api_diff_runs"].c.id == run["id"]).values(
                        finding_count=int(run["finding_count"]) + 1,
                        version=int(run["version"]) + 1, updated_at=occurred_at,
                    ))
        return row

    async def record_replay(
        self, *, run_id: str, replay_id: str, replay: MinimizedReplay, occurred_at: datetime,
    ) -> dict[str, object]:
        run = await self._active_run(run_id)
        public = {
            "schema": "redagent.r106-minimized-replay/v1", "case_id": replay.case_id,
            "operation_id": replay.operation_id, "relation": replay.relation.value,
            "resource_lineage_sha256": replay.resource_lineage_sha256,
            "violated_predicate": replay.violated_predicate,
            "sequence_steps": list(replay.sequence_steps), "public_values": dict(replay.public_values),
            "seed": replay.seed,
        }
        # Identity handles are deliberately excluded from durable replay payloads.
        return await self._immutable(
            "api_diff_replay_artifacts", {"replay_id": replay_id},
            {
                "run_record_id": run["id"], "replay_id": _identifier("replay_id", replay_id, 100),
                "case_id": _identifier("case_id", replay.case_id, 150),
                "minimized_replay_sha256": _canonical_sha(public), "public_replay": public,
                "semantic_predicate": _identifier("semantic_predicate", replay.violated_predicate, 100),
                "replay_state": "verified-local-lab",
            }, occurred_at, "replay",
        )

    async def request_cancel(
        self, *, run_id: str, expected_version: int, reason_code: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run = await self._active_run(run_id)
        if run["run_state"] in {"cancelled", "cleaned", "succeeded", "failed", "quota_denied", "containment_denied"}:
            return run
        if run["version"] != expected_version:
            raise ApiDifferentialRepositoryConflict("api_run_version_conflict")
        values = {
            "run_state": "cancel_requested", "reason_code": _identifier("reason_code", reason_code, 100),
            "version": int(run["version"]) + 1, "updated_at": occurred_at,
        }
        await self.session.execute(update(metadata.tables["api_diff_runs"]).where(
            metadata.tables["api_diff_runs"].c.id == run["id"]).values(**values))
        return {**run, **values}

    async def record_cancellation(
        self, *, run_id: str, receipt_id: str, gateway_blocked: bool,
        native_stop_attempted: bool, native_stop_acknowledged: bool,
        lease_revoked: bool, forced_termination: bool, occurred_at: datetime,
    ) -> dict[str, object]:
        run = await self._active_run(run_id)
        if run["run_state"] != "cancel_requested":
            raise ApiDifferentialRepositoryConflict("api_cancellation_state_invalid")
        if not gateway_blocked or not native_stop_attempted or not lease_revoked:
            raise ApiDifferentialRepositoryConflict("api_cancellation_phase_incomplete")
        if not native_stop_acknowledged and not forced_termination:
            raise ApiDifferentialRepositoryConflict("api_cancellation_containment_required")
        row = await self._immutable(
            "api_diff_cancellation_receipts", {"receipt_id": receipt_id},
            {
                "run_record_id": run["id"], "receipt_id": _identifier("receipt_id", receipt_id, 100),
                "gateway_blocked": gateway_blocked, "native_stop_attempted": native_stop_attempted,
                "native_stop_acknowledged": native_stop_acknowledged, "lease_revoked": lease_revoked,
                "forced_termination": forced_termination, "completed_at": occurred_at,
            }, occurred_at, "cancellation",
        )
        await self._release_run_quotas(str(run["run_id"]), occurred_at)
        await self.session.execute(update(metadata.tables["api_diff_runs"]).where(
            metadata.tables["api_diff_runs"].c.id == run["id"]).values(
                run_state="cancelled", reason_code="api_native_stop_acknowledged" if native_stop_acknowledged else "api_forced_containment",
                version=int(run["version"]) + 1, updated_at=occurred_at,
            ))
        return row

    async def record_cleanup(
        self, *, run_id: str, receipt_id: str, compensation_complete: bool,
        lease_revoked: bool, container_count: int, network_count: int,
        transient_file_count: int, residual_resource_count: int,
        inventory_sha256: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run = await self._active_run(run_id); _sha(inventory_sha256)
        counts = (container_count, network_count, transient_file_count, residual_resource_count)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise ApiDifferentialRepositoryConflict("api_cleanup_counts_invalid")
        complete = compensation_complete and lease_revoked and residual_resource_count == 0
        row = await self._immutable(
            "api_diff_cleanup_receipts", {"receipt_id": receipt_id},
            {
                "run_record_id": run["id"], "receipt_id": _identifier("receipt_id", receipt_id, 100),
                "compensation_complete": compensation_complete, "lease_revoked": lease_revoked,
                "container_count": container_count, "network_count": network_count,
                "transient_file_count": transient_file_count,
                "residual_resource_count": residual_resource_count,
                "inventory_sha256": inventory_sha256, "completed_at": occurred_at,
            }, occurred_at, "cleanup",
        )
        await self._release_run_quotas(str(run["run_id"]), occurred_at)
        await self.session.execute(update(metadata.tables["api_diff_runs"]).where(
            metadata.tables["api_diff_runs"].c.id == run["id"]).values(
                run_state="cleaned" if complete else "cleanup_failed",
                reason_code="api_cleanup_complete" if complete else "api_cleanup_incomplete",
                version=int(run["version"]) + 1, updated_at=occurred_at,
            ))
        return row

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context(); result: dict[str, list[dict[str, object]]] = {}
        for key, table_name in (
            ("profiles", "api_diff_profiles"), ("plans", "api_diff_plans"),
            ("runs", "api_diff_runs"), ("observations", "api_diff_observations"),
            ("replays", "api_diff_replay_artifacts"), ("cleanups", "api_diff_cleanup_receipts"),
        ):
            table = metadata.tables[table_name]
            rows = (await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id).order_by(table.c.created_at.desc()).limit(100)
            )).mappings().all()
            result[key] = [dict(row) for row in rows]
        targets = metadata.tables["api_diff_target_attestations"]
        target_rows = (await self.session.execute(select(targets).where(
            targets.c.tenant_id == self.tenant_id,
            targets.c.target_id == "r106-owned-api-fixture",
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
            "schemathesis:4.22.4-r106.1" in row["adapter_allowlist"]
            and f"sha256:{EXPECTED_WHEEL_SHA256}" in row["image_allowlist"]
        )]
        result["job_options"] = [dict(row) for row in job_rows if (
            isinstance(row["request"], dict)
            and row["request"].get("capability") == "api-authorization-differential"
        )]
        return result

    async def _containment_active(self, job_id: str) -> bool:
        controls = metadata.tables["containment_controls"]
        row = (await self.session.execute(select(controls.c.id).where(
            controls.c.tenant_id == self.tenant_id, controls.c.control_state == "active",
            or_(
                controls.c.scope_kind == "global",
                (controls.c.scope_kind == "tenant") & (controls.c.scope_id == self.tenant_id),
                (controls.c.scope_kind == "job") & (controls.c.scope_id == job_id),
                (controls.c.scope_kind == "capability") & (controls.c.scope_id == "api-authorization-differential"),
            ),
        ).limit(1))).one_or_none()
        return row is not None

    async def _reserve_run_quotas(
        self, run_id: str, job_id: str, profile: dict[str, object], occurred_at: datetime,
    ) -> tuple[bool, str]:
        limits = profile["limits"]
        if not isinstance(limits, dict):
            raise ApiDifferentialRepositoryConflict("api_profile_limits_invalid")
        requested = {
            "time_seconds": int(limits["time"]), "operations": int(limits["requests"]),
            "concurrency": int(limits["concurrency"]), "data_bytes": int(limits["data"]),
        }
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
            raise ApiDifferentialRepositoryConflict("api_quota_policy_set_required")
        repository = ContainmentRepository(
            self.session, tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, correlation_id=self.correlation_id,
        )
        reservations: list[tuple[str, int]] = []
        try:
            for dimension, amount in requested.items():
                operation_id = f"r106:{run_id}:{dimension}"
                quota = await repository.reserve_quota(
                    policy_record_id=str(selected[dimension]["id"]), operation_id=operation_id,
                    requested=amount, occurred_at=occurred_at,
                )
                if not quota.decision.allowed:
                    for reservation_id, reserved in reservations:
                        await repository.adjust_quota(
                            reservation_id=reservation_id, operation_id=f"{reservation_id}:rollback",
                            operation_kind="release", amount=reserved, occurred_at=occurred_at,
                        )
                    return False, quota.decision.reason_code
                reservations.append((operation_id, amount))
        except ContainmentRepositoryConflict as exc:
            raise ApiDifferentialRepositoryConflict(str(exc)) from exc
        return True, "quota_reserved"

    async def _release_run_quotas(self, run_id: str, occurred_at: datetime) -> None:
        table = metadata.tables["quota_reservations"]
        rows = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id,
            table.c.reservation_id.like(f"r106:{run_id}:%"),
            table.c.reservation_state.in_(("reserved", "partially_consumed")),
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
                    operation_id=f"{row['reservation_id']}:cleanup", operation_kind="release",
                    amount=available, occurred_at=occurred_at,
                )

    async def _active_run(self, run_id: str) -> dict[str, object]:
        key = _identifier("run_id", run_id, 100); await self._context(); await self._lock(f"api-diff-run:{key}")
        row = await self._find("api_diff_runs", {"run_id": key})
        if row is None:
            raise ApiDifferentialRepositoryConflict("api_run_not_found")
        return row

    async def _immutable(
        self, table_name: str, where: dict[str, object], values: dict[str, object],
        occurred_at: datetime, prefix: str,
    ) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing is not None:
            if any(existing[name] != value for name, value in values.items()):
                raise ApiDifferentialRepositoryConflict(f"api_{prefix}_immutable")
            return existing
        row = {
            "id": f"api-diff-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id,
            **values, "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
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
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {
            "scope": f"{self.tenant_id}:{scope}",
        })

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, action=event, subject_type="api_differential",
            subject_id=subject[:64], correlation_id=self.correlation_id, details=details,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id, event_type=event,
            aggregate_id=subject[:64], payload=details, published=False,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))


def _identifier(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not all(
        char.isalnum() or char in "._:-" for char in value
    ):
        raise ApiDifferentialRepositoryConflict(f"api_{name}_invalid")
    return value


def _sha(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ApiDifferentialRepositoryConflict("api_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ApiDifferentialRepositoryConflict("api_time_invalid")


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ApiDifferentialRepositoryConflict("api_promotion_input_unavailable") from exc
