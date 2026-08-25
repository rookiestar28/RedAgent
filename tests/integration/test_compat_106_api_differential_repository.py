from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api_differential_service.artifact import EXPECTED_WHEEL_SHA256
from redagent_platform.api_differential_service.compiler import compile_differential_plan
from redagent_platform.api_differential_service.contracts import (
    ApiDifferentialAuthorization,
    ApiDifferentialProfileId,
    ApiDifferentialTargetBinding,
    IdentityRelation,
    IdentityState,
)
from redagent_platform.api_differential_service.minimization import minimize_replay
from redagent_platform.api_differential_service.oracle import (
    DifferentialObservation,
    evaluate_authorization_differential,
)
from redagent_platform.api_differential_service.repository import (
    ApiDifferentialRepository,
    ApiDifferentialRepositoryConflict,
)
from redagent_platform.api_differential_service.promotion import verify_api_differential_promotion
from redagent_platform.api_differential_service.provisioning import register_api_differential_capability
from redagent_platform.api_differential_service.specification import validate_and_snapshot_spec
from redagent_platform.containment_service.contracts import ControlScope, ControlScopeKind, QuotaDimension, QuotaPolicy
from redagent_platform.containment_service.repository import ContainmentRepository
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from tests.unit.test_compat_106_api_differential_contracts import spec


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 11, 14, 0, tzinfo=timezone.utc)


def test_r106_foundation_dispatch_revalidation_finding_replay_cancel_cleanup_and_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r106-{suffix}"
    actor = f"operator-r106-{suffix}"
    job_id = f"job-r106-{suffix}"
    runner_id = f"runner-r106-{suffix}"
    plan_id = f"plan-r106-{suffix}"
    run_id = f"run-r106-{suffix}"
    snapshot = validate_and_snapshot_spec(spec())
    promotion_receipt, promoted_snapshot, _, signature_sha256 = verify_api_differential_promotion(ROOT, now=NOW)
    assert promoted_snapshot.spec_sha256 == snapshot.spec_sha256
    operation_sha256 = file_sha("bundles/r106-api/operation-manifest.json")
    matrix_sha256 = file_sha("bundles/r106-api/identity-matrix.json")
    grammar_sha256 = file_sha("bundles/r106-api/sequence-grammar.json")
    target = ApiDifferentialTargetBinding(
        target_id="r106-owned-api-fixture", attestation_sha256="a" * 64,
        fixture_sha256="b" * 64, endpoint="http://redagent-r106-gateway:8080",
        network_id="redagent-r106-gateway-target", non_production=True,
        issued_at=NOW, expires_at=NOW + timedelta(minutes=20),
    )
    authorization = ApiDifferentialAuthorization(
        tenant_id=tenant, policy_decision_id=f"decision-r106-{suffix}", policy_revision="r099-v1",
        roe_version_id=f"roe-r106-{suffix}", approved_profile_ids=(ApiDifferentialProfileId.STANDARD,),
        approved_spec_sha256=snapshot.spec_sha256,
        approved_at=NOW, expires_at=NOW + timedelta(minutes=15),
    )
    compiled = compile_differential_plan(
        profile_id=ApiDifferentialProfileId.STANDARD, snapshot=snapshot,
        authorization=authorization,
        identity_handles={
            IdentityState.OWNER: "identity-owner", IdentityState.PEER: "identity-peer",
            IdentityState.TENANT_ADMIN: "identity-admin",
            IdentityState.OTHER_TENANT: "identity-other-tenant",
            IdentityState.EXPIRED: "identity-expired", IdentityState.REVOKED: "identity-revoked",
        }, seed=10620260711, now=NOW,
    )
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}",
            ).bootstrap_tenant(name="compat_106 API differential", occurred_at=NOW)
            registered = await register_api_differential_capability(
                session, workspace=ROOT, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"capability-{suffix}", occurred_at=NOW,
            )
            assert registered["capability_id"] == "api-authorization-differential"
            assert registered["artifact_receipt_id"] == promotion_receipt.receipt_id
            await _bootstrap_job_runner_and_quotas(session, tenant, actor, suffix, job_id, runner_id)
            repository = ApiDifferentialRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"api-diff-{suffix}",
            )
            foundation = await repository.ensure_certified_foundation(
                workspace=ROOT, snapshot=snapshot, operation_manifest_sha256=operation_sha256,
                identity_matrix_sha256=matrix_sha256, sequence_grammar_sha256=grammar_sha256,
                signature_sha256=signature_sha256, expires_at=promotion_receipt.expires_at, occurred_at=NOW,
            )
            replay_foundation = await repository.ensure_certified_foundation(
                workspace=ROOT, snapshot=snapshot, operation_manifest_sha256=operation_sha256,
                identity_matrix_sha256=matrix_sha256, sequence_grammar_sha256=grammar_sha256,
                signature_sha256=signature_sha256, expires_at=promotion_receipt.expires_at, occurred_at=NOW,
            )
            assert replay_foundation["promotion"]["id"] == foundation["promotion"]["id"]
            await repository.register_target_attestation(
                attestation_id=f"attestation-r106-{suffix}", target=target, occurred_at=NOW,
            )
            plan = await repository.store_plan(
                plan_id=plan_id, compiled=compiled, target=target,
                authorization=authorization, occurred_at=NOW,
            )
            target_table = metadata.tables["api_diff_target_attestations"]
            await session.execute(update(target_table).where(
                target_table.c.tenant_id == tenant, target_table.c.target_id == target.target_id,
            ).values(attestation_state="revoked"))
            with pytest.raises(ApiDifferentialRepositoryConflict, match="api_target_revalidation_required"):
                await repository.create_run(
                    run_id=run_id, plan_id=plan_id, job_id=job_id,
                    runner_id=runner_id, occurred_at=NOW + timedelta(seconds=1),
                )
            await session.execute(update(target_table).where(
                target_table.c.tenant_id == tenant, target_table.c.target_id == target.target_id,
            ).values(attestation_state="active"))
            policy_table = metadata.tables["policy_decisions"]
            await session.execute(update(policy_table).where(
                policy_table.c.tenant_id == tenant,
                policy_table.c.opa_decision_id == authorization.policy_decision_id,
            ).values(allowed=False))
            with pytest.raises(ApiDifferentialRepositoryConflict, match="api_policy_revalidation_required"):
                await repository.create_run(
                    run_id=run_id, plan_id=plan_id, job_id=job_id,
                    runner_id=runner_id, occurred_at=NOW + timedelta(seconds=1),
                )
            await session.execute(update(policy_table).where(
                policy_table.c.tenant_id == tenant,
                policy_table.c.opa_decision_id == authorization.policy_decision_id,
            ).values(allowed=True))
            run = await repository.create_run(
                run_id=run_id, plan_id=plan_id, job_id=job_id,
                runner_id=runner_id, occurred_at=NOW + timedelta(seconds=1),
            )
            assert plan["plan_sha256"] == compiled.plan_sha256 and run["run_state"] == "dispatch_pending"
            await repository.record_resource(
                run_id=run_id, resource_id="document-owner-a", resource_lineage_sha256="1" * 64,
                owner_identity_handle="identity-owner", tenant_handle="tenant-a",
                idempotency_key="create-document-owner-a", compensation_operation="deleteDocument",
                occurred_at=NOW + timedelta(seconds=2),
            )
            observation = DifferentialObservation(
                case_id="compat_106:getDocument:cross_owner", operation_id="getDocument",
                relation=IdentityRelation.CROSS_OWNER, privileged_status=200, lower_status=200,
                privileged_properties=("id", "owner_id", "title"),
                lower_properties=("id", "owner_id", "title"),
                expected_lower_outcomes=("403", "404"), protected_properties=("owner_id", "title"),
                resource_lineage_sha256="1" * 64,
            )
            decision = evaluate_authorization_differential(observation)
            recorded = await repository.record_observation(
                run_id=run_id, observation_id=f"observation-r106-{suffix}",
                observation=observation, decision=decision,
                evidence_instance_id=f"evidence-r106-{suffix}", occurred_at=NOW + timedelta(seconds=3),
            )
            assert recorded["violated"] is True and recorded["finding_type"] == "bola"
            replay = minimize_replay(
                case_id=observation.case_id, operation_id=observation.operation_id,
                relation=observation.relation, privileged_identity_handle="identity-owner",
                lower_identity_handle="identity-peer", resource_lineage_sha256="1" * 64,
                violated_predicate="cross_owner_read",
                sequence_steps=("create-document", "read-owner", "read-peer"),
                required_steps=("create-document", "read-peer"),
                public_values={"documentId": "document-owner-a"},
                required_value_names=("documentId",), seed=compiled.seed,
            )
            replay_row = await repository.record_replay(
                run_id=run_id, replay_id=f"replay-r106-{suffix}", replay=replay,
                occurred_at=NOW + timedelta(seconds=4),
            )
            assert "identity" not in json_text(replay_row["public_replay"])
            requested = await repository.request_cancel(
                run_id=run_id, expected_version=2, reason_code="operator_cancel_requested",
                occurred_at=NOW + timedelta(seconds=5),
            )
            assert requested["run_state"] == "cancel_requested"
            cancel = await repository.record_cancellation(
                run_id=run_id, receipt_id=f"cancel-r106-{suffix}", gateway_blocked=True,
                native_stop_attempted=True, native_stop_acknowledged=True,
                lease_revoked=True, forced_termination=False,
                occurred_at=NOW + timedelta(seconds=6),
            )
            assert cancel["gateway_blocked"] and cancel["lease_revoked"]
            cleanup = await repository.record_cleanup(
                run_id=run_id, receipt_id=f"cleanup-r106-{suffix}", compensation_complete=True,
                lease_revoked=True, container_count=0, network_count=0, transient_file_count=0,
                residual_resource_count=0, inventory_sha256="2" * 64,
                occurred_at=NOW + timedelta(seconds=7),
            )
            assert cleanup["residual_resource_count"] == 0
            issue_count = await session.scalar(select(func.count()).select_from(
                metadata.tables["issue_definitions"]).where(
                    metadata.tables["issue_definitions"].c.tenant_id == tenant,
                    metadata.tables["issue_definitions"].c.tool == "api-differential",
                ))
            finding_count = await session.scalar(select(func.count()).select_from(
                metadata.tables["finding_instances"]).where(
                    metadata.tables["finding_instances"].c.tenant_id == tenant,
                ))
            assert issue_count == 1 and finding_count == 1
        async with sessions() as session, session.begin():
            dashboard = await ApiDifferentialRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"dashboard-{suffix}",
            ).dashboard()
            assert dashboard["runs"][0]["run_state"] == "cleaned"
            assert len(dashboard["observations"]) == 1 and len(dashboard["replays"]) == 1
            assert dashboard["target_options"][0]["target_id"] == "r106-owned-api-fixture"
            assert [row["runner_id"] for row in dashboard["runner_options"]] == [runner_id]
            assert [row["id"] for row in dashboard["job_options"]] == [job_id]
            other = await ApiDifferentialRepository(
                session, tenant_id=f"other-{suffix}", actor_user_id=actor,
                correlation_id=f"other-{suffix}",
            ).dashboard()
            assert all(not rows for rows in other.values())
    finally:
        await engine.dispose()


def json_text(value: object) -> str:
    import json
    return json.dumps(value, sort_keys=True)


def file_sha(relative: str) -> str:
    import hashlib
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


async def _bootstrap_job_runner_and_quotas(
    session, tenant: str, actor: str, suffix: str, job_id: str, runner_id: str,
) -> None:
    owned = {"tenant_id": tenant, "version": 1, "created_at": NOW, "updated_at": NOW}
    engagement_id = f"engagement-r106-{suffix}"
    roe_id = f"roe-r106-{suffix}"
    runner_class_id = f"runner-class-r106-{suffix}"
    await session.execute(insert(metadata.tables["engagements"]).values(
        id=engagement_id, name="compat_106 owned API fixture", owner_user_id=actor, **owned))
    await session.execute(insert(metadata.tables["roe_versions"]).values(
        id=roe_id, engagement_id=engagement_id, revision=1, status="approved",
        document={"target": "r106-owned-api-fixture"}, **owned))
    await session.execute(insert(metadata.tables["policy_decisions"]).values(
        id=f"policy-decision-r106-{suffix}", opa_decision_id=f"decision-r106-{suffix}",
        bundle_revision="r099-v1", input_hash="3" * 64, boundary="runner",
        action="api_diff.plan.compile", subject_id=actor, resource_type="api_diff_profile",
        resource_id="openapi-authorization-differential-v1", resource_version=1, allowed=True,
        reason_code="r106_profile_approved", obligations=["owned_fixture_only"],
        issued_at=NOW, valid_until=NOW + timedelta(minutes=20),
        correlation_id=f"policy-r106-{suffix}", **owned))
    await session.execute(insert(metadata.tables["jobs"]).values(
        id=job_id, engagement_id=engagement_id, roe_version_id=roe_id,
        created_by_user_id=actor, campaign_id=None, status="approved",
        request={"capability": "api-authorization-differential", "approval_timeout_seconds": 600,
                 "max_activity_attempts": 1, "budget_reference": f"budget-r106-{suffix}"},
        policy_reference="policy:r099-v1", workflow_id=f"workflow-r106-{suffix}",
        workflow_run_id=f"workflow-run-r106-{suffix}", orchestration_state="ready",
        orchestration_revision=1, current_gate="runner_dispatch", failure_code=None,
        retry_count=0, dispatch_blocked=False, stop_requested=False, **owned))
    await session.execute(insert(metadata.tables["runner_classes"]).values(
        id=runner_class_id, class_id=f"api-r106-{suffix}", class_revision=1,
        environment="local-conformance", network_plane="r106-owned-gateway",
        isolation_tier="container", runtime_name="runc", sandbox_profile_id="api-r106-isolated",
        policy_revision="r099-v1", resource_limits={"timeout_seconds": 120},
        credential_classes=["synthetic-api-identity"], evidence_schemas=["api-differential-v1"],
        class_status="certified", author_user_id=f"author-{suffix}",
        reviewer_user_id=f"reviewer-{suffix}", **owned))
    await session.execute(insert(metadata.tables["runner_registrations"]).values(
        id=f"registration-r106-{suffix}", runner_id=runner_id, runner_class_record_id=runner_class_id,
        environment="local-conformance", network_plane="r106-owned-gateway",
        spiffe_id=f"spiffe://redagent.test/runner/{runner_id}", certificate_fingerprint="4" * 64,
        certificate_serial=f"serial-{suffix}", adapter_allowlist=["schemathesis:4.22.4-r106.1"],
        image_allowlist=[f"sha256:{EXPECTED_WHEEL_SHA256}"], required_policy_revision="r099-v1",
        generation=1, attestation_sha256="5" * 64, registration_state="active",
        registered_at=NOW, expires_at=NOW + timedelta(minutes=15),
        revoked_at=None, last_seen_at=NOW, **owned))
    quotas = ContainmentRepository(
        session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"quota-{suffix}",
    )
    for dimension, limit in (
        (QuotaDimension.TIME_SECONDS, 600), (QuotaDimension.OPERATIONS, 100),
        (QuotaDimension.CONCURRENCY, 10), (QuotaDimension.DATA_BYTES, 100 * 1024 * 1024),
    ):
        await quotas.register_quota_policy(QuotaPolicy(
            policy_id=f"quota-r106-{dimension.value}-{suffix}", tenant_id=tenant, revision=1,
            dimension=dimension, scope=ControlScope(ControlScopeKind.JOB, job_id),
            hard_limit=limit, window_seconds=3600,
            active_from=NOW - timedelta(minutes=1), active_until=NOW + timedelta(hours=1),
            extension_name=None,
        ), occurred_at=NOW)
