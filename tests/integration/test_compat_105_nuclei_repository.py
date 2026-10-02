from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.containment_service.contracts import ControlScope, ControlScopeKind, QuotaDimension, QuotaPolicy
from redagent_platform.containment_service.repository import ContainmentRepository
from redagent_platform.nuclei_service.compiler import compile_nuclei_plan
from redagent_platform.nuclei_service.artifact_promotion import verify_current_nuclei_artifact_promotion
from redagent_platform.nuclei_service.contracts import (
    CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
    CURRENT_R105_TARGET_IMAGE_ID,
    R105_TARGET_SOURCE_SHA256,
    NucleiAuthorization,
    NucleiProfileId,
    NucleiTargetBinding,
)
from redagent_platform.nuclei_service.normalization import NormalizedNucleiResult
from redagent_platform.nuclei_service.promotion import verify_current_nuclei_bundle_promotion
from redagent_platform.nuclei_service.provisioning import register_nuclei_capability
from redagent_platform.nuclei_service.repository import NucleiRepository, NucleiRepositoryConflict
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.fromisoformat("2026-10-02T11:58:19.928804+00:00") + timedelta(minutes=1)


def test_nuclei_foundation_target_plan_run_result_cleanup_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r105-{suffix}"
    actor = f"operator-r105-{suffix}"
    job_id = f"job-r105-{suffix}"
    runner_id = f"runner-r105-{suffix}"
    plan_id = f"plan-r105-{suffix}"
    run_id = f"run-r105-{suffix}"
    promoted = verify_current_nuclei_bundle_promotion(
        manifest_bytes=(ROOT / "bundles/r105-nuclei/bundle-manifest-v3.json").read_bytes(),
        signature_bundle_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.sigstore.json").read_bytes(),
        public_key_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.pub").read_bytes(),
        template_bytes=(ROOT / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml").read_bytes(),
        certificate_bytes=(ROOT / "config/trust/r105-nuclei-user.crt").read_bytes(),
        qualification_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_RUNTIME_QUALIFICATION_V3.json").read_bytes(),
        now=NOW,
    )
    artifact_receipt, artifact_signature_sha = verify_current_nuclei_artifact_promotion(
        promotion_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.json").read_bytes(),
        signature_bundle_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.sigstore.json").read_bytes(),
        public_key_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.pub").read_bytes(),
        runtime_lock_bytes=(ROOT / "config/r105-nuclei-runtime-v3.json").read_bytes(),
        qualification_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_RUNTIME_QUALIFICATION_V3.json").read_bytes(),
        now=NOW,
    )
    target = NucleiTargetBinding(
        target_id="r105-owned-http-fixture", attestation_sha256="a" * 64,
        endpoint="http://redagent-r105-gateway:8080",
        allowed_paths=("/nuclei/missing-header",), network_id="redagent-r105-gateway-target",
        non_production=True, issued_at=NOW, expires_at=NOW + timedelta(minutes=15),
    )
    authorization = NucleiAuthorization(
        tenant_id=tenant, policy_decision_id=f"decision-r105-{suffix}", policy_revision="r099-v1",
        roe_version_id=f"roe-r105-{suffix}", approved_profile_ids=(NucleiProfileId.HTTP_HEADER,),
        approved_bundle_id=promoted.bundle_id, approved_at=NOW, expires_at=NOW + timedelta(minutes=10),
    )
    compiled = compile_nuclei_plan(profile_id=NucleiProfileId.HTTP_HEADER, bundle=promoted,
                                   target=target, authorization=authorization, now=NOW)
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=actor,
                                         correlation_id=f"bootstrap-{suffix}").bootstrap_tenant(
                                             name="compat_105 Nuclei Repository", occurred_at=NOW)
            registered = await register_nuclei_capability(
                session, workspace=ROOT, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"capability-{suffix}", occurred_at=NOW,
            )
            assert registered["capability_id"] == "nuclei-trusted-runtime"
            await _bootstrap_job_runner_and_quotas(session, tenant, actor, suffix, job_id, runner_id)
            repository = NucleiRepository(session, tenant_id=tenant, actor_user_id=actor,
                                          correlation_id=f"nuclei-{suffix}")
            foundation = await repository.ensure_certified_foundation(
                bundle=promoted, artifact_signature_sha256=artifact_signature_sha,
                artifact_provenance_sha256=artifact_receipt.provenance_sha256,
                bundle_signature_sha256=hashlib.sha256((ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.sigstore.json").read_bytes()).hexdigest(),
                occurred_at=NOW,
            )
            assert foundation["profile"]["profile_id"] == "nuclei-http-header-v1"
            replay = await repository.ensure_certified_foundation(
                bundle=promoted, artifact_signature_sha256=artifact_signature_sha,
                artifact_provenance_sha256=artifact_receipt.provenance_sha256,
                bundle_signature_sha256=hashlib.sha256((ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.sigstore.json").read_bytes()).hexdigest(),
                occurred_at=NOW,
            )
            assert replay["bundle"]["id"] == foundation["bundle"]["id"]
            await repository.register_target_attestation(
                attestation_id=f"attestation-r105-{suffix}", target=target,
                target_source_sha256=R105_TARGET_SOURCE_SHA256, target_image_id=CURRENT_R105_TARGET_IMAGE_ID,
                address_sha256="b" * 64, occurred_at=NOW,
            )
            plan = await repository.store_plan(plan_id=plan_id, compiled=compiled, target=target,
                                               authorization=authorization, occurred_at=NOW)
            attestations = metadata.tables["nuclei_target_attestations"]
            await session.execute(update(attestations).where(
                attestations.c.tenant_id == tenant,
                attestations.c.target_id == target.target_id,
            ).values(attestation_state="revoked"))
            with pytest.raises(NucleiRepositoryConflict, match="nuclei_target_revalidation_required"):
                await repository.create_run(run_id=run_id, plan_id=plan_id, job_id=job_id,
                                            runner_id=runner_id, occurred_at=NOW + timedelta(seconds=1))
            await session.execute(update(attestations).where(
                attestations.c.tenant_id == tenant,
                attestations.c.target_id == target.target_id,
            ).values(attestation_state="active"))
            decisions = metadata.tables["policy_decisions"]
            await session.execute(update(decisions).where(
                decisions.c.tenant_id == tenant,
                decisions.c.opa_decision_id == authorization.policy_decision_id,
            ).values(allowed=False))
            with pytest.raises(NucleiRepositoryConflict, match="nuclei_policy_revalidation_required"):
                await repository.create_run(run_id=run_id, plan_id=plan_id, job_id=job_id,
                                            runner_id=runner_id, occurred_at=NOW + timedelta(seconds=1))
            await session.execute(update(decisions).where(
                decisions.c.tenant_id == tenant,
                decisions.c.opa_decision_id == authorization.policy_decision_id,
            ).values(allowed=True))
            run = await repository.create_run(run_id=run_id, plan_id=plan_id, job_id=job_id,
                                              runner_id=runner_id, occurred_at=NOW + timedelta(seconds=1))
            assert plan["plan_sha256"] == compiled.plan_sha256
            assert run["run_state"] == "dispatch_pending"
            normalized = NormalizedNucleiResult(
                template_id="redagent-r105-missing-header", matcher_name="missing-security-header",
                title="compat_105 Missing Security Header", severity="low",
                affected_resource="/nuclei/missing-header", fingerprint="c" * 64,
                source_sha256="d" * 64,
            )
            result = await repository.record_result(
                run_id=run_id, result_id=f"result-r105-{suffix}", result=normalized,
                evidence_instance_id=f"evidence-r105-{suffix}", occurred_at=NOW + timedelta(seconds=2),
            )
            assert result["affected_resource"] == "/nuclei/missing-header"
            replay_result = await repository.record_result(
                run_id=run_id, result_id=f"result-r105-{suffix}", result=normalized,
                evidence_instance_id=f"evidence-r105-{suffix}", occurred_at=NOW + timedelta(seconds=2),
            )
            assert replay_result["id"] == result["id"]
            requested = await repository.request_cancel(
                run_id=run_id, expected_version=2, reason_code="operator_cancel_requested",
                occurred_at=NOW + timedelta(seconds=3),
            )
            assert requested["run_state"] == "cancel_requested"
            cancellation = await repository.record_cancellation(
                run_id=run_id, receipt_id=f"cancel-r105-{suffix}",
                native_stop_attempted=True, native_stop_acknowledged=True,
                lease_revoked=True, evidence_finalized=True, forced_termination=False,
                occurred_at=NOW + timedelta(seconds=4),
            )
            assert cancellation["native_stop_acknowledged"] is True
            issue_count = await session.scalar(select(func.count()).select_from(
                metadata.tables["issue_definitions"]).where(
                    metadata.tables["issue_definitions"].c.tenant_id == tenant,
                    metadata.tables["issue_definitions"].c.tool == "nuclei",
                ))
            finding_count = await session.scalar(select(func.count()).select_from(
                metadata.tables["finding_instances"]).where(
                    metadata.tables["finding_instances"].c.tenant_id == tenant,
                ))
            assert issue_count == 1 and finding_count == 1
            cleanup = await repository.record_cleanup(
                run_id=run_id, receipt_id=f"cleanup-r105-{suffix}", container_count=0,
                network_count=0, home_count=0, key_count=0, residual_resource_count=0,
                inventory_sha256="e" * 64, occurred_at=NOW + timedelta(seconds=5),
            )
            assert cleanup["cleanup_complete"] is True
        async with sessions() as session, session.begin():
            dashboard = await NucleiRepository(session, tenant_id=tenant, actor_user_id=actor,
                                               correlation_id=f"dashboard-{suffix}").dashboard()
            assert len(dashboard["profiles"]) == 1 and len(dashboard["results"]) == 1
            assert dashboard["runs"][0]["run_state"] == "cleaned"
            assert dashboard["target_options"][0]["target_id"] == "r105-owned-http-fixture"
            assert [row["runner_id"] for row in dashboard["runner_options"]] == [runner_id]
            assert [row["id"] for row in dashboard["job_options"]] == [job_id]
            other = await NucleiRepository(session, tenant_id=f"other-{suffix}", actor_user_id=actor,
                                           correlation_id=f"other-{suffix}").dashboard()
            assert all(not rows for rows in other.values())
    finally:
        await engine.dispose()


async def _bootstrap_job_runner_and_quotas(session, tenant: str, actor: str, suffix: str,
                                           job_id: str, runner_id: str) -> None:
    owned = {"tenant_id": tenant, "version": 1, "created_at": NOW, "updated_at": NOW}
    engagement_id = f"engagement-r105-{suffix}"
    roe_id = f"roe-r105-{suffix}"
    runner_class_id = f"runner-class-r105-{suffix}"
    await session.execute(insert(metadata.tables["engagements"]).values(
        id=engagement_id, name="compat_105 owned fixture", owner_user_id=actor, **owned))
    await session.execute(insert(metadata.tables["roe_versions"]).values(
        id=roe_id, engagement_id=engagement_id, revision=1, status="approved",
        document={"target": "r105-owned-http-fixture"}, **owned))
    await session.execute(insert(metadata.tables["policy_decisions"]).values(
        id=f"policy-decision-r105-{suffix}", opa_decision_id=f"decision-r105-{suffix}",
        bundle_revision="r099-v1", input_hash="8" * 64, boundary="runner",
        action="nuclei.plan.compile", subject_id=actor, resource_type="nuclei_profile",
        resource_id="nuclei-http-header-v1", resource_version=1, allowed=True,
        reason_code="r105_profile_approved", obligations=["owned_fixture_only"],
        issued_at=NOW, valid_until=NOW + timedelta(minutes=15),
        correlation_id=f"policy-r105-{suffix}", **owned))
    await session.execute(insert(metadata.tables["jobs"]).values(
        id=job_id, engagement_id=engagement_id, roe_version_id=roe_id,
        created_by_user_id=actor, campaign_id=None, status="approved",
        request={"capability": "nuclei-trusted-runtime", "approval_timeout_seconds": 600,
                 "max_activity_attempts": 1, "budget_reference": f"budget-r105-{suffix}"},
        policy_reference="policy:r099-v1", workflow_id=f"workflow-r105-{suffix}",
        workflow_run_id=f"workflow-run-r105-{suffix}", orchestration_state="ready",
        orchestration_revision=1, current_gate="runner_dispatch", failure_code=None,
        retry_count=0, dispatch_blocked=False, stop_requested=False, **owned))
    await session.execute(insert(metadata.tables["runner_classes"]).values(
        id=runner_class_id, class_id=f"nuclei-r105-{suffix}", class_revision=1,
        environment="local-conformance", network_plane="r105-owned-gateway",
        isolation_tier="container", runtime_name="runc", sandbox_profile_id="nuclei-r105-isolated",
        policy_revision="r099-v1", resource_limits={"timeout_seconds": 60},
        credential_classes=["none"], evidence_schemas=["nuclei-result-v1"],
        class_status="certified", author_user_id=f"author-{suffix}",
        reviewer_user_id=f"reviewer-{suffix}", **owned))
    await session.execute(insert(metadata.tables["runner_registrations"]).values(
        id=f"registration-r105-{suffix}", runner_id=runner_id, runner_class_record_id=runner_class_id,
        environment="local-conformance", network_plane="r105-owned-gateway",
        spiffe_id=f"spiffe://redagent.test/runner/{runner_id}", certificate_fingerprint="f" * 64,
        certificate_serial=f"serial-{suffix}", adapter_allowlist=["nuclei-service:3.11.1-r105.3"],
        image_allowlist=[CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"]],
        required_policy_revision="r099-v1", generation=1, attestation_sha256="9" * 64,
        registration_state="active", registered_at=NOW, expires_at=NOW + timedelta(minutes=10),
        revoked_at=None, last_seen_at=NOW, **owned))
    quotas = ContainmentRepository(session, tenant_id=tenant, actor_user_id=actor,
                                   correlation_id=f"quota-{suffix}")
    for dimension, limit in (
        (QuotaDimension.TIME_SECONDS, 600), (QuotaDimension.OPERATIONS, 60),
        (QuotaDimension.CONCURRENCY, 10), (QuotaDimension.DATA_BYTES, 100 * 1024 * 1024),
    ):
        await quotas.register_quota_policy(QuotaPolicy(
            policy_id=f"quota-r105-{dimension.value}-{suffix}", tenant_id=tenant, revision=1,
            dimension=dimension, scope=ControlScope(ControlScopeKind.JOB, job_id),
            hard_limit=limit, window_seconds=3600, active_from=NOW - timedelta(minutes=1),
            active_until=NOW + timedelta(hours=1), extension_name=None,
        ), occurred_at=NOW)
