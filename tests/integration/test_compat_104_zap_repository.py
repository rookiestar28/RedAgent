from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.containment_service.contracts import (
    ControlScope,
    ControlScopeKind,
    QuotaDimension,
    QuotaPolicy,
)
from redagent_platform.containment_service.repository import ContainmentRepository
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.zap_service.compiler import compile_zap_plan
from redagent_platform.zap_service.contracts import (
    ApprovalClass,
    CertifiedProfileId,
    CURRENT_R104_TARGET_IMAGE_ID,
    R104_TARGET_SOURCE_SHA256,
    ZapAuthorization,
    ZapTargetBinding,
)
from redagent_platform.zap_service.repository import ZapRepository, ZapRepositoryConflict
from redagent_platform.zap_service.provisioning import register_zap_capability


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.fromisoformat("2026-10-02T11:58:19.928804+00:00") + timedelta(minutes=1)
IMAGE = "sha256:3cd55809bfea0393bc67862eec614091faa873cfb219d28465122f04ae8d266b"


def test_zap_profile_plan_run_cancel_audit_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r104-{suffix}"
    actor = f"operator-r104-{suffix}"
    plan_id = f"plan-r104-{suffix}"
    run_id = f"run-r104-{suffix}"
    job_id = f"job-r104-{suffix}"
    runner_id = f"runner-r104-{suffix}"
    target = ZapTargetBinding(
        target_id="r104-owned-web-fixture", attestation_sha256="a" * 64,
        endpoint="http://redagent-r104-gateway:8080",
        allowed_paths=("/passive/missing-header",),
        network_id="redagent-r104-gateway-target", non_production=True,
        issued_at=NOW, expires_at=NOW + timedelta(minutes=15),
    )
    authorization = ZapAuthorization(
        tenant_id=tenant, policy_decision_id=f"decision-r104-{suffix}",
        policy_revision="r099-v1", roe_version_id=f"roe-r104-{suffix}",
        approval_class=ApprovalClass.LOW_RISK,
        approved_profile_ids=(CertifiedProfileId.PASSIVE,), credential_reference_ids=(),
        approved_at=NOW, expires_at=NOW + timedelta(minutes=10),
    )
    compiled = compile_zap_plan(
        profile_id=CertifiedProfileId.PASSIVE, target=target,
        authorization=authorization, now=NOW,
    )
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}",
            ).bootstrap_tenant(name="compat_104 ZAP Repository", occurred_at=NOW)
            await _bootstrap_job_and_runner(
                session, tenant=tenant, actor=actor, suffix=suffix,
                job_id=job_id, runner_id=runner_id,
            )
            await register_zap_capability(
                session, workspace=ROOT, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"capability-{suffix}", occurred_at=NOW,
            )
            quotas = ContainmentRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"quota-{suffix}",
            )
            for dimension, limit in (
                (QuotaDimension.TIME_SECONDS, 600), (QuotaDimension.OPERATIONS, 60),
                (QuotaDimension.CONCURRENCY, 10), (QuotaDimension.DATA_BYTES, 100 * 1024 * 1024),
            ):
                await quotas.register_quota_policy(QuotaPolicy(
                    policy_id=f"quota-r104-{dimension.value}-{suffix}", tenant_id=tenant, revision=1,
                    dimension=dimension, scope=ControlScope(ControlScopeKind.JOB, job_id),
                    hard_limit=limit, window_seconds=3600,
                    active_from=NOW - timedelta(minutes=1), active_until=NOW + timedelta(hours=1),
                    extension_name=None,
                ), occurred_at=NOW)
        async with sessions() as session, session.begin():
            repository = ZapRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"zap-{suffix}",
            )
            profiles = await repository.ensure_certified_profiles(occurred_at=NOW)
            assert len(profiles) == 4
            await repository.register_target_attestation(
                attestation_id=f"attestation-r104-{suffix}", target=target,
                target_source_sha256=R104_TARGET_SOURCE_SHA256,
                target_image_id=CURRENT_R104_TARGET_IMAGE_ID, address_sha256="e" * 64,
                occurred_at=NOW,
            )
            plan = await repository.store_plan(
                plan_id=plan_id, compiled=compiled, target=target,
                authorization=authorization, occurred_at=NOW,
            )
            replay = await repository.store_plan(
                plan_id=plan_id, compiled=compiled, target=target,
                authorization=authorization, occurred_at=NOW,
            )
            assert replay["id"] == plan["id"]
            run = await repository.create_run(
                run_id=run_id, plan_id=plan_id, job_id=job_id,
                runner_id=runner_id, occurred_at=NOW + timedelta(seconds=1),
            )
            cancelled = await repository.request_cancel(
                run_id=run_id, expected_version=1,
                reason_code="operator_cancel_requested", occurred_at=NOW + timedelta(seconds=2),
            )
            assert run["run_state"] == "dispatch_pending"
            assert run["reason_code"] == "zap_run_accepted"
            assert cancelled["run_state"] == "cancel_requested" and cancelled["version"] == 2
            denied = await repository.create_run(
                run_id=f"run-r104-denied-{suffix}", plan_id=plan_id, job_id=job_id,
                runner_id=runner_id, occurred_at=NOW + timedelta(seconds=3),
            )
            assert denied["run_state"] == "quota_denied"
            assert denied["reason_code"] == "hard_quota_exceeded"
            with pytest.raises(ZapRepositoryConflict, match="zap_run_version_conflict"):
                await repository.request_cancel(
                    run_id=run_id, expected_version=1,
                    reason_code="operator_cancel_requested", occurred_at=NOW + timedelta(seconds=3),
                )
            cancellation = await repository.record_cancellation(
                run_id=run_id, receipt_id=f"cancel-r104-{suffix}",
                native_stop_attempted=True, native_stop_acknowledged=True,
                lease_revoked=True, evidence_finalized=True, forced_termination=False,
                occurred_at=NOW + timedelta(seconds=4),
            )
            assert cancellation["native_stop_acknowledged"] is True
            cleanup = await repository.record_cleanup(
                run_id=run_id, receipt_id=f"cleanup-r104-{suffix}",
                container_count=0, network_count=0, home_count=0,
                key_count=0, credential_count=0, residual_resource_count=0,
                inventory_sha256="d" * 64, occurred_at=NOW + timedelta(seconds=5),
            )
            assert cleanup["cleanup_complete"] is True
            reserved = await session.scalar(select(func.coalesce(
                func.sum(metadata.tables["quota_usage"].c.reserved_amount), 0,
            )).where(metadata.tables["quota_usage"].c.tenant_id == tenant))
            assert int(reserved or 0) == 0
            after_release = await repository.create_run(
                run_id=f"run-r104-released-{suffix}", plan_id=plan_id, job_id=job_id,
                runner_id=runner_id, occurred_at=NOW + timedelta(seconds=6),
            )
            assert after_release["run_state"] == "containment_denied"
            assert after_release["reason_code"] == "zap_containment_active"
        async with sessions() as session, session.begin():
            dashboard = await ZapRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"dashboard-{suffix}",
            ).dashboard()
            assert len(dashboard["profiles"]) == 4
            assert [row["plan_id"] for row in dashboard["plans"]] == [plan_id]
            assert {row["run_id"] for row in dashboard["runs"]} == {
                run_id, f"run-r104-denied-{suffix}", f"run-r104-released-{suffix}",
            }
            assert dashboard["cleanups"][0]["cleanup_complete"] is True
            assert [(row["target_id"], row["attestation_sha256"]) for row in dashboard["target_options"]] == [
                ("r104-owned-web-fixture", "a" * 64),
            ]
            assert [row["runner_id"] for row in dashboard["runner_options"]] == [runner_id]
        async with sessions() as session, session.begin():
            other = await ZapRepository(
                session, tenant_id=f"other-r104-{suffix}", actor_user_id=actor,
                correlation_id=f"other-{suffix}",
            ).dashboard()
            assert other == {
                "profiles": [], "plans": [], "runs": [], "cleanups": [],
                "target_options": [], "runner_options": [],
            }
    finally:
        await engine.dispose()


async def _bootstrap_job_and_runner(
    session, *, tenant: str, actor: str, suffix: str, job_id: str, runner_id: str,
) -> None:
    owned = {"tenant_id": tenant, "version": 1, "created_at": NOW, "updated_at": NOW}
    engagement_id = f"engagement-r104-{suffix}"
    roe_id = f"roe-r104-{suffix}"
    runner_class_id = f"runner-class-r104-{suffix}"
    await session.execute(insert(metadata.tables["engagements"]).values(
        id=engagement_id, name="compat_104 owned web fixture", owner_user_id=actor, **owned,
    ))
    await session.execute(insert(metadata.tables["roe_versions"]).values(
        id=roe_id, engagement_id=engagement_id, revision=1, status="approved",
        document={"target": "r104-owned-web-fixture"}, **owned,
    ))
    await session.execute(insert(metadata.tables["jobs"]).values(
        id=job_id, engagement_id=engagement_id, roe_version_id=roe_id,
        created_by_user_id=actor, campaign_id=None, status="approved",
        request={
            "capability": "zap-controlled-runtime", "approval_timeout_seconds": 600,
            "max_activity_attempts": 1, "budget_reference": f"budget-r104-{suffix}",
        },
        policy_reference="policy:r099-v1", workflow_id=f"workflow-r104-{suffix}",
        workflow_run_id=f"workflow-run-r104-{suffix}", orchestration_state="ready",
        orchestration_revision=1, current_gate="runner_dispatch", failure_code=None,
        retry_count=0, dispatch_blocked=False, stop_requested=False, **owned,
    ))
    await session.execute(insert(metadata.tables["runner_classes"]).values(
        id=runner_class_id, class_id=f"zap-r104-{suffix}", class_revision=1,
        environment="local-conformance", network_plane="r104-owned-gateway",
        isolation_tier="container", runtime_name="runc", sandbox_profile_id="zap-r104-isolated",
        policy_revision="r099-v1", resource_limits={"timeout_seconds": 300},
        credential_classes=["http_header"], evidence_schemas=["zap-alert-v1"],
        class_status="certified", author_user_id=f"author-{suffix}",
        reviewer_user_id=f"reviewer-{suffix}", **owned,
    ))
    await session.execute(insert(metadata.tables["runner_registrations"]).values(
        id=f"registration-r104-{suffix}", runner_id=runner_id,
        runner_class_record_id=runner_class_id, environment="local-conformance",
        network_plane="r104-owned-gateway", spiffe_id=f"spiffe://redagent.test/runner/{runner_id}",
        certificate_fingerprint="b" * 64, certificate_serial=f"serial-{suffix}",
        adapter_allowlist=["zap-service:2.17.0-r104.3"], image_allowlist=[IMAGE],
        required_policy_revision="r099-v1", generation=1, attestation_sha256="c" * 64,
        registration_state="active", registered_at=NOW,
        expires_at=NOW + timedelta(minutes=10), revoked_at=None, last_seen_at=NOW, **owned,
    ))
