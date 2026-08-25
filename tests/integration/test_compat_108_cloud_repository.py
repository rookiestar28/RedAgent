from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.cloud_connectors.checks import SnapshotCheck, evaluate_snapshot
from redagent_platform.cloud_connectors.collector import CollectionSnapshot, SnapshotResource
from redagent_platform.cloud_connectors.compiler import compile_collection_plan
from redagent_platform.cloud_connectors.contracts import CollectionAuthorization, ProviderKind
from redagent_platform.cloud_connectors.profiles import emulator_profiles
from redagent_platform.cloud_connectors.provisioning import register_cloud_capability
from redagent_platform.cloud_connectors.repository import CloudRepository
from redagent_platform.persistence.database import load_database_settings


ROOT = Path(__file__).resolve().parents[2]


def test_r108_repository_persists_foundation_plan_result_cleanup_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    now = datetime(2026, 7, 12, tzinfo=timezone.utc)
    tenant = f"tenant-r108-{uuid4().hex[:8]}"
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    profile = emulator_profiles()[ProviderKind.AWS]
    permissions = tuple(item.action for item in profile.operations)
    authorization = CollectionAuthorization(
        tenant_id=tenant, policy_decision_id="decision-r108", policy_revision="r099-v1",
        reservation_id="reservation-r108", credential_lease_id="lease-r108",
        profile_id=profile.profile_id, effective_permissions=permissions,
        approved_permissions=permissions, approved_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=10),
    )
    compiled = compile_collection_plan(profile=profile, authorization=authorization, now=now)
    snapshot = CollectionSnapshot(
        identity=profile.expected_identity, collected_at=now, plan_sha256=compiled.plan_sha256,
        complete=True, partial_reasons=(), page_count=1, resource_count=1,
        resources=(SnapshotResource(
            resource_id="aws:123456789012:role/auditor",
            operation_id=profile.operations[0].operation_id,
            attributes={"mfa_required": True},
        ),), snapshot_sha256="5" * 64,
    )
    evaluation = evaluate_snapshot(
        snapshot=snapshot, control_pack_id="r108-cloud-baseline-v1",
        control_pack_sha256="3" * 64,
        checks=(SnapshotCheck(
            check_id="R108-AWS-001", operation_id=profile.operations[0].operation_id,
            attribute="mfa_required", expected=True, severity="high",
        ),), evaluated_at=now,
    )
    try:
        async with factory.begin() as session:
            registered = await register_cloud_capability(
                session, workspace=ROOT, tenant_id=tenant, actor_user_id="operator-r108",
                correlation_id="corr-r108-capability", occurred_at=now,
            )
            assert registered["capability_id"] == "cloud-posture"
            assert str(registered["image_digest"]).startswith("sha256:")
            repository = CloudRepository(session, tenant_id=tenant, actor_user_id="operator-r108", correlation_id="corr-r108")
            await repository.certify_foundation(source_sha256="a" * 64, occurred_at=now)
            await repository.store_plan(
                plan_id="plan-r108", binding_id="r108-aws-identity-v1",
                compiled=compiled, authorization=authorization, roe_version_id="roe-r108",
                occurred_at=now,
            )
            await repository.create_run(
                run_id="run-r108", plan_id="plan-r108", job_id="job-r108",
                runner_id="runner-r108", occurred_at=now,
            )
            completed = await repository.record_evaluation(
                run_id="run-r108", snapshot=snapshot, evaluation=evaluation, occurred_at=now,
            )
            assert completed["run_state"] == "succeeded"
            dashboard = await repository.dashboard()
            assert len(dashboard["profiles"]) == 4
            assert len(dashboard["runs"]) == 1
            assert len(dashboard["results"]) == 1
            assert dashboard["cleanups"][0]["residual_resource_count"] == 0
            assert len(dashboard["identity_options"]) == 4
            assert all(row["binding_state"] == "active-local-emulator" for row in dashboard["identity_options"])
            assert dashboard["runner_options"] == []
            assert dashboard["job_options"] == []
            assert dashboard["reservation_options"] == []
            assert dashboard["lease_options"] == []
        async with factory.begin() as session:
            other = await CloudRepository(
                session, tenant_id=f"other-{tenant}", actor_user_id="operator-r108", correlation_id="corr-r108-other",
            ).dashboard()
            assert all(not rows for rows in other.values())
    finally:
        await engine.dispose()
