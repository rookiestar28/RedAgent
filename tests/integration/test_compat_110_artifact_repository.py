from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.artifact_pipeline.compiler import compile_artifact_plan
from redagent_platform.artifact_pipeline.contracts import ArtifactAuthorization
from redagent_platform.artifact_pipeline.profiles import certified_profiles
from redagent_platform.artifact_pipeline.provisioning import register_artifact_capability
from redagent_platform.artifact_pipeline.repository import ArtifactPipelineRepository
from redagent_platform.persistence.database import load_database_settings


ROOT = Path(__file__).resolve().parents[2]


def test_r110_repository_persists_foundation_plan_run_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    now = datetime(2026, 7, 12, tzinfo=timezone.utc); tenant = f"tenant-r110-{uuid4().hex[:8]}"; profile = certified_profiles()["r110-repository-snapshot-v1"]
    authorization = ArtifactAuthorization(authorization_id="authorization-r110", policy_decision_id="decision-r110", policy_revision="r110-v1", reservation_id="reservation-r110",
        artifact_lease_id="lease-r110", artifact_binding_id="binding-r110", artifact_sha256="a" * 64, artifact_kind=profile.artifact_kind, manifest_sha256="b" * 64,
        profile_id=profile.profile_id, stage_ids=tuple(item.value for item in profile.stages), approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    compiled = compile_artifact_plan(profile=profile, authorization=authorization, now=now); settings = load_database_settings(ROOT, env=os.environ); engine = create_async_engine(settings.url); factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory.begin() as session:
            registered = await register_artifact_capability(session, workspace=ROOT, tenant_id=tenant, actor_user_id="operator-r110", correlation_id="corr-r110-capability", occurred_at=now); assert registered["capability_id"] == "artifact-posture"
            repository = ArtifactPipelineRepository(session, tenant_id=tenant, actor_user_id="operator-r110", correlation_id="corr-r110")
            await repository.certify_foundation(source_sha256="c" * 64, occurred_at=now)
            await repository.register_binding(binding_id="binding-r110", compiled=compiled, declared_files=1, declared_bytes=128, expires_at=authorization.expires_at, occurred_at=now)
            await repository.store_plan(plan_id="plan-r110", compiled=compiled, authorization=authorization, occurred_at=now)
            await repository.create_run(run_id="run-r110", plan_id="plan-r110", job_id="job-r110", runner_id="runner-r110", occurred_at=now)
            dashboard = await repository.dashboard(); assert len(dashboard["profiles"]) == 3 and len(dashboard["runs"]) == 1 and dashboard["runs"][0]["untrusted_execution_count"] == 0
            assert len(dashboard["binding_options"]) == 1
            assert dashboard["binding_options"][0]["binding_state"] == "active-canonical-fixture"
            assert dashboard["runner_options"] == [] and dashboard["job_options"] == [] and dashboard["reservation_options"] == []
        async with factory.begin() as session:
            other = await ArtifactPipelineRepository(session, tenant_id=f"other-{tenant}", actor_user_id="operator-r110", correlation_id="corr-r110-other").dashboard(); assert all(not rows for rows in other.values())
    finally: await engine.dispose()
