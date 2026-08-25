from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.identity_saas.compiler import compile_identity_plan
from redagent_platform.identity_saas.contracts import IdentityAuthorization, IdentityProvider
from redagent_platform.identity_saas.profiles import emulator_profiles
from redagent_platform.identity_saas.provisioning import register_identity_capability
from redagent_platform.identity_saas.repository import IdentitySaasRepository
from redagent_platform.persistence.database import load_database_settings


ROOT = Path(__file__).resolve().parents[2]


def test_r109_repository_persists_foundation_plan_run_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    now = datetime(2026, 7, 12, tzinfo=timezone.utc); tenant = f"tenant-r109-{uuid4().hex[:8]}"
    settings = load_database_settings(ROOT, env=os.environ); engine = create_async_engine(settings.url); factory = async_sessionmaker(engine, expire_on_commit=False)
    profile = emulator_profiles()[IdentityProvider.OKTA]
    authorization = IdentityAuthorization(authorization_id="authorization-r109", policy_decision_id="decision-r109", policy_revision="r109-v1",
        reservation_id="reservation-r109", credential_lease_id="lease-r109", tenant_id=profile.tenant_id, audience=profile.audience,
        consent_mode=profile.consent_mode, granted_scopes=tuple(item.permission_scope for item in profile.operations),
        effective_role_permissions=tuple(item.effective_role_permission for item in profile.operations), approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    compiled = compile_identity_plan(profile=profile, authorization=authorization, now=now)
    try:
        async with factory.begin() as session:
            registered = await register_identity_capability(session, workspace=ROOT, tenant_id=tenant, actor_user_id="operator-r109", correlation_id="corr-r109-capability", occurred_at=now)
            assert registered["capability_id"] == "identity-posture"
            repository = IdentitySaasRepository(session, tenant_id=tenant, actor_user_id="operator-r109", correlation_id="corr-r109")
            await repository.certify_foundation(source_sha256="a" * 64, occurred_at=now)
            await repository.store_plan(plan_id="plan-r109", binding_id="r109-okta-binding-v1", compiled=compiled, authorization=authorization, occurred_at=now)
            await repository.create_run(run_id="run-r109", plan_id="plan-r109", job_id="job-r109", runner_id="runner-r109", occurred_at=now)
            dashboard = await repository.dashboard(); assert len(dashboard["profiles"]) == 3 and len(dashboard["runs"]) == 1
            assert len(dashboard["binding_options"]) == 3
            assert all(row["binding_state"] == "active-local-emulator" for row in dashboard["binding_options"])
            assert dashboard["runner_options"] == []
            assert dashboard["job_options"] == []
            assert dashboard["reservation_options"] == []
            assert dashboard["lease_options"] == []
        async with factory.begin() as session:
            other = await IdentitySaasRepository(session, tenant_id=f"other-{tenant}", actor_user_id="operator-r109", correlation_id="corr-r109-other").dashboard()
            assert all(not rows for rows in other.values())
    finally: await engine.dispose()
