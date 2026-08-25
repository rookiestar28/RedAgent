from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.zap_service.contracts import CURRENT_R104_TARGET_IMAGE_ID
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.now(timezone.utc)


def test_zap_profiles_compile_dashboard_permissions_and_closed_input() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r104-api-{suffix}"
    actor = f"operator-r104-{suffix}"
    roe_id = f"roe-r104-{suffix}"
    profile_id = "zap-passive-v1"
    decision_id = f"decision-r104-{suffix}"
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}",
            ).bootstrap_tenant(name="compat_104 ZAP API", occurred_at=NOW)
            owned = {"tenant_id": tenant, "version": 1, "created_at": NOW, "updated_at": NOW}
            engagement_id = f"engagement-r104-{suffix}"
            await session.execute(insert(metadata.tables["engagements"]).values(
                id=engagement_id, name="compat_104 API fixture", owner_user_id=actor, **owned,
            ))
            await session.execute(insert(metadata.tables["roe_versions"]).values(
                id=roe_id, engagement_id=engagement_id, revision=1, status="approved",
                document={"target": "r104-owned-web-fixture"}, **owned,
            ))
            await session.execute(insert(metadata.tables["policy_decisions"]).values(
                id=f"policy-decision-{suffix}", opa_decision_id=decision_id,
                bundle_revision="r099-v1", input_hash="a" * 64, boundary="api",
                action="zap.plan.compile", subject_id=actor, resource_type="zap_profile",
                resource_id=profile_id, resource_version=1, allowed=True,
                reason_code="r104_profile_approved", obligations=["owned_fixture_only"],
                issued_at=NOW, valid_until=NOW + timedelta(minutes=15),
                correlation_id=f"seed-{suffix}", **owned,
            ))
            await session.execute(insert(metadata.tables["zap_target_attestations"]).values(
                id=f"zap-target-{suffix}", attestation_id=f"attestation-r104-{suffix}",
                target_id="r104-owned-web-fixture",
                target_source_sha256="eadf76b79ea4b64f956cac5f6dc5e004990405f4f4504997fe43002768b7e493",
                target_image_id=CURRENT_R104_TARGET_IMAGE_ID,
                network_id="redagent-r104-gateway-target", container_name="redagent-r104-target",
                address_sha256="c" * 64, endpoint="http://redagent-r104-gateway:8080",
                allowed_paths=["/passive/missing-header"], attestation_sha256="b" * 64,
                non_production=True, attestation_state="active",
                issued_at=NOW, expires_at=NOW + timedelta(minutes=15), **owned,
            ))
    finally:
        await engine.dispose()

    app = create_app(
        database_settings=settings, test_issuer_enabled=True,
        policy_provider=DeterministicFakePolicyProvider(revision="r099-v1"),
        policy_required_revision="r099-v1",
    )
    base = {
        "X-RedAgent-Test-Subject": actor,
        "X-RedAgent-Test-Tenant": tenant,
        "X-Correlation-ID": f"api-r104-{suffix}",
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://testserver",
        ) as client:
            profiles = await client.get("/api/v1/zap/profiles", headers={
                **base, "X-RedAgent-Test-Permissions": "job:read",
            })
            assert profiles.status_code == 200, profiles.text
            assert {row["profile_id"] for row in profiles.json()["data"]} == {
                "zap-passive-v1", "zap-auth-crawl-v1",
                "zap-client-spider-v1", "zap-active-xss-lab-v1",
            }
            payload = {
                "plan_id": f"plan-r104-{suffix}", "profile_id": profile_id,
                "target_id": "r104-owned-web-fixture",
                "target_attestation_sha256": "b" * 64,
                "policy_decision_id": decision_id, "policy_revision": "r099-v1",
                "roe_version_id": roe_id, "credential_reference_ids": [],
            }
            compiled = await client.post("/api/v1/zap/plans", headers={
                **base, "X-RedAgent-Test-Permissions": "job:create",
                "X-RedAgent-Policy-Reference": "policy:compat_104:compile",
                "X-RedAgent-ROE-Version": roe_id, "Idempotency-Key": f"compile-{suffix}",
            }, json=payload)
            assert compiled.status_code == 201, compiled.text
            assert compiled.json()["data"]["profile_id"] == profile_id
            assert len(compiled.json()["data"]["plan_sha256"]) == 64
            dashboard = await client.get("/api/v1/zap/dashboard", headers={
                **base, "X-RedAgent-Test-Permissions": "audit:read",
            })
            assert dashboard.status_code == 200, dashboard.text
            assert dashboard.json()["data"]["plans"][0]["plan_id"] == payload["plan_id"]
            assert dashboard.json()["data"]["target_options"] == [{
                "target_id": "r104-owned-web-fixture", "attestation_sha256": "b" * 64,
                "attestation_state": "active", "non_production": True,
                "expires_at": (NOW + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
            }]
            assert dashboard.json()["data"]["runner_options"] == []
            denied = await client.get("/api/v1/zap/profiles", headers={
                **base, "X-RedAgent-Test-Permissions": "audit:read",
            })
            assert denied.status_code == 403
            arbitrary = await client.post("/api/v1/zap/plans", headers={
                **base, "X-Correlation-ID": f"api-r104-bad-{suffix}",
                "X-RedAgent-Test-Permissions": "job:create",
                "X-RedAgent-Policy-Reference": "policy:compat_104:compile",
                "X-RedAgent-ROE-Version": roe_id, "Idempotency-Key": f"bad-{suffix}",
            }, json={**payload, "url": "https://example.com"})
            assert arbitrary.status_code == 422, arbitrary.text
