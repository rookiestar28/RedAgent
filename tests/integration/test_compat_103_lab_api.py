from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.lab_service.contracts import (
    LAB_SCHEMA, FixtureKind, LabBundleManifest, TestClass as LabTestClass,
)
from redagent_platform.lab_service.repository import LabRepository
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 11, 14, 0, tzinfo=timezone.utc)


def test_lab_dashboard_is_permission_guarded_and_never_accepts_arbitrary_targets() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r103-api-{suffix}"
    operator = f"operator-{suffix}"
    manifest = LabBundleManifest(
        schema=LAB_SCHEMA, bundle_id=f"bundle-{suffix}", revision=1,
        fixture_digest="sha256:" + "8" * 64, seed_manifest_sha256="9" * 64,
        fixture_kinds=tuple(FixtureKind), allowed_test_classes=tuple(LabTestClass),
        network_id="redagent-r103-lab", non_production=True,
        created_at=NOW, expires_at=NOW + timedelta(hours=2),
    )
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"bootstrap-{suffix}",
            ).bootstrap_tenant(name="compat_103 dashboard", occurred_at=NOW)
            await LabRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"lab-{suffix}",
            ).register_bundle(manifest, occurred_at=NOW)
    finally:
        await engine.dispose()

    app = create_app(test_issuer_enabled=True, database_settings=settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://testserver",
        ) as client:
            allowed = await client.get("/api/v1/lab/dashboard", headers={
                "X-RedAgent-Test-Tenant": tenant,
                "X-RedAgent-Test-Subject": operator,
                "X-RedAgent-Test-Permissions": "audit:read",
            })
            assert allowed.status_code == 200, allowed.text
            data = allowed.json()["data"]
            assert data["bundle"]["bundle_id"] == manifest.bundle_id
            assert data["arbitrary_target_input_allowed"] is False
            assert data["emergency_stop_path"] == "/jobs/{job_id}/emergency-stop"
            denied = await client.get("/api/v1/lab/dashboard", headers={
                "X-RedAgent-Test-Tenant": tenant,
                "X-RedAgent-Test-Subject": operator,
                "X-RedAgent-Test-Permissions": "job:read",
            })
            assert denied.status_code == 403
            arbitrary = await client.post("/api/v1/lab/dashboard", headers={
                "X-RedAgent-Test-Tenant": tenant,
                "X-RedAgent-Test-Subject": operator,
                "X-RedAgent-Test-Permissions": "audit:read",
            }, json={"target": "https://example.com"})
            assert arbitrary.status_code == 405
