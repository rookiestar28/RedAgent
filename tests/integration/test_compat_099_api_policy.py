from __future__ import annotations

import asyncio
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider


ROOT = Path(__file__).resolve().parents[2]


def test_api_permission_is_rechecked_by_policy_and_persists_boundary_receipt() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r099-api-{suffix}"
    app = create_app(
        database_settings=settings,
        test_issuer_enabled=True,
        policy_provider=DeterministicFakePolicyProvider(revision="synthetic-r099-v1"),
        policy_required_revision="synthetic-r099-v1",
    )
    headers = {
        "X-RedAgent-Test-Subject": f"operator-r099-{suffix}",
        "X-RedAgent-Test-Tenant": tenant,
        "X-RedAgent-Test-Permissions": "engagement:read",
        "X-Correlation-ID": f"api-r099-{suffix}",
    }
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/api/v1/engagements", headers=headers)
            status = await client.get("/api/v1/policy/status", headers={
                **headers, "X-RedAgent-Test-Permissions": "policy:read",
            })
            simulation = await client.post(
                "/api/v1/policy/simulations",
                headers={
                    **headers, "X-RedAgent-Test-Permissions": "policy:simulate",
                    "X-RedAgent-Policy-Reference": "policy:compat_099:simulation",
                    "Idempotency-Key": f"simulate-{suffix}",
                },
                json={"fixture": "evidence-write"},
            )
        assert response.status_code == 200, response.text
        assert status.status_code == 200, status.text
        assert status.json()["data"]["required_revision"] == "synthetic-r099-v1"
        assert simulation.status_code == 200, simulation.text
        assert simulation.json()["data"]["fixture"] == "evidence-write"

    engine = create_async_engine(settings.url, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                await connection.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
                decisions = await connection.scalar(select(func.count()).select_from(metadata.tables["policy_decisions"]).where(
                    metadata.tables["policy_decisions"].c.tenant_id == tenant,
                    metadata.tables["policy_decisions"].c.boundary == "api",
                ))
                receipts = await connection.scalar(select(func.count()).select_from(metadata.tables["policy_boundary_receipts"]).where(
                    metadata.tables["policy_boundary_receipts"].c.tenant_id == tenant,
                    metadata.tables["policy_boundary_receipts"].c.boundary == "api",
                ))
                evidence_receipts = await connection.scalar(select(func.count()).select_from(metadata.tables["policy_boundary_receipts"]).where(
                    metadata.tables["policy_boundary_receipts"].c.tenant_id == tenant,
                    metadata.tables["policy_boundary_receipts"].c.boundary == "evidence",
                ))
                assert decisions == 3 and receipts == 3 and evidence_receipts == 1
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()
