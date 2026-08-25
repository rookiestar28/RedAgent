from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

import httpx

from redagent_platform.api.app import create_app
from redagent_platform.persistence.database import load_database_settings


ROOT = Path(__file__).resolve().parents[2]


def test_runner_operational_api_is_tenant_scoped_read_only_and_metadata_only() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    tenant = f"tenant-r100-api-{uuid4().hex[:10]}"
    app = create_app(test_issuer_enabled=True, database_settings=settings)
    headers = {
        "X-RedAgent-Test-Subject": "runner-observer-1",
        "X-RedAgent-Test-Tenant": tenant,
        "X-RedAgent-Test-Permissions": "runner:read",
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client:
            status = await client.get("/api/v1/runners/status", headers=headers)
            registrations = await client.get("/api/v1/runners/registrations", headers=headers)
            manifests = await client.get("/api/v1/runner-manifests", headers=headers)
            executions = await client.get("/api/v1/runner-executions", headers=headers)
            denied = await client.get("/api/v1/runners/status", headers={**headers, "X-RedAgent-Test-Permissions": "job:read"})

    assert status.status_code == 200, status.text
    assert status.json()["data"]["registration_count"] == 0
    for response in (registrations, manifests, executions):
        assert response.status_code == 200, response.text
        assert response.json()["data"] == []
    assert denied.status_code == 403
    openapi = app.openapi()
    runner_schemas = {
        name: schema for name, schema in openapi["components"]["schemas"].items()
        if name.startswith("Runner")
    }
    # IMPORTANT: runner metadata must stay secret-free, while unrelated domains
    # may legitimately use similarly named attestation identifiers.
    rendered = json.dumps(runner_schemas, sort_keys=True).lower()
    for forbidden in (
        "manifest_document", "signature", "lease_token", "certificate_fingerprint",
        "certificate_serial", "spiffe_id", "attestation_sha256", "nonce_hash",
    ):
        assert forbidden not in rendered
