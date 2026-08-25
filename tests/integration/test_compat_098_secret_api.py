from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.secret_service.fakes import DeterministicFakeSecretProvider


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)


def test_live_secret_api_is_metadata_only_tenant_scoped_idempotent_and_revocable() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant, actor = f"tenant-secret-api-{suffix}", f"operator-secret-api-{suffix}"
    engagement, roe, job = f"eng-secret-api-{suffix}", f"roe-secret-api-{suffix}", f"job-secret-api-{suffix}"
    try:
        await _bootstrap(sessions, tenant, actor, engagement, roe, job, suffix)
        app = create_app(
            test_issuer_enabled=True, database_settings=settings,
            secret_provider=DeterministicFakeSecretProvider(seed=suffix), synthetic_secret_enabled=True,
        )
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://testserver",
            ) as client:
                payload = {
                    "reference_id": f"reference-secret-api-{suffix}", "lease_id": f"lease-secret-api-{suffix}",
                    "engagement_id": engagement, "job_id": job,
                    "workload_client_id": f"client-secret-api-{suffix}", "ttl_seconds": 300,
                }
                issue_headers = _mutation_headers(tenant, actor, "secret:issue", f"issue-{suffix}", roe)
                issued = await client.post("/api/v1/secret-leases/synthetic", headers=issue_headers, json=payload)
                replayed = await client.post("/api/v1/secret-leases/synthetic", headers=issue_headers, json=payload)
                assert issued.status_code == 201, issued.text
                assert replayed.status_code == 201, replayed.text
                assert replayed.json()["meta"]["replayed"] is True
                rendered = json.dumps(issued.json(), sort_keys=True).lower()
                for forbidden in ("password", "credential", "token", "role_reference", "provider_lease_reference", "issue_path"):
                    assert forbidden not in rendered

                references = await client.get("/api/v1/secret-references", headers=_read_headers(tenant, actor))
                leases = await client.get("/api/v1/secret-leases", headers=_read_headers(tenant, actor))
                assert references.status_code == 200 and references.json()["page"]["returned"] == 1
                assert leases.status_code == 200 and leases.json()["data"][0]["lease_state"] == "active"

                revoked = await client.post(
                    f"/api/v1/secret-leases/{payload['lease_id']}/revoke",
                    headers=_mutation_headers(tenant, actor, "secret:revoke", f"revoke-{suffix}"),
                    json={"expected_version": 1},
                )
                assert revoked.status_code == 200, revoked.text
                assert revoked.json()["data"]["lease_state"] == "revoked"
                duplicate = await client.post(
                    f"/api/v1/secret-leases/{payload['lease_id']}/revoke",
                    headers=_mutation_headers(tenant, actor, "secret:revoke", f"revoke-replay-{suffix}"),
                    json={"expected_version": 1},
                )
                assert duplicate.status_code == 200 and duplicate.json()["meta"]["replayed"] is True

                hidden = await client.get(
                    "/api/v1/secret-leases", headers=_read_headers(f"other-{suffix}", "other-operator")
                )
                assert hidden.status_code == 200 and hidden.json()["data"] == []

                openapi = json.dumps(app.openapi(), sort_keys=True).lower()
                for forbidden_schema in ("provider_lease_reference", "role_reference", "material_fields", "secret_token"):
                    assert forbidden_schema not in openapi
    finally:
        await engine.dispose()


def _read_headers(tenant: str, actor: str) -> dict[str, str]:
    return {
        "X-RedAgent-Test-Subject": actor, "X-RedAgent-Test-Tenant": tenant,
        "X-RedAgent-Test-Permissions": "secret:read",
    }


def _mutation_headers(
    tenant: str, actor: str, permission: str, idempotency: str, roe: str | None = None,
) -> dict[str, str]:
    headers = {
        "X-RedAgent-Test-Subject": actor, "X-RedAgent-Test-Tenant": tenant,
        "X-RedAgent-Test-Permissions": permission, "X-RedAgent-Policy-Reference": "policy:compat_098:1",
        "Idempotency-Key": idempotency,
    }
    if roe is not None:
        headers["X-RedAgent-ROE-Version"] = roe
    return headers


async def _bootstrap(sessions, tenant: str, actor: str, engagement: str, roe: str, job: str, suffix: str) -> None:
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}")
        await repo.bootstrap_tenant(name="Secret API Tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
        await repo.create_engagement(
            engagement_id=engagement, name="Secret API synthetic", owner_user_id=actor,
            idempotency_key=f"eng-{suffix}", occurred_at=NOW,
        )
        created = await repo.create_roe_version(
            roe_version_id=roe, engagement_id=engagement, revision=1, document={"active_testing": False},
            policy_reference_id=f"policy-reference-{suffix}", policy_name="r098-policy", policy_version="1",
            idempotency_key=f"roe-{suffix}", occurred_at=NOW,
        )
        await repo.approve_roe_version(
            roe_version_id=roe, approval_id=f"approval-{suffix}", expected_version=int(created.resource["version"]),
            idempotency_key=f"approval-{suffix}", occurred_at=NOW,
        )
        await repo.create_job(
            job_id=job, engagement_id=engagement, roe_version_id=roe,
            request={"capability": "synthetic-noop", "approval_timeout_seconds": 3600, "max_activity_attempts": 3, "budget_reference": "budget:compat_098:fixture"},
            workflow_id=f"workflow-{suffix}", policy_reference="policy:compat_098:1", campaign_id=None,
            idempotency_key=f"job-{suffix}", occurred_at=NOW,
        )
