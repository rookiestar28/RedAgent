from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.orchestration.contracts import deterministic_job_workflow_id
from redagent_platform.orchestration.gateway import WorkflowReference
from redagent_platform.persistence.database import DatabaseSettings, load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 8, 0, tzinfo=timezone.utc)


class _StubOrchestrationGateway:
    async def health(self) -> bool:
        return True

    async def start_job(self, request) -> WorkflowReference:
        return WorkflowReference(
            deterministic_job_workflow_id(request.tenant_id, request.job_id),
            f"run-{request.job_id}",
            False,
        )


def test_live_api_lifecycle_restart_durability_and_audit_linkage() -> None:
    asyncio.run(_api_lifecycle())


def test_database_outage_is_stable_and_does_not_leak_connection_details() -> None:
    asyncio.run(_database_outage())


async def _api_lifecycle() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    suffix = uuid4().hex
    tenant_id = f"tenant-api-{suffix}"
    user_id = f"user-api-{suffix}"
    engagement_id = f"eng-api-{suffix}"
    target_id = f"target-api-{suffix}"
    roe_id = f"roe-api-{suffix}"
    policy_id = f"policy-api-{suffix}"
    approval_id = f"approval-api-{suffix}"
    job_id = f"job-api-{suffix}"
    finding_id = f"finding-api-{suffix}"
    await _bootstrap(settings, tenant_id, user_id)

    permissions = ",".join(
        (
            "engagement:create",
            "engagement:read",
            "engagement:update",
            "target:create",
            "target:read",
            "roe:create",
            "roe:read",
            "roe:approve",
            "job:create",
            "job:read",
            "job:update",
            "finding:ingest",
        )
    )
    headers = {
        "X-RedAgent-Test-Subject": user_id,
        "X-RedAgent-Test-Tenant": tenant_id,
        "X-RedAgent-Test-Permissions": permissions,
        "X-RedAgent-Policy-Reference": "policy-bootstrap:1",
        "X-Correlation-ID": f"corr-api-{suffix}",
    }

    app = create_app(
        test_issuer_enabled=True,
        database_settings=settings,
        orchestration_gateway=_StubOrchestrationGateway(),
    )
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            ready = await client.get("/health/ready")
            assert ready.status_code == 200
            assert ready.json() == {"status": "ready", "revision": settings.expected_revision}

            create_headers = {**headers, "Idempotency-Key": f"eng-create-{suffix}"}
            created = await client.post(
                "/api/v1/engagements",
                headers=create_headers,
                json={"engagement_id": engagement_id, "name": "API lifecycle", "owner_user_id": user_id},
            )
            replayed = await client.post(
                "/api/v1/engagements",
                headers=create_headers,
                json={"engagement_id": engagement_id, "name": "API lifecycle", "owner_user_id": user_id},
            )
            assert created.status_code == 201
            assert replayed.status_code == 201
            assert created.json()["meta"]["replayed"] is False
            assert replayed.json()["meta"]["replayed"] is True
            assert replayed.json()["meta"]["audit_id"] == created.json()["meta"]["audit_id"]

            updated = await client.patch(
                f"/api/v1/engagements/{engagement_id}",
                headers={**headers, "Idempotency-Key": f"eng-update-{suffix}"},
                json={"name": "API lifecycle updated", "expected_version": 1},
            )
            stale = await client.patch(
                f"/api/v1/engagements/{engagement_id}",
                headers={**headers, "Idempotency-Key": f"eng-stale-{suffix}"},
                json={"name": "Stale", "expected_version": 1},
            )
            assert updated.status_code == 200 and updated.json()["data"]["version"] == 2
            assert stale.status_code == 409 and stale.json()["error"]["code"] == "version_conflict"

            target = await client.post(
                f"/api/v1/engagements/{engagement_id}/targets",
                headers={**headers, "Idempotency-Key": f"target-{suffix}"},
                json={"target_id": target_id, "target_type": "hostname", "normalized_value": "api.example.invalid"},
            )
            assert target.status_code == 201

            roe = await client.post(
                f"/api/v1/engagements/{engagement_id}/roe-versions",
                headers={**headers, "Idempotency-Key": f"roe-{suffix}"},
                json={
                    "roe_version_id": roe_id,
                    "revision": 1,
                    "document": {"scope": ["api.example.invalid"], "active_testing": False},
                    "policy_reference_id": policy_id,
                    "policy_name": "api-policy",
                    "policy_version": "1",
                },
            )
            assert roe.status_code == 201 and roe.json()["data"]["status"] == "draft"

            approved = await client.post(
                f"/api/v1/roe-versions/{roe_id}/approve",
                headers={**headers, "Idempotency-Key": f"approve-{suffix}", "X-RedAgent-ROE-Version": roe_id},
                json={"approval_id": approval_id, "expected_version": 1},
            )
            assert approved.status_code == 200 and approved.json()["data"]["status"] == "approved"

            job_headers = {**headers, "X-RedAgent-ROE-Version": roe_id}
            job = await client.post(
                "/api/v1/jobs",
                headers={**job_headers, "Idempotency-Key": f"job-{suffix}"},
                json={
                    "job_id": job_id,
                    "engagement_id": engagement_id,
                    "roe_version_id": roe_id,
                    "request": {
                        "capability": "synthetic-noop",
                        "approval_timeout_seconds": 3600,
                        "max_activity_attempts": 3,
                        "budget_reference": "budget:compat_096:api",
                    },
                },
            )
            invalid = await client.patch(
                f"/api/v1/jobs/{job_id}",
                headers={**job_headers, "Idempotency-Key": f"job-invalid-{suffix}"},
                json={"expected_version": 1, "next_status": "succeeded"},
            )
            assert job.status_code == 201 and job.json()["data"]["status"] == "pending"
            assert job.json()["data"]["orchestration_state"] == "dispatch_pending"
            assert job.json()["data"]["workflow_run_id"] == f"run-{job_id}"
            assert invalid.status_code == 405

            finding_headers = {**headers, "Idempotency-Key": f"finding-{suffix}"}
            finding_payload = {
                "finding_id": finding_id,
                "tool": "nuclei",
                "rule_id": "SYNTHETIC-API",
                "tool_version": "3.0",
                "database_version": "2026.07",
                "title": "Synthetic API finding",
                "severity": "high",
                "confidence": "confirmed",
                "affected_resource": "https://api.example.invalid",
                "location": "/synthetic",
                "evidence_reference": "evidence://synthetic/api",
                "redaction_state": "sanitized",
            }
            finding = await client.post("/api/v1/findings/ingest", headers=finding_headers, json=finding_payload)
            finding_replay = await client.post("/api/v1/findings/ingest", headers=finding_headers, json=finding_payload)
            assert finding.status_code == 201
            assert finding_replay.json()["meta"]["replayed"] is True

            targets = await client.get(f"/api/v1/engagements/{engagement_id}/targets", headers=headers)
            roes = await client.get(f"/api/v1/engagements/{engagement_id}/roe-versions", headers=headers)
            persisted_job = await client.get(f"/api/v1/jobs/{job_id}", headers=job_headers)
            assert targets.json()["data"][0]["target_id"] == target_id
            assert roes.json()["data"][0]["roe_version_id"] == roe_id
            assert persisted_job.json()["data"]["status"] == "pending"
            assert persisted_job.json()["data"]["orchestration_state"] == "dispatch_pending"

    restarted = create_app(test_issuer_enabled=True, database_settings=settings)
    async with restarted.router.lifespan_context(restarted):
        async with _client(restarted) as client:
            persisted = await client.get(f"/api/v1/engagements/{engagement_id}", headers=headers)
            assert persisted.status_code == 200
            assert persisted.json()["data"]["name"] == "API lifecycle updated"

    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as session, session.begin():
            audits = metadata.tables["audit_events"]
            count = await session.scalar(
                select(func.count())
                .select_from(audits)
                .where(audits.c.tenant_id == tenant_id, audits.c.correlation_id == f"corr-api-{suffix}")
            )
            assert int(count or 0) >= 7
    finally:
        await engine.dispose()


async def _database_outage() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    unavailable = DatabaseSettings(
        url=settings.url.set(port=1),
        driver=settings.driver,
        host=settings.host,
        database=settings.database,
        expected_revision=settings.expected_revision,
    )
    app = create_app(test_issuer_enabled=True, database_settings=unavailable)
    headers = {
        "X-RedAgent-Test-Subject": "outage-user",
        "X-RedAgent-Test-Tenant": "outage-tenant",
        "X-RedAgent-Test-Permissions": "engagement:read",
        "X-RedAgent-Policy-Reference": "outage-policy:1",
    }
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            ready = await client.get("/health/ready")
            business = await client.get("/api/v1/engagements", headers=headers)
    assert ready.status_code == 503, ready.text
    assert business.status_code == 503, business.text
    assert ready.json()["error"]["code"] == "database_unavailable"
    assert business.json()["error"]["code"] == "database_unavailable"
    assert "127.0.0.1" not in ready.text
    assert "password" not in business.text.lower()


async def _bootstrap(settings: DatabaseSettings, tenant_id: str, user_id: str) -> None:
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id=f"bootstrap-{tenant_id}",
            )
            await repo.bootstrap_tenant(name="API Tenant", occurred_at=NOW)
            await repo.bootstrap_user(user_id=user_id, subject=user_id, occurred_at=NOW)
    finally:
        await engine.dispose()


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    )
