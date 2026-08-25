from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 20, 0, tzinfo=timezone.utc)


def test_live_evidence_api_lifecycle_is_tenant_scoped_and_never_returns_bytes() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    suffix = uuid4().hex
    tenant = f"tenant-evidence-api-{suffix}"
    actor = f"producer-api-{suffix}"
    engagement = f"eng-evidence-api-{suffix}"
    roe = f"roe-evidence-api-{suffix}"
    job = f"job-evidence-api-{suffix}"
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        await _bootstrap(sessions, tenant, actor, engagement, roe, job, suffix)
        backend = LocalAppendOnlyBackend(
            ROOT / ".tmp" / "r097-evidence-api" / suffix,
            profile="synthetic-local",
        )
        app = create_app(
            test_issuer_enabled=True,
            database_settings=settings,
            evidence_backend=backend,
            evidence_kms_reference="kms:local:fixture",
            synthetic_evidence_enabled=True,
        )
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                base_url="http://testserver",
            ) as client:
                artifact_id = f"artifact-api-{suffix}"
                created = await client.post(
                    "/api/v1/evidence/synthetic",
                    headers=_headers(tenant, actor, "evidence:write", f"create-{suffix}"),
                    json={
                        "artifact_id": artifact_id,
                        "engagement_id": engagement,
                        "job_id": job,
                        "fixture_kind": "sanitized-json",
                        "retention_days": 30,
                    },
                )
                assert created.status_code == 201, created.text
                assert created.json()["data"]["artifact_class"] == "redacted"
                assert "content" not in created.json()["data"]

                listed = await client.get(
                    "/api/v1/evidence/artifacts",
                    headers=_read_headers(tenant, actor),
                )
                assert listed.status_code == 200
                assert listed.json()["page"]["returned"] == 1

                report_id = f"artifact-report-api-{suffix}"
                report = await client.post(
                    f"/api/v1/evidence/artifacts/{artifact_id}/derive",
                    headers=_headers(tenant, actor, "evidence:derive", f"derive-report-{suffix}"),
                    json={"artifact_id": report_id, "artifact_class": "report_safe", "quality_approved": True},
                )
                assert report.status_code == 201, report.text
                export_id = f"artifact-export-api-{suffix}"
                exported = await client.post(
                    f"/api/v1/evidence/artifacts/{artifact_id}/derive",
                    headers=_headers(tenant, actor, "evidence:derive", f"derive-export-{suffix}"),
                    json={"artifact_id": export_id, "artifact_class": "export_safe", "quality_approved": True},
                )
                assert exported.status_code == 201, exported.text

                selected = await client.get(
                    f"/api/v1/evidence/artifacts/{artifact_id}/selection?purpose=report",
                    headers=_read_headers(tenant, actor),
                )
                assert selected.status_code == 200
                assert selected.json()["data"]["artifact_id"] == export_id

                verified = await client.post(
                    f"/api/v1/evidence/artifacts/{artifact_id}/verify",
                    headers=_headers(tenant, actor, "evidence:verify", f"verify-{suffix}"),
                )
                assert verified.status_code == 200
                assert verified.json()["data"]["verified"] is True

                held = await client.post(
                    f"/api/v1/evidence/artifacts/{artifact_id}/legal-hold",
                    headers=_headers(tenant, actor, "evidence:retention-admin", f"hold-{suffix}"),
                    json={"expected_version": 1},
                )
                assert held.status_code == 200, held.text
                assert held.json()["data"]["legal_hold"] is True

                detail = await client.get(
                    f"/api/v1/evidence/artifacts/{report_id}",
                    headers=_read_headers(tenant, actor),
                )
                assert detail.status_code == 200
                assert detail.json()["data"]["source_artifact_id"] == artifact_id
                assert detail.json()["data"]["custody_event_count"] >= 4

                hidden = await client.get(
                    f"/api/v1/evidence/artifacts/{artifact_id}",
                    headers=_read_headers(f"other-{suffix}", "other-user"),
                )
                assert hidden.status_code == 404
    finally:
        await engine.dispose()


def _read_headers(tenant: str, actor: str) -> dict[str, str]:
    return {
        "X-RedAgent-Test-Subject": actor,
        "X-RedAgent-Test-Tenant": tenant,
        "X-RedAgent-Test-Permissions": "evidence:read",
    }


def _headers(tenant: str, actor: str, permission: str, idempotency: str) -> dict[str, str]:
    return {
        "X-RedAgent-Test-Subject": actor,
        "X-RedAgent-Test-Tenant": tenant,
        "X-RedAgent-Test-Permissions": permission,
        "X-RedAgent-Policy-Reference": "policy:compat_097:1",
        "Idempotency-Key": idempotency,
    }


async def _bootstrap(sessions, tenant: str, actor: str, engagement: str, roe: str, job: str, suffix: str) -> None:
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}")
        await repo.bootstrap_tenant(name="Evidence API Tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
        await repo.create_engagement(
            engagement_id=engagement, name="Evidence API synthetic", owner_user_id=actor,
            idempotency_key=f"eng-{suffix}", occurred_at=NOW,
        )
        created_roe = await repo.create_roe_version(
            roe_version_id=roe, engagement_id=engagement, revision=1,
            document={"active_testing": False}, policy_reference_id=f"policy-{suffix}",
            policy_name="r097-policy", policy_version="1", idempotency_key=f"roe-{suffix}", occurred_at=NOW,
        )
        await repo.approve_roe_version(
            roe_version_id=roe, approval_id=f"approval-{suffix}",
            expected_version=int(created_roe.resource["version"]), idempotency_key=f"approve-{suffix}", occurred_at=NOW,
        )
        await repo.create_job(
            job_id=job, engagement_id=engagement, roe_version_id=roe,
            request={
                "capability": "synthetic-noop", "approval_timeout_seconds": 3600,
                "max_activity_attempts": 3, "budget_reference": "budget:compat_097:fixture",
            },
            workflow_id=f"workflow-{suffix}", policy_reference="policy:compat_097:1", campaign_id=None,
            idempotency_key=f"job-{suffix}", occurred_at=NOW,
        )
