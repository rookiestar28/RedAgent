from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 21, 0, tzinfo=timezone.utc)


class _StopGateway:
    def __init__(self) -> None:
        self.stops: list[tuple[str, object]] = []

    async def health(self) -> bool:
        return True

    async def stop_job(self, workflow_id: str, signal: object) -> None:
        self.stops.append((workflow_id, signal))


def test_broad_control_dual_control_fanout_and_policy_outage_safety_path() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r101-api-{suffix}"
    operator = f"operator-{suffix}"
    approver = f"approver-{suffix}"
    campaign = f"campaign-{suffix}"
    engagement = f"engagement-{suffix}"
    roe = f"roe-{suffix}"
    try:
        async with sessions() as session, session.begin():
            repository = ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"bootstrap-{suffix}",
            )
            await repository.bootstrap_tenant(name="compat_101 API tenant", occurred_at=NOW)
            await repository.bootstrap_user(user_id=operator, subject=operator, occurred_at=NOW)
            await repository.bootstrap_user(user_id=approver, subject=approver, occurred_at=NOW)
            await session.execute(insert(metadata.tables["engagements"]).values(
                id=engagement, name="compat_101 API synthetic", owner_user_id=operator,
                tenant_id=tenant, version=1, created_at=NOW, updated_at=NOW,
            ))
            await session.execute(insert(metadata.tables["roe_versions"]).values(
                id=roe, engagement_id=engagement, revision=1, status="approved", document={},
                tenant_id=tenant, version=1, created_at=NOW, updated_at=NOW,
            ))
            await session.execute(insert(metadata.tables["campaigns"]).values(
                id=campaign, engagement_id=engagement, roe_version_id=roe,
                name="compat_101 synthetic campaign", status="running",
                workflow_id=f"campaign-workflow-{suffix}", workflow_run_id=f"campaign-run-{suffix}",
                orchestration_revision=1, tenant_id=tenant, version=1,
                created_at=NOW, updated_at=NOW,
            ))
            for index in range(2):
                job_id = f"job-{index}-{suffix}"
                await session.execute(insert(metadata.tables["jobs"]).values(
                    id=job_id, engagement_id=engagement, roe_version_id=roe,
                    created_by_user_id=operator, campaign_id=campaign, status="running",
                    request={"capability": "synthetic-noop"}, policy_reference="policy:r101-api:1",
                    workflow_id=f"workflow-{index}-{suffix}", workflow_run_id=f"run-{index}-{suffix}",
                    orchestration_state="running", orchestration_revision=4,
                    current_gate="synthetic_activity", failure_code=None, retry_count=0,
                    dispatch_blocked=False, stop_requested=False, tenant_id=tenant,
                    version=1, created_at=NOW, updated_at=NOW,
                ))
    finally:
        await engine.dispose()

    gateway = _StopGateway()
    app = create_app(
        test_issuer_enabled=True, database_settings=settings,
        orchestration_gateway=gateway,
        policy_provider=object(), policy_required_revision="synthetic-r101-v1",
    )
    common = {
        "X-RedAgent-Test-Tenant": tenant,
        "X-RedAgent-Policy-Reference": "policy:r101-api:1",
    }
    operator_headers = {
        **common, "X-RedAgent-Test-Subject": operator,
        "X-RedAgent-Test-Permissions": "job:read,job:stop",
        "Idempotency-Key": f"request-{suffix}",
    }
    async with app.router.lifespan_context(app):
        # CRITICAL: emergency containment remains available when normal policy evaluation is unavailable.
        app.state.policy_sdk = None
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://testserver",
        ) as client:
            requested = await client.post(
                "/api/v1/containment-controls", headers=operator_headers,
                json={
                    "stop_id": f"stop-{suffix}", "scope_kind": "campaign",
                    "scope_id": campaign, "expected_version": 1,
                    "reason": "Synthetic campaign policy-outage containment",
                },
            )
            assert requested.status_code == 202, requested.text
            control = requested.json()["data"]
            assert control["control_state"] == "pending_approval"
            assert gateway.stops == []

            same_person = await client.post(
                f"/api/v1/containment-controls/{control['control_id']}/approve",
                headers={**operator_headers, "X-RedAgent-Test-Permissions": "job:approve"},
                json={
                    "approval_id": f"same-{suffix}", "request_hash": control["request_hash"],
                    "expected_version": 1,
                },
            )
            assert same_person.status_code == 409

            approved = await client.post(
                f"/api/v1/containment-controls/{control['control_id']}/approve",
                headers={
                    **common, "X-RedAgent-Test-Subject": approver,
                    "X-RedAgent-Test-Permissions": "job:approve",
                    "Idempotency-Key": f"approve-{suffix}",
                },
                json={
                    "approval_id": f"approval-{suffix}", "request_hash": control["request_hash"],
                    "expected_version": 1,
                },
            )
            assert approved.status_code == 200, approved.text
            assert approved.json()["data"]["control_state"] == "active"
            assert len(gateway.stops) == 2
            assert {item[0] for item in gateway.stops} == {
                f"workflow-0-{suffix}", f"workflow-1-{suffix}",
            }

            listed = await client.get(
                "/api/v1/containment-controls",
                headers={**common, "X-RedAgent-Test-Subject": operator, "X-RedAgent-Test-Permissions": "job:read"},
            )
            quota = await client.get(
                "/api/v1/quotas/status",
                headers={**common, "X-RedAgent-Test-Subject": operator, "X-RedAgent-Test-Permissions": "job:read"},
            )
            assert listed.status_code == 200 and listed.json()["data"][0]["control_id"] == control["control_id"]
            assert quota.status_code == 200 and quota.json()["data"] == []

            recovery = await client.post(
                f"/api/v1/containment-controls/{control['control_id']}/recover",
                headers={
                    **common, "X-RedAgent-Test-Subject": f"reviewer-{suffix}",
                    "X-RedAgent-Test-Permissions": "audit:read", "Idempotency-Key": f"recover-{suffix}",
                },
                json={"review_id": f"review-{suffix}", "expected_version": 2},
            )
            assert recovery.status_code == 503
            assert recovery.json()["error"]["code"] == "policy_unavailable"
