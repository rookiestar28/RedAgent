from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.telemetry_service.contracts import (
    TELEMETRY_SCHEMA, ResourceType, ServiceName, SignalKind, SignalOutcome, TelemetryEnvelope,
)
from redagent_platform.telemetry_service.operations import IncidentRepository, SloRepository
from redagent_platform.telemetry_service.repository import TelemetryRepository
from redagent_platform.telemetry_service.slo import SloObjective


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 11, 7, 0, tzinfo=timezone.utc)


def test_observability_dashboard_correlation_incident_timeline_and_action_api() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r102-api-{suffix}"
    operator = f"operator-{suffix}"
    correlation = f"correlation-{suffix}"
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"bootstrap-{suffix}",
            ).bootstrap_tenant(name="compat_102 API", occurred_at=NOW)
            await IncidentRepository(
                session, tenant_id=tenant, actor_user_id=operator, correlation_id=correlation,
            ).open_incident(
                incident_id=f"incident-{suffix}", source_kind="telemetry",
                source_id=f"export-{suffix}", severity="high",
                reason_code="telemetry_degraded", occurred_at=NOW,
            )
            await TelemetryRepository(
                session, tenant_id=tenant, actor_user_id=operator, correlation_id=correlation,
            ).enqueue(
                operation_id=f"export-{suffix}", priority="security", occurred_at=NOW,
                envelope=TelemetryEnvelope(
                    schema=TELEMETRY_SCHEMA, event_id=f"event-{suffix}", tenant_id=tenant,
                    correlation_id=correlation, trace_id="7" * 32, span_id="8" * 16,
                    parent_span_id=None, sampled=True, kind=SignalKind.EVENT,
                    service_name=ServiceName.TELEMETRY, service_version="0.1.0",
                    service_instance_id="telemetry-api-1", resource_type=ResourceType.EXPORT,
                    resource_id=f"export-{suffix}", operation="telemetry.export.degraded",
                    outcome=SignalOutcome.DEGRADED, reason_code="telemetry_degraded",
                    occurred_at=NOW, duration_ms=None, measurement_name=None,
                    measurement_value=None,
                ),
            )
            slos = SloRepository(
                session, tenant_id=tenant, actor_user_id=operator, correlation_id=correlation,
            )
            definition = await slos.register_objective(
                SloObjective("api_availability", 9900, 300), revision=1,
                metric_name="api_availability", occurred_at=NOW,
            )
            await slos.evaluate_ratio_window(
                definition_id=str(definition["id"]), window_start=NOW,
                window_end=NOW + timedelta(minutes=5), total=100, bad=2, missing=0,
                source_hash="b" * 64, occurred_at=NOW + timedelta(minutes=5),
            )
    finally:
        await engine.dispose()

    app = create_app(test_issuer_enabled=True, database_settings=settings)
    headers = {
        "X-RedAgent-Test-Tenant": tenant, "X-RedAgent-Test-Subject": operator,
        "X-RedAgent-Test-Permissions": "audit:read",
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://testserver",
        ) as client:
            dashboard = await client.get("/api/v1/observability/dashboard", headers=headers)
            assert dashboard.status_code == 200, dashboard.text
            assert dashboard.json()["data"]["open_alerts"] == 1
            assert dashboard.json()["data"]["incident_state_counts"]["open"] == 1
            lookup = await client.get(
                f"/api/v1/observability/correlations/{correlation}", headers=headers,
            )
            assert lookup.status_code == 200, lookup.text
            assert lookup.json()["data"][0]["event_id"] == f"event-{suffix}"
            incidents = await client.get("/api/v1/incidents", headers=headers)
            assert incidents.status_code == 200
            assert incidents.json()["data"][0]["state"] == "open"
            runbooks = await client.get("/api/v1/incidents/runbooks", headers=headers)
            assert runbooks.status_code == 200
            assert {item["runbook_id"] for item in runbooks.json()["data"]} >= {
                "telemetry_outage", "failed_containment", "evidence_integrity",
            }
            timeline = await client.get(
                f"/api/v1/incidents/incident-{suffix}/timeline", headers=headers,
            )
            assert timeline.status_code == 200 and timeline.json()["data"][0]["event_type"] == "opened"
            assigned = await client.post(
                f"/api/v1/incidents/incident-{suffix}/actions",
                headers={
                    **headers, "X-RedAgent-Policy-Reference": "policy:compat_102:1",
                    "Idempotency-Key": f"assign-{suffix}",
                },
                json={
                    "action_id": f"assign-{suffix}", "action": "assign",
                    "expected_version": 1, "assignee_id": f"responder-{suffix}",
                },
            )
            assert assigned.status_code == 200, assigned.text
            assert assigned.json()["data"]["assigned_to_user_id"] == f"responder-{suffix}"

            denied = await client.get(
                "/api/v1/incidents",
                headers={
                    "X-RedAgent-Test-Tenant": tenant,
                    "X-RedAgent-Test-Subject": operator,
                    "X-RedAgent-Test-Permissions": "job:read",
                },
            )
            assert denied.status_code == 403
