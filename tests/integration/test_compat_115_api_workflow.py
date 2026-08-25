from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from redagent_platform.api.routers import finding_operations as finding_operations_routes
from redagent_platform.api.app import create_app
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)


def test_real_finding_operations_api_persists_review_report_delivery_and_tenant_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(finding_operations_routes, "_now", lambda: FIXTURE_ACTIVE_AT)
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    suffix = uuid4().hex
    tenant = f"tenant-api115-{suffix}"
    base = {
        "X-RedAgent-Test-Tenant": tenant, "X-Correlation-ID": f"api-r115-{suffix}",
        "X-RedAgent-Policy-Reference": "policy:compat_115:fixture",
    }
    app = create_app(
        test_issuer_enabled=True, database_settings=settings,
        policy_provider=DeterministicFakePolicyProvider(revision="r099-v1"),
        policy_required_revision="r099-v1",
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True), base_url="http://testserver",
        ) as client:
            imported = await client.post("/api/v1/finding-operations/imports", headers={
                **base, "X-RedAgent-Test-Subject": f"operator-{suffix}",
                "X-RedAgent-Test-Permissions": "finding:ingest", "Idempotency-Key": f"import-{suffix}",
            }, json={
                "import_id": f"import-{suffix}", "run_id": f"run-{suffix}",
                "source_record_id": f"source-{suffix}", "resource_id": f"resource-{suffix}",
                "evidence_id": f"evidence-{suffix}", "evidence_sha256": "a" * 64,
                "coverage_state": "complete", "confirmation": "--confirm-r115-fixture-import",
            })
            assert imported.status_code == 202, imported.text
            issue_id = imported.json()["data"]["issue_ids"][0]
            reviewed = await client.post(f"/api/v1/finding-operations/issues/{issue_id}/review", headers={
                **base, "X-RedAgent-Test-Subject": f"reviewer-{suffix}",
                "X-RedAgent-Test-Permissions": "finding:review", "Idempotency-Key": f"review-{suffix}",
            }, json={
                "operation_id": f"review-{suffix}", "disposition": "confirmed",
                "reason_code": "reviewed-fixture-evidence", "confirmation": "--confirm-r115-reviewed-disposition",
            })
            assert reviewed.status_code == 200, reviewed.text
            assert reviewed.json()["data"]["disposition"] == "confirmed"
            issue_fingerprint = reviewed.json()["data"]["issue_fingerprint"]
            report = await client.post("/api/v1/finding-operations/reports", headers={
                **base, "X-RedAgent-Test-Subject": f"reviewer-{suffix}",
                "X-RedAgent-Test-Permissions": "report:create", "Idempotency-Key": f"report-{suffix}",
            }, json={
                "report_id": f"report-{suffix}", "audience": "technical",
                "reviewed_snapshot_sha256": issue_fingerprint, "evidence_sha256": "a" * 64,
                "confirmation": "--confirm-r115-deterministic-report",
            })
            assert report.status_code == 201, report.text
            assert report.json()["data"]["report_state"] == "publishable"
            report_sha = report.json()["data"]["report_sha256"]
            publish_headers = {
                **base, "X-RedAgent-Test-Subject": f"admin-{suffix}",
                "X-RedAgent-Test-Permissions": "report:publish", "Idempotency-Key": f"publication-{suffix}",
            }
            published = await client.post(
                f"/api/v1/finding-operations/reports/report-{suffix}/publish", headers=publish_headers,
                json={"publication_id": f"publication-{suffix}", "report_sha256": report_sha,
                      "confirmation": "--confirm-r115-independent-publication"},
            )
            assert published.status_code == 200, published.text
            assert published.json()["data"]["publisher_id"] == f"admin-{suffix}"
            delivered = await client.post("/api/v1/finding-operations/deliveries", headers={
                **base, "X-RedAgent-Test-Subject": f"admin-{suffix}",
                "X-RedAgent-Test-Permissions": "connector:deliver", "Idempotency-Key": f"delivery-{suffix}",
            }, json={
                "delivery_id": f"delivery-{suffix}", "profile_id": "fixture-ticket-v1",
                "report_id": f"report-{suffix}", "report_sha256": report_sha,
                "destination_object_id": "SEC", "confirmation": "--confirm-r115-fixture-delivery",
            })
            assert delivered.status_code == 202, delivered.text
            assert delivered.json()["data"]["network_contact_count"] == 0
            dashboard = await client.get("/api/v1/finding-operations/dashboard", headers={
                **base, "X-RedAgent-Test-Subject": f"reviewer-{suffix}",
                "X-RedAgent-Test-Permissions": "finding:read",
            })
            assert dashboard.status_code == 200, dashboard.text
            assert len(dashboard.json()["data"]["issues"]) == 1
            assert dashboard.json()["data"]["issues"][0]["disposition"] == "confirmed"
            assert dashboard.json()["data"]["deliveries"][0]["network_contact_count"] == 0
            assert dashboard.json()["data"]["publications"][0]["publication_state"] == "published"
            other = await client.get("/api/v1/finding-operations/dashboard", headers={
                "X-RedAgent-Test-Tenant": f"other-{suffix}",
                "X-RedAgent-Test-Subject": f"reviewer-{suffix}",
                "X-RedAgent-Test-Permissions": "finding:read",
            })
            assert other.status_code == 200
            assert all(not rows for rows in other.json()["data"].values())
