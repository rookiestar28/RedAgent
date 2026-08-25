from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from redagent_platform.api.routers import workbench as workbench_routes
from redagent_platform.api.app import create_app
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)


def test_real_workbench_api_persists_successor_exact_review_freeze_and_tenant_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(workbench_routes, "_now", lambda: FIXTURE_ACTIVE_AT)
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    suffix = uuid4().hex
    tenant = f"tenant-api114-{suffix}"
    operator = f"operator-api114-{suffix}"
    reviewer = f"reviewer-api114-{suffix}"
    base = {"X-RedAgent-Test-Tenant": tenant, "X-Correlation-ID": f"api-r114-{suffix}"}
    app = create_app(test_issuer_enabled=True, database_settings=settings,
                     policy_provider=DeterministicFakePolicyProvider(revision="r099-v1"),
                     policy_required_revision="r099-v1")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
                                    base_url="http://testserver") as client:
            create_headers = {**base, "X-RedAgent-Test-Subject": operator,
                "X-RedAgent-Test-Permissions": "job:create", "X-RedAgent-Policy-Reference": "policy:compat_114:draft",
                "Idempotency-Key": f"draft-{suffix}"}
            draft_id = f"draft-{suffix}"
            payload = {"draft_id": draft_id, "campaign_id": "campaign-r114", "plan_id": "plan-r114-stored",
                "target_id": "target-r114-owned", "tool_fqn": "redagent.r114-mcp-fixture.propose.v1",
                "confirmation": "--confirm-r114-structured-draft"}
            created = await client.post("/api/v1/workbench/drafts", headers=create_headers, json=payload)
            assert created.status_code == 202, created.text
            proposal_sha = created.json()["data"]["proposal_sha256"]
            own_review = await client.post(f"/api/v1/workbench/drafts/{draft_id}/review", headers={
                **create_headers, "X-Correlation-ID": f"own-review-{suffix}",
                "Idempotency-Key": f"own-review-{suffix}"}, json={
                "decision_id": f"own-{suffix}", "expected_proposal_sha256": proposal_sha,
                "decision": "approve_exact", "confirmation": "--confirm-r114-exact-review"})
            assert own_review.status_code == 409
            successor_id = f"successor-{suffix}"
            successor = await client.post(f"/api/v1/workbench/drafts/{draft_id}/successors", headers={
                **create_headers, "X-Correlation-ID": f"successor-{suffix}",
                "Idempotency-Key": f"successor-{suffix}"}, json={
                "successor_draft_id": successor_id, "plan_id": "plan-r114-successor",
                "confirmation": "--confirm-r114-successor-invalidates-approval"})
            assert successor.status_code == 202, successor.text
            reviewed = await client.post(f"/api/v1/workbench/drafts/{successor_id}/review", headers={
                **base, "X-RedAgent-Test-Subject": reviewer, "X-RedAgent-Test-Permissions": "job:create",
                "X-Correlation-ID": f"review-{suffix}",
                "X-RedAgent-Policy-Reference": "policy:compat_114:review", "Idempotency-Key": f"review-{suffix}"}, json={
                "decision_id": f"decision-{suffix}",
                "expected_proposal_sha256": successor.json()["data"]["proposal_sha256"],
                "decision": "approve_exact", "confirmation": "--confirm-r114-exact-review"})
            assert reviewed.status_code == 200 and reviewed.json()["data"]["draft_state"] == "approved"
            dashboard = await client.get("/api/v1/workbench/dashboard", headers={
                **base, "X-RedAgent-Test-Subject": reviewer, "X-RedAgent-Test-Permissions": "audit:read"})
            assert dashboard.status_code == 200 and len(dashboard.json()["data"]["drafts"]) == 2
            registration = dashboard.json()["data"]["registrations"][0]
            frozen = await client.post(f"/api/v1/mcp/servers/{registration['registration_id']}/freeze", headers={
                **base, "X-RedAgent-Test-Subject": operator, "X-RedAgent-Test-Permissions": "job:stop",
                "X-Correlation-ID": f"freeze-{suffix}",
                "X-RedAgent-Policy-Reference": "policy:compat_114:freeze", "Idempotency-Key": f"freeze-{suffix}"}, json={
                "expected_inventory_sha256": registration["inventory_sha256"],
                "confirmation": "--confirm-r114-freeze-and-invalidate"})
            assert frozen.status_code == 200 and frozen.json()["data"]["invalidated_approval_count"] == 1
            other = await client.get("/api/v1/workbench/dashboard", headers={
                "X-RedAgent-Test-Tenant": f"other-{suffix}", "X-RedAgent-Test-Subject": reviewer,
                "X-RedAgent-Test-Permissions": "audit:read"})
            assert other.status_code == 200
            other_data = other.json()["data"]
            assert other_data["binding_options"] == [{
                "binding_id": "binding-r114-fixture",
                "campaign_id": "campaign-r114",
                "campaign_label": "R114 synthetic campaign",
                "plan_id": "plan-r114-stored",
                "plan_label": "Stored fixture plan",
                "successor_plan_id": "plan-r114-successor",
                "successor_plan_label": "Revised fixture plan",
                "target_id": "target-r114-owned",
                "target_label": "Owned synthetic target",
                "tool_fqn": "redagent.r114-mcp-fixture.propose.v1",
                "binding_state": "available",
                "fixture_only": True,
                "egress_class": "none",
            }]
            tenant_owned = set(other_data) - {"binding_options"}
            assert tenant_owned
            assert all(not other_data[key] for key in tenant_owned)
