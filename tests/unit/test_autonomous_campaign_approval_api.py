from __future__ import annotations

import asyncio
from datetime import timedelta

from fastapi.testclient import TestClient

from redagent_platform.api.app import create_app
from redagent_platform.campaign_service.application_contracts import ApplicationTransitionConflict
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.approval_api import AutonomousCampaignDenialRequest
from tests.unit.test_autonomous_campaign_plan_approval import (
    Repository,
    _service,
    _stage_command,
)


READ_AUTH = {
    "X-RedAgent-Test-Subject": "operator-a",
    "X-RedAgent-Test-Tenant": "tenant-a",
    "X-RedAgent-Test-Permissions": "campaign:read",
}
APPROVE_AUTH = {
    "X-RedAgent-Test-Subject": "approver-a",
    "X-RedAgent-Test-Tenant": "tenant-a",
    "X-RedAgent-Test-Permissions": "campaign:approve,campaign:read",
    "X-RedAgent-Policy-Reference": "policy-a",
    "Idempotency-Key": "api-approval-a",
}


def test_denial_reason_api_contract_matches_the_one_character_domain_minimum() -> None:
    payload = AutonomousCampaignDenialRequest(
        preview_id="preview-a",
        preview_sha256="a" * 64,
        reason_code="a",
    )
    assert payload.reason_code == "a"


def _staged_app(monkeypatch):
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)
    staged = asyncio.run(service.stage_plan(command))
    monkeypatch.setattr(
        "redagent_platform.campaign_service.approval_api._now",
        lambda: command.occurred_at + timedelta(seconds=1),
    )
    return create_app(
        test_issuer_enabled=True,
        autonomous_campaign_application_service=service,
    ), staged


def test_safe_preview_route_is_tenant_guarded_complete_and_no_store(monkeypatch) -> None:
    app, staged = _staged_app(monkeypatch)
    response = TestClient(app).get(
        "/api/v1/autonomous-campaigns/campaign-a/plan-preview",
        headers=READ_AUTH,
    )
    assert response.status_code == 200
    assert response.headers["etag"] == staged.preview.etag
    assert response.headers["cache-control"] == "no-store"
    data = response.json()["data"]
    assert data["preview_id"] == staged.preview.preview_id
    assert data["preview_sha256"] == staged.preview.preview_sha256
    assert data["actions"][0]["operator_id"] == "collect-artifact-posture"
    assert data["required_approvers"] == [
        {"principal_id": "approver-a", "role_id": "campaign-owner"}
    ]
    serialized = response.text
    assert "signature_hex" not in serialized
    assert "arguments" not in serialized


def test_exact_approval_requires_campaign_approve_and_matching_if_match(monkeypatch) -> None:
    app, staged = _staged_app(monkeypatch)
    client = TestClient(app)
    payload = {
        "preview_id": staged.preview.preview_id,
        "preview_sha256": staged.preview.preview_sha256,
    }
    denied = client.post(
        "/api/v1/autonomous-campaigns/campaign-a/plan-approval",
        headers={
            **APPROVE_AUTH,
            "X-RedAgent-Test-Permissions": "campaign:read",
            "If-Match": staged.preview.etag,
        },
        json=payload,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "permission_denied"

    stale = client.post(
        "/api/v1/autonomous-campaigns/campaign-a/plan-approval",
        headers={**APPROVE_AUTH, "If-Match": '"r172-2-' + "0" * 64 + '"'},
        json=payload,
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "approval_etag_mismatch"

    approved = client.post(
        "/api/v1/autonomous-campaigns/campaign-a/plan-approval",
        headers={**APPROVE_AUTH, "If-Match": staged.preview.etag},
        json=payload,
    )
    assert approved.status_code == 200
    data = approved.json()["data"]
    assert data["decision"] == "approved"
    assert data["policy_reference"] == APPROVE_AUTH["X-RedAgent-Policy-Reference"]
    assert data["application"]["lifecycle_state"] == "APPROVED"
    assert data["application"]["admission_ready"] is False
    assert data["application"]["start_ready"] is False


def test_explicit_denial_route_persists_terminal_reason(monkeypatch) -> None:
    app, staged = _staged_app(monkeypatch)
    response = TestClient(app).post(
        "/api/v1/autonomous-campaigns/campaign-a/plan-denial",
        headers={**APPROVE_AUTH, "Idempotency-Key": "api-denial-a", "If-Match": staged.preview.etag},
        json={
            "preview_id": staged.preview.preview_id,
            "preview_sha256": staged.preview.preview_sha256,
            "reason_code": "operator_denied_exact_plan",
        },
    )
    assert response.status_code == 200
    assert response.json()["data"]["decision"] == "denied"
    assert response.json()["data"]["reason_code"] == "operator_denied_exact_plan"


def test_revoked_or_superseded_lifecycle_returns_typed_conflict(monkeypatch) -> None:
    app, staged = _staged_app(monkeypatch)

    async def reject_stale_lifecycle(self, command):
        raise ApplicationTransitionConflict("application_lifecycle_transition_invalid")

    monkeypatch.setattr(AutonomousCampaignApplicationService, "approve_plan", reject_stale_lifecycle)
    response = TestClient(app, raise_server_exceptions=False).post(
        "/api/v1/autonomous-campaigns/campaign-a/plan-approval",
        headers={**APPROVE_AUTH, "If-Match": staged.preview.etag},
        json={
            "preview_id": staged.preview.preview_id,
            "preview_sha256": staged.preview.preview_sha256,
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "application_lifecycle_transition_invalid"


def test_openapi_exposes_only_read_and_explicit_decision_routes() -> None:
    paths = create_app(test_issuer_enabled=True).openapi()["paths"]
    assert "/api/v1/autonomous-campaigns/{campaign_id}/plan-preview" in paths
    assert "/api/v1/autonomous-campaigns/{campaign_id}/plan-approval" in paths
    assert "/api/v1/autonomous-campaigns/{campaign_id}/plan-denial" in paths
    assert not any("stage" in path or "admit" in path or "start" in path for path in paths if "autonomous" in path)
