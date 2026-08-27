from __future__ import annotations

import asyncio
from dataclasses import replace

import httpx
import pytest

from redagent_platform.api.app import create_app
from redagent_platform.campaign_service.qualification import (
    QualificationStartReceiptV1,
)
from redagent_platform.campaign_service.status import (
    CampaignStatusV1,
    CampaignEffectStatusV1,
)


AUTH = {
    "X-RedAgent-Test-Subject": "operator-r123",
    "X-RedAgent-Test-Tenant": "tenant-r123",
    "X-RedAgent-Test-Permissions": "campaign:read,campaign:create",
}


class QualificationService:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def start(self, intent, **values):
        self.calls.append({"intent": intent, **values})
        return QualificationStartReceiptV1(
            schema_version="redagent.r123-qualification-start-receipt/v1",
            campaign_id="campaign-server-generated",
            aggregate_sequence=1,
            status="dispatch_pending",
        )


class CampaignStatusOwner:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    async def read(self, **values):
        self.calls.append(values)
        return CampaignStatusV1(
            schema_version="redagent.r123-campaign-status/v1",
            campaign_id="campaign-server-generated",
            status="workflow_started",
            aggregate_sequence=3,
            replan_count=0,
            attention_reason=None,
            workflow_delivery_state="delivered",
            workflow_reconciliation_state="none",
            effects=(CampaignEffectStatusV1(
                capability_id="zap-controlled-runtime@2",
                state="confirmed",
                reconciliation_state="confirmed",
                evidence_count=1,
                cleanup_complete=True,
            ),),
            terminal_receipt_present=False,
        )


def test_r123_internal_api_is_modular_strict_and_exposes_no_runtime_id_input() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()

    assert "/api/v1/internal/r123/status" in schema["paths"]
    assert "/api/v1/internal/r123/qualification" in schema["paths"]
    assert "/api/v1/internal/r123/campaigns/{campaign_id}/status" in schema["paths"]
    request = schema["components"]["schemas"]["R123QualificationRequest"]
    assert request["additionalProperties"] is False
    assert set(request["properties"]) == {
        "fixture_id",
        "objective_kind",
        "header_code",
        "require_corroboration",
        "risk_profile",
    }
    assert not {
        "tenant_id", "principal_id", "engagement_id", "target_id", "campaign_id",
        "workflow_id", "runner_id", "adapter_id", "url", "command",
    }.intersection(request["properties"])


def test_r123_status_defaults_disabled_without_touching_runtime_dependencies() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "GET",
        "/api/v1/internal/r123/status",
        headers=AUTH,
    )

    assert response.status_code == 200
    assert response.json() == {
        "data": {
            "ready": True,
            "execution_enabled": False,
            "reason": "strategy_loop_disabled",
            "capability_ids": [],
        }
    }


def test_r123_qualification_uses_auth_identity_and_transport_generated_idempotency() -> None:
    service = QualificationService()
    app = create_app(test_issuer_enabled=True, r123_qualification_service=service)
    response = _request(
        app,
        "POST",
        "/api/v1/internal/r123/qualification",
        headers={
            **AUTH,
            "X-RedAgent-Policy-Reference": "policy-r123-owned-loopback",
            "Idempotency-Key": "cli-generated-r123-request",
        },
        json={
            "fixture_id": "owned-loopback-http-first-slice",
            "objective_kind": "http_posture",
            "header_code": None,
            "require_corroboration": False,
            "risk_profile": "tier1_passive",
        },
    )

    assert response.status_code == 202, response.text
    assert response.json() == {
        "data": {
            "schema_version": "redagent.r123-qualification-start-receipt/v1",
            "campaign_id": "campaign-server-generated",
            "aggregate_sequence": 1,
            "status": "dispatch_pending",
        }
    }
    assert service.calls[0]["tenant_id"] == "tenant-r123"
    assert service.calls[0]["principal_id"] == "operator-r123"
    assert service.calls[0]["now"].tzinfo is not None


def test_r123_qualification_fails_closed_when_runtime_service_is_not_composed() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "POST",
        "/api/v1/internal/r123/qualification",
        headers={
            **AUTH,
            "X-RedAgent-Policy-Reference": "policy-r123-owned-loopback",
            "Idempotency-Key": "cli-generated-r123-request",
        },
        json={
            "fixture_id": "owned-loopback-http-first-slice",
            "objective_kind": "http_posture",
            "header_code": None,
            "require_corroboration": False,
            "risk_profile": "tier1_passive",
        },
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "r123_qualification_unavailable"


def test_r123_campaign_status_is_tenant_scoped_and_contains_no_runtime_dispatch_identity() -> None:
    owner = CampaignStatusOwner()
    response = _request(
        create_app(test_issuer_enabled=True, r123_campaign_status_owner=owner),
        "GET",
        "/api/v1/internal/r123/campaigns/campaign-server-generated/status",
        headers=AUTH,
    )

    assert response.status_code == 200, response.text
    assert owner.calls == [{
        "tenant_id": "tenant-r123",
        "campaign_id": "campaign-server-generated",
    }]
    data = response.json()["data"]
    assert data["status"] == "workflow_started"
    assert data["effects"] == [{
        "capability_id": "zap-controlled-runtime@2",
        "state": "confirmed",
        "reconciliation_state": "confirmed",
        "evidence_count": 1,
        "cleanup_complete": True,
    }]
    assert not {
        "workflow_id", "workflow_run_id", "runner_id", "workload_identity",
        "effect_id", "invocation_id", "receipt_sha256", "evidence_ids",
    }.intersection(data)


def test_campaign_status_projects_workflow_ambiguity_as_closed_manual_review_state() -> None:
    status = CampaignStatusV1(
        schema_version="redagent.r123-campaign-status/v1",
        campaign_id="campaign-ambiguous",
        status="workflow_started",
        aggregate_sequence=2,
        replan_count=0,
        attention_reason="workflow_start_ambiguous",
        workflow_delivery_state="reconciliation_required",
        workflow_reconciliation_state="manual_review_required",
        effects=(),
        terminal_receipt_present=False,
    )
    assert status.workflow_delivery_state == "reconciliation_required"
    assert status.workflow_reconciliation_state == "manual_review_required"

    with pytest.raises(ValueError, match="r123_status_workflow_reconciliation_invalid"):
        replace(status, workflow_reconciliation_state="arbitrary-corrupt-state")


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())
