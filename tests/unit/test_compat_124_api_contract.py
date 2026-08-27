from __future__ import annotations

import asyncio

import httpx

from redagent_platform.api.app import create_app
from redagent_platform.campaign_service.service import CampaignCoreCreateDisabled, CampaignCoreEtagConflict
from redagent_platform.campaign_service.status import CampaignStatusNotFound


AUTH = {
    "X-RedAgent-Test-Subject": "operator-r124",
    "X-RedAgent-Test-Tenant": "tenant-r124",
    "X-RedAgent-Test-Permissions": (
        "campaign:read,campaign:create,campaign:stop,campaign:inspect"
    ),
}
MUTATION = {
    **AUTH,
    "X-RedAgent-Policy-Reference": "policy-r124-owned-loopback",
    "Idempotency-Key": "transport-generated-r124-request",
}


class CampaignCoreService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def list_engagement_options(self, **values):
        self.calls.append(("engagements", values))
        return {
            "data": [{
                "binding": "r124-engagement-opaque",
                "label": "Owned loopback engagement",
                "revision": "7",
                "freshness": "current",
                "eligible": True,
                "unavailable_reason": None,
            }],
            "page": {"limit": 20, "next_cursor": None},
        }

    async def start_campaign(self, intent, **values):
        self.calls.append(("start", {"intent": intent, **values}))
        return {
            "data": {
                "campaign_id": "campaign-server-generated",
                "status": "dispatch_pending",
                "aggregate_sequence": 1,
                "etag": '"campaign-server-generated:1"',
                "replayed": False,
            }
        }


class CampaignCoreFailureService(CampaignCoreService):
    async def start_campaign(self, intent, **values):
        del intent, values
        raise CampaignCoreCreateDisabled("r124_campaign_create_disabled")

    async def recover_campaign(self, **values):
        del values
        raise CampaignCoreEtagConflict("r124_etag_conflict")

    async def read_campaign(self, **values):
        del values
        raise CampaignStatusNotFound("r124_campaign_not_found")

    async def inspect_campaign(self, **values):
        del values
        raise CampaignStatusNotFound("r124_campaign_not_found")

def test_r124_openapi_exposes_only_the_frozen_campaign_core_surface() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()

    expected = {
        "/api/v1/campaign-core/options/engagements",
        "/api/v1/campaign-core/options/targets",
        "/api/v1/campaign-core/options/risk-profiles",
        "/api/v1/campaign-core/campaigns",
        "/api/v1/campaign-core/campaigns/{campaign_id}",
        "/api/v1/campaign-core/campaigns/{campaign_id}/inspector",
        "/api/v1/campaign-core/attention",
        "/api/v1/campaign-core/campaigns/{campaign_id}/stop",
        "/api/v1/campaign-core/campaigns/{campaign_id}/revoke",
    }
    assert expected.issubset(schema["paths"])
    request = schema["components"]["schemas"]["R124CampaignStartRequest"]
    assert request["additionalProperties"] is False
    assert set(request["properties"]) == {
        "engagement_binding",
        "target_binding",
        "objective",
        "risk_profile",
    }
    forbidden = {
        "tenant_id", "principal_id", "engagement_id", "target_id", "campaign_id",
        "workflow_id", "job_id", "runner_id", "tool_fqn", "adapter_id", "provider",
        "url", "command", "idempotency_key",
    }
    assert forbidden.isdisjoint(request["properties"])
    aggregate = schema["components"]["schemas"]["R124CampaignAggregateResponse"]
    inspector = schema["components"]["schemas"]["R124CampaignInspectorResponse"]
    assert aggregate["properties"]["data"]["$ref"].endswith("/R124CampaignAggregateData")
    assert inspector["properties"]["data"]["$ref"].endswith("/R124CampaignInspectorData")
    assert schema["paths"]["/api/v1/campaigns"]["post"]["deprecated"] is True


def test_r124_option_resolution_is_tenant_principal_and_page_bounded() -> None:
    service = CampaignCoreService()
    response = _request(
        create_app(test_issuer_enabled=True, r124_campaign_core_service=service),
        "GET",
        "/api/v1/campaign-core/options/engagements?limit=20",
        headers=AUTH,
    )

    assert response.status_code == 200, response.text
    assert response.json()["data"][0] == {
        "binding": "r124-engagement-opaque",
        "label": "Owned loopback engagement",
        "revision": "7",
        "freshness": "current",
        "eligible": True,
        "unavailable_reason": None,
    }
    assert service.calls == [("engagements", {
        "tenant_id": "tenant-r124",
        "principal_id": "operator-r124",
        "limit": 20,
        "cursor": None,
        "now": service.calls[0][1]["now"],
    })]
    assert service.calls[0][1]["now"].tzinfo is not None


def test_r124_start_uses_auth_and_transport_idempotency_only() -> None:
    service = CampaignCoreService()
    response = _request(
        create_app(test_issuer_enabled=True, r124_campaign_core_service=service),
        "POST",
        "/api/v1/campaign-core/campaigns",
        headers=MUTATION,
        json={
            "engagement_binding": "r124-engagement-opaque",
            "target_binding": "r124-target-opaque",
            "objective": "Assess HTTP security posture",
            "risk_profile": "r124-risk-opaque",
        },
    )

    assert response.status_code == 202, response.text
    assert response.json()["data"]["campaign_id"] == "campaign-server-generated"
    name, call = service.calls[0]
    assert name == "start"
    assert call["tenant_id"] == "tenant-r124"
    assert call["principal_id"] == "operator-r124"
    assert call["idempotency_key"] == "transport-generated-r124-request"
    assert call["intent"].model_dump() == {
        "engagement_binding": "r124-engagement-opaque",
        "target_binding": "r124-target-opaque",
        "objective": "Assess HTTP security posture",
        "risk_profile": "r124-risk-opaque",
    }


def test_legacy_caller_id_campaign_create_rejects_interactive_identity() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "POST",
        "/api/v1/campaigns",
        headers={
            **MUTATION,
            "X-RedAgent-ROE-Version": "roe-r124",
        },
        json={
            "campaign_id": "caller-id-forbidden",
            "engagement_id": "engagement-caller-id",
            "roe_version_id": "roe-r124",
            "name": "Legacy browser attempt",
            "jobs": [{
                "job_id": "legacy-job-caller-id",
                "request": {
                    "capability": "synthetic-noop",
                    "approval_timeout_seconds": 3600,
                    "max_activity_attempts": 3,
                    "budget_reference": "legacy-budget-caller-id",
                },
            }],
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "m2m_compatibility_required"


def test_r124_pagination_and_extra_input_fail_closed_before_service_call() -> None:
    service = CampaignCoreService()
    app = create_app(test_issuer_enabled=True, r124_campaign_core_service=service)

    oversized = _request(
        app,
        "GET",
        "/api/v1/campaign-core/options/engagements?limit=51",
        headers=AUTH,
    )
    extra = _request(
        app,
        "POST",
        "/api/v1/campaign-core/campaigns",
        headers=MUTATION,
        json={
            "engagement_binding": "r124-engagement-opaque",
            "target_binding": "r124-target-opaque",
            "objective": "Assess HTTP security posture",
            "risk_profile": "r124-risk-opaque",
            "runner_id": "caller-selected-runner",
        },
    )

    assert oversized.status_code == 422
    assert extra.status_code == 422
    assert service.calls == []


def test_r124_feature_rollback_and_etag_conflict_are_typed_fail_closed_errors() -> None:
    service = CampaignCoreFailureService()
    app = create_app(test_issuer_enabled=True, r124_campaign_core_service=service)
    disabled = _request(
        app,
        "POST",
        "/api/v1/campaign-core/campaigns",
        headers=MUTATION,
        json={
            "engagement_binding": "r124-engagement-opaque",
            "target_binding": "r124-target-opaque",
            "objective": "Assess HTTP security posture",
            "risk_profile": "r124-risk-opaque",
        },
    )
    conflict = _request(
        app,
        "POST",
        "/api/v1/campaign-core/campaigns/campaign-current/stop",
        headers={**MUTATION, "If-Match": '"campaign-current:4"'},
        json={"reason": "Emergency operator requested containment"},
    )

    assert disabled.status_code == 503
    assert disabled.json()["error"]["code"] == "campaign_create_disabled"
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "etag_conflict"


def test_r124_unknown_campaign_reads_are_typed_not_found_errors() -> None:
    app = create_app(
        test_issuer_enabled=True,
        r124_campaign_core_service=CampaignCoreFailureService(),
    )

    aggregate = _request(
        app,
        "GET",
        "/api/v1/campaign-core/campaigns/campaign-missing",
        headers=AUTH,
    )
    inspector = _request(
        app,
        "GET",
        "/api/v1/campaign-core/campaigns/campaign-missing/inspector",
        headers=AUTH,
    )

    assert aggregate.status_code == 404
    assert aggregate.json()["error"]["code"] == "campaign_not_found"
    assert inspector.status_code == 404
    assert inspector.json()["error"]["code"] == "campaign_not_found"


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())
