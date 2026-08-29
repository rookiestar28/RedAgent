from __future__ import annotations

import asyncio
from datetime import datetime

import httpx

from redagent_platform.api.app import create_app
from redagent_platform.campaign_service.operations import (
    CampaignOperationsSource,
    project_campaign_operations,
)


AUTH = {
    "X-RedAgent-Test-Subject": "operator-safe",
    "X-RedAgent-Test-Tenant": "tenant-safe",
    "X-RedAgent-Test-Permissions": "campaign:read,campaign:inspect",
}


class CampaignCoreReader:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def read_campaign(self, **values):
        self.calls.append(values)
        return {"data": {"campaign_id": values["campaign_id"]}}


class CampaignOperationsOwner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def read(self, **values):
        self.calls.append(values)
        return {
            "schema_version": "redagent.campaign-operations/v1",
            "aggregate_version": 7,
            "etag": '"campaign-safe:7"',
            "preparation_state": "not_prepared",
            "authority": {
                "state": "unavailable",
                "signed_authority_sha256": None,
                "authority_sha256": None,
                "lifecycle_epoch": None,
                "policy_revocation_epoch": None,
                "roe_revocation_epoch": None,
                "kill_switch_epoch": None,
                "expires_at": None,
            },
            "plan": {
                "revision_label": "Unavailable",
                "parent_revision_present": False,
                "nodes": [],
                "edges": [],
            },
            "validation": {"result": "unavailable", "reason": None, "counterexample_codes": []},
            "admission": {"outcome": "unavailable", "reason": None, "receipt_sha256": None},
            "budget": {"state": "unavailable", "dimensions": {}},
            "execution": {
                "state": "unavailable",
                "transition_count": 0,
                "max_transitions": 0,
                "stop_requested": False,
                "terminal_reason": None,
                "frontier": {},
            },
            "observations": [],
            "revisions": [],
            "audit": [],
            "evidence": {
                "effect_count": 0,
                "evidence_count": 0,
                "cleanup_state": "unavailable",
                "terminal_receipt_present": False,
                "export_state": "unavailable_without_verified_bundle",
            },
        }


class InvalidCampaignOperationsOwner(CampaignOperationsOwner):
    async def read(self, **values):
        self.calls.append(values)
        return {"etag": '"campaign-safe:7"', "schema_version": "wrong"}


class DeepInvalidCampaignOperationsOwner(CampaignOperationsOwner):
    async def read(self, **values):
        self.calls.append(values)
        deep: dict[str, object] = {}
        cursor = deep
        for _ in range(64):
            child: dict[str, object] = {}
            cursor["next"] = child
            cursor = child
        return project_campaign_operations(
            CampaignOperationsSource(
                campaign={"id": values["campaign_id"], "version": 1},
                execution={"input_payload": deep},
            ),
            now=values["now"],
        )


def test_campaign_operations_route_is_tenant_guarded_typed_and_etagged() -> None:
    core = CampaignCoreReader()
    owner = CampaignOperationsOwner()
    app = create_app(
        test_issuer_enabled=True,
        r124_campaign_core_service=core,
        campaign_operations_owner=owner,
    )

    response = _request(
        app,
        "GET",
        "/api/v1/campaign-core/campaigns/campaign-safe/operations",
        headers=AUTH,
    )

    assert response.status_code == 200, response.text
    assert response.headers["etag"] == '"campaign-safe:7"'
    assert response.json()["data"]["evidence"]["export_state"] == "unavailable_without_verified_bundle"
    assert core.calls[0]["tenant_id"] == "tenant-safe"
    assert core.calls[0]["principal_id"] == "operator-safe"
    assert owner.calls == [
        {
            "tenant_id": "tenant-safe",
            "campaign_id": "campaign-safe",
            "now": owner.calls[0]["now"],
        }
    ]
    assert isinstance(owner.calls[0]["now"], datetime)
    assert owner.calls[0]["now"].tzinfo is not None
    assert core.calls[0]["now"] == owner.calls[0]["now"]


def test_campaign_operations_has_no_client_authority_or_unverified_export_mutation() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    operations = schema["paths"]["/api/v1/campaign-core/campaigns/{campaign_id}/operations"]

    assert set(operations) == {"get"}
    assert operations["get"]["operationId"] == "get_campaign_operations"
    assert operations["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/CampaignOperationsResponse"
    )
    assert not any("approve" in path or "export" in path for path in schema["paths"] if "campaign-core" in path)


def test_campaign_operations_requires_inspect_permission_and_configured_owner() -> None:
    core = CampaignCoreReader()
    denied = _request(
        create_app(
            test_issuer_enabled=True,
            r124_campaign_core_service=core,
            campaign_operations_owner=CampaignOperationsOwner(),
        ),
        "GET",
        "/api/v1/campaign-core/campaigns/campaign-safe/operations",
        headers={**AUTH, "X-RedAgent-Test-Permissions": "campaign:read"},
    )
    unavailable = _request(
        create_app(test_issuer_enabled=True, r124_campaign_core_service=core),
        "GET",
        "/api/v1/campaign-core/campaigns/campaign-safe/operations",
        headers=AUTH,
    )

    assert denied.status_code == 403
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "campaign_operations_unavailable"


def test_campaign_operations_rejects_invalid_owner_projection_with_typed_error() -> None:
    response = _request(
        create_app(
            test_issuer_enabled=True,
            r124_campaign_core_service=CampaignCoreReader(),
            campaign_operations_owner=InvalidCampaignOperationsOwner(),
        ),
        "GET",
        "/api/v1/campaign-core/campaigns/campaign-safe/operations",
        headers=AUTH,
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "campaign_operations_projection_invalid"


def test_campaign_operations_converts_deep_stored_json_to_typed_503() -> None:
    response = _request(
        create_app(
            test_issuer_enabled=True,
            r124_campaign_core_service=CampaignCoreReader(),
            campaign_operations_owner=DeepInvalidCampaignOperationsOwner(),
        ),
        "GET",
        "/api/v1/campaign-core/campaigns/campaign-safe/operations",
        headers=AUTH,
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "campaign_operations_projection_invalid"


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())
