from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from redagent_platform.api.app import create_app


AUTH = {"X-RedAgent-Test-Subject": "operator-a", "X-RedAgent-Test-Tenant": "tenant-a",
        "X-RedAgent-Test-Permissions": "campaign:create", "X-RedAgent-Policy-Reference": "policy-a",
        "X-RedAgent-ROE-Version": "roe-a", "Idempotency-Key": "child-api-a"}
PATH = "/api/v1/autonomous-campaigns/campaign-a/child-replan"


def test_child_api_is_registered_and_unconfigured_dependency_denies_after_guards():
    response = TestClient(create_app(test_issuer_enabled=True)).post(PATH, headers=AUTH, json={"expected_revision": 7})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "autonomous_campaign_not_configured"


@pytest.mark.parametrize("field", ["facts", "authority", "budget", "consumed_replans", "mode", "plan", "producer"])
def test_child_api_rejects_client_owned_proof_or_enablement(field):
    response = TestClient(create_app(test_issuer_enabled=True)).post(PATH, headers=AUTH,
        json={"expected_revision": 7, field: "untrusted"})
    assert response.status_code == 422


@pytest.mark.parametrize("field, expected", [("X-RedAgent-Test-Permissions", 403), ("X-RedAgent-ROE-Version", 400),
                                            ("X-RedAgent-Policy-Reference", 400), ("Idempotency-Key", 400)])
def test_child_api_requires_permission_roe_policy_and_idempotency(field, expected):
    headers = {name: value for name, value in AUTH.items() if name != field}
    response = TestClient(create_app(test_issuer_enabled=True)).post(PATH, headers=headers, json={"expected_revision": 7})
    assert response.status_code == expected
