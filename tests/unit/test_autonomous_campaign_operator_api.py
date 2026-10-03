from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from redagent_platform.api.app import create_app
from tests.unit.test_autonomous_campaign_operator_service import _operator, _preparation
from tests.unit.test_compat_124_campaign_service import NOW, _operator_selections


READ = {
    "X-RedAgent-Test-Subject": "operator-r124", "X-RedAgent-Test-Tenant": "tenant-r124",
    "X-RedAgent-Test-Permissions": "campaign:read",
}
CREATE = {
    **READ, "X-RedAgent-Test-Permissions": "campaign:read,campaign:create",
    "X-RedAgent-Policy-Reference": "policy:operator-test", "Idempotency-Key": "operator-api-intent",
}


def test_operator_availability_is_guarded_truthful_and_no_store() -> None:
    client = TestClient(create_app(test_issuer_enabled=True))
    path = "/api/v1/campaign-core/operator-availability"
    assert client.get(path).status_code == 401
    denied = client.get(path, headers={**READ, "X-RedAgent-Test-Permissions": "job:read"})
    assert denied.status_code == 403
    response = client.get(path, headers=READ)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["data"] == {
        "canonical_configured": False, "create_available": False, "preparation_available": False,
        "status_available": False, "stop_available": False, "revoke_available": False,
        "mode": "disabled", "legacy_available": False, "reason": "operator_owner_not_configured",
    }


def _intent_app(monkeypatch):
    operator, core, starter, repository = _operator()
    monkeypatch.setattr("redagent_platform.campaign_service.operator_api._now", lambda: NOW)
    return TestClient(create_app(
        test_issuer_enabled=True, autonomous_campaign_operator_service=operator,
    )), vars(_operator_selections(core)), starter, repository


def test_normal_intent_route_uses_exact_four_selections_and_never_calls_legacy(monkeypatch) -> None:
    client, payload, starter, repository = _intent_app(monkeypatch)
    response = client.post("/api/v1/autonomous-campaigns", headers=CREATE, json=payload)
    assert response.status_code == 201
    data = response.json()["data"]
    assert data["mode"] == "plan_only" and data["lifecycle_state"] == "INTENT_CREATED"
    assert data["aggregate_revision"] == 1
    assert response.headers["etag"] == data["etag"]
    assert response.headers["cache-control"] == "no-store"
    assert data["etag"] == f'"autonomous-{data["campaign_id"]}:1"'
    assert len(repository.commands) == 1
    assert starter.replay_calls == starter.calls == []


@pytest.mark.parametrize("forbidden", ["mode", "campaign_id", "signed_authority", "expires_at", "certificate"])
def test_normal_intent_rejects_client_authority_fields_before_native_write(monkeypatch, forbidden) -> None:
    client, payload, starter, repository = _intent_app(monkeypatch)
    response = client.post(
        "/api/v1/autonomous-campaigns", headers=CREATE, json={**payload, forbidden: "client-value"},
    )
    assert response.status_code == 422
    assert repository.commands == starter.replay_calls == starter.calls == []


def test_normal_intent_auth_permission_and_idempotency_denial_precede_native_write(monkeypatch) -> None:
    client, payload, starter, repository = _intent_app(monkeypatch)
    path = "/api/v1/autonomous-campaigns"
    assert client.post(path, json=payload).status_code == 401
    assert client.post(path, headers=READ, json=payload).status_code == 403
    assert client.post(path, headers={key: value for key, value in CREATE.items()
                                     if key != "Idempotency-Key"}, json=payload).status_code == 400
    assert repository.commands == starter.replay_calls == starter.calls == []


def test_normal_preparation_requires_aggregate_etag_and_does_not_decide_or_admit(monkeypatch) -> None:
    operator, _source, repository, command = _preparation()
    monkeypatch.setattr("redagent_platform.campaign_service.operator_api._now", lambda: command.occurred_at)
    client = TestClient(create_app(test_issuer_enabled=True, autonomous_campaign_operator_service=operator))
    path = "/api/v1/autonomous-campaigns/campaign-a/prepare-plan"
    headers = {**CREATE, "X-RedAgent-Test-Tenant": "tenant-a",
               "X-RedAgent-Test-Subject": "operator-a"}
    assert client.post(path, headers=headers, json={"expected_revision": 1}).status_code == 422
    stale = client.post(path, headers={**headers, "If-Match": '"autonomous-campaign-a:2"'},
                        json={"expected_revision": 1})
    assert stale.status_code == 409
    assert repository.stage_calls == repository.decision_calls == 0
    prepared = client.post(path, headers={**headers, "If-Match": '"autonomous-campaign-a:1"'},
                           json={"expected_revision": 1})
    assert prepared.status_code == 201
    assert prepared.json()["data"]["application_revision"] == 3
    assert prepared.json()["data"]["validation_result"] == "valid"
    assert prepared.headers["etag"] == repository.preview.etag
    assert repository.stage_calls == 1 and repository.decision_calls == 0
