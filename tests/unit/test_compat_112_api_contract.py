import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import HumanSimulationCompileRequest


def test_human_simulation_routes_are_registered_once():
    paths = [route.path for route in create_app().routes]
    expected = {"/api/v1/human-simulation/campaigns", "/api/v1/human-simulation/plans",
        "/api/v1/human-simulation/runs", "/api/v1/human-simulation/runs/{run_id}/stop",
        "/api/v1/human-simulation/dashboard"}
    assert expected <= set(paths) and all(paths.count(path) == 1 for path in expected)


def test_compile_schema_accepts_stored_ids_only_and_rejects_delivery_content_and_people():
    payload = {"plan_id": "plan-r112", "campaign_id": "r112-sink-email-canary-v1", "approval_id": "approval-r112",
        "policy_decision_id": "policy-r112", "policy_revision": "r112-v1", "roe_version_id": "roe-r112",
        "reservation_id": "reservation-r112", "delivery_lease_id": "lease-r112", "stop_switch_id": "stop-r112",
        "quota_id": "quota-r112", "confirmation": "--confirm-r112-synthetic-sink-only"}
    assert HumanSimulationCompileRequest.model_validate(payload).campaign_id == "r112-sink-email-canary-v1"
    for field, value in (("recipient", "person@example.com"), ("recipients", ["person@example.com"]), ("domain", "example.com"),
        ("sender", "ceo@example.com"), ("subject", "Urgent"), ("body", "Click now"), ("template", "native"),
        ("url", "https://example.com"), ("attachment", "file"), ("provider", "smtp"), ("token", "opaque"),
        ("credential_fields", ["password"]), ("tracking", True), ("command", "sendmail")):
        with pytest.raises(ValidationError):
            HumanSimulationCompileRequest.model_validate(payload | {field: value})


def test_campaigns_require_authentication():
    from fastapi.testclient import TestClient
    response = TestClient(create_app(test_issuer_enabled=True)).get("/api/v1/human-simulation/campaigns")
    assert response.status_code == 401 and response.json()["error"]["code"] == "security_context_required"


def test_human_dashboard_projects_only_domain_owned_execution_choices():
    schema = create_app().openapi()["components"]["schemas"]
    dashboard = schema["HumanSimulationDashboardData"]["properties"]
    assert {"approval_options", "runner_options", "job_options", "reservation_options"} <= dashboard.keys()
    assert set(schema["HumanSimulationApprovalOptionData"]["properties"]) == {
        "approval_id", "campaign_id", "approval_state", "expires_at",
    }
