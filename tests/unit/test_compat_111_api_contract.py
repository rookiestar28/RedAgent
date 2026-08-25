import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import PurpleCompileRequest


def test_purple_lab_routes_are_registered_once():
    paths = [route.path for route in create_app().routes]
    expected = {"/api/v1/purple-lab/abilities", "/api/v1/purple-lab/plans", "/api/v1/purple-lab/runs",
        "/api/v1/purple-lab/runs/{run_id}/kill", "/api/v1/purple-lab/dashboard"}
    assert expected <= set(paths) and all(paths.count(path) == 1 for path in expected)


def test_compile_schema_accepts_stored_ids_only_and_rejects_commands_payloads_and_targets():
    payload = {"plan_id": "plan-r111", "ability_id": "r111-file-stage-marker-v1", "lab_binding_id": "lab-r111",
        "approval_id": "approval-r111", "policy_decision_id": "policy-r111", "policy_revision": "r111-v1",
        "roe_version_id": "roe-r111", "reservation_id": "reservation-r111", "lease_id": "lease-r111",
        "kill_switch_id": "kill-r111", "quota_id": "quota-r111", "confirmation": "--confirm-r111-owned-disposable-lab"}
    assert PurpleCompileRequest.model_validate(payload).ability_id == "r111-file-stage-marker-v1"
    for field, value in (("command", "touch marker"), ("payload", "opaque"), ("target", "example.invalid"),
        ("path", "../escape"), ("content", "caller supplied"), ("native_ability", {"executor": "sh"}),
        ("plugin", "caldera"), ("credentials", {"token": "opaque"}), ("network", True)):
        with pytest.raises(ValidationError):
            PurpleCompileRequest.model_validate(payload | {field: value})


def test_purple_abilities_require_authentication():
    from fastapi.testclient import TestClient
    response = TestClient(create_app(test_issuer_enabled=True)).get("/api/v1/purple-lab/abilities")
    assert response.status_code == 401 and response.json()["error"]["code"] == "security_context_required"


def test_purple_dashboard_projects_only_domain_owned_execution_choices():
    schema = create_app().openapi()["components"]["schemas"]
    dashboard = schema["PurpleDashboardData"]["properties"]
    assert {"lab_options", "approval_options", "runner_options", "job_options", "reservation_options"} <= dashboard.keys()
    assert set(schema["PurpleLabOptionData"]["properties"]) == {
        "binding_id", "runner_id", "disposable", "production", "egress_allowed", "binding_state", "expires_at",
    }
    assert set(schema["PurpleApprovalOptionData"]["properties"]) == {
        "approval_id", "ability_id", "lab_binding_id", "approval_state", "expires_at",
    }
