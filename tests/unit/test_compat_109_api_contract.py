import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import IdentitySaasCompileRequest


def test_identity_posture_routes_are_registered_once() -> None:
    paths = [route.path for route in create_app().routes]
    expected = {
        "/api/v1/identity-posture/profiles", "/api/v1/identity-posture/plans",
        "/api/v1/identity-posture/runs", "/api/v1/identity-posture/runs/{run_id}/cancel",
        "/api/v1/identity-posture/dashboard",
    }
    assert expected <= set(paths)
    assert all(paths.count(path) == 1 for path in expected)


def test_compile_schema_rejects_endpoint_credentials_queries_and_graph_controls() -> None:
    payload = {
        "plan_id": "plan-r109", "profile_id": "r109-okta-emulator-v1",
        "tenant_binding_id": "r109-okta-binding-v1", "policy_decision_id": "policy-r109",
        "policy_revision": "r109-v1", "roe_version_id": "roe-r109",
        "reservation_id": "reservation-r109", "credential_lease_id": "lease-r109",
        "confirmation": "--confirm-r109-local-lab",
    }
    assert IdentitySaasCompileRequest.model_validate(payload).profile_id == "r109-okta-emulator-v1"
    for field, value in (("endpoint", "https://example.invalid"), ("token", "opaque"),
        ("query", "$select=id"), ("scopes", ["okta.users.manage"]), ("graph_export", True),
        ("tenant_id", "other"), ("command", "external-tool")):
        with pytest.raises(ValidationError):
            IdentitySaasCompileRequest.model_validate(payload | {field: value})


def test_identity_profiles_require_authentication() -> None:
    from fastapi.testclient import TestClient

    response = TestClient(create_app(test_issuer_enabled=True)).get("/api/v1/identity-posture/profiles")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "security_context_required"


def test_identity_dashboard_projects_only_domain_owned_execution_choices() -> None:
    schema = create_app().openapi()["components"]["schemas"]
    dashboard = schema["IdentitySaasDashboardData"]["properties"]
    assert {
        "binding_options", "runner_options", "job_options", "reservation_options", "lease_options",
    } <= dashboard.keys()
    assert set(schema["IdentitySaasBindingOptionData"]["properties"]) == {
        "binding_id", "profile_id", "provider_tenant_id", "audience", "consent_mode",
        "permission_digest", "binding_state",
    }
    assert set(schema["IdentitySaasLeaseOptionData"]["properties"]) == {
        "lease_id", "job_id", "roe_version_id", "permission_digest", "lease_state", "expires_at",
    }
