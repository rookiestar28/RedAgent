import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import CloudCompileRequest


def test_cloud_dashboard_projects_only_domain_owned_execution_choices() -> None:
    schemas = create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]
    properties = schemas["CloudDashboardData"]["properties"]
    assert {"identity_options", "runner_options", "job_options", "reservation_options", "lease_options"} <= set(properties)
    assert set(schemas["CloudIdentityOptionData"]["properties"]) == {
        "binding_id", "profile_id", "provider", "expected_identity", "permission_digest", "binding_state",
    }
    assert set(schemas["CloudRunnerOptionData"]["properties"]) == {
        "runner_id", "environment", "network_plane", "required_policy_revision", "registration_state", "expires_at",
    }
    assert set(schemas["CloudJobOptionData"]["properties"]) == {
        "job_id", "engagement_id", "roe_version_id", "status", "current_gate", "dispatch_blocked", "stop_requested",
    }
    assert set(schemas["CloudReservationOptionData"]["properties"]) == {
        "reservation_id", "reserved_amount", "consumed_amount", "released_amount",
        "remaining_amount", "reservation_state", "expires_at",
    }
    assert set(schemas["CloudLeaseOptionData"]["properties"]) == {
        "lease_id", "job_id", "roe_version_id", "permission_digest", "lease_state", "expires_at",
    }
    assert "policy_revision" in schemas["CloudPlanData"]["properties"]


def test_cloud_routes_are_registered_with_strict_stored_identifier_contracts() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    assert {
        "/api/v1/cloud-posture/profiles",
        "/api/v1/cloud-posture/plans",
        "/api/v1/cloud-posture/runs",
        "/api/v1/cloud-posture/runs/{run_id}/cancel",
        "/api/v1/cloud-posture/dashboard",
    } <= set(schema["paths"])
    request_schema = schema["components"]["schemas"]["CloudCompileRequest"]
    assert request_schema["additionalProperties"] is False
    assert set(request_schema["properties"]) == {
        "plan_id", "profile_id", "identity_binding_id", "policy_decision_id",
        "policy_revision", "roe_version_id", "reservation_id", "credential_lease_id",
        "confirmation",
    }


def test_cloud_compile_schema_rejects_endpoint_credentials_native_options_and_paths() -> None:
    payload = {
        "plan_id": "plan-r108",
        "profile_id": "r108-aws-emulator-v1",
        "identity_binding_id": "r108-aws-identity-v1",
        "policy_decision_id": "decision-r108",
        "policy_revision": "r099-v1",
        "roe_version_id": "roe-r108",
        "reservation_id": "reservation-r108",
        "credential_lease_id": "lease-r108",
        "confirmation": "--confirm-r108-local-lab",
    }
    assert CloudCompileRequest.model_validate(payload).identity_binding_id == "r108-aws-identity-v1"
    for field, value in (
        ("endpoint", "http://127.0.0.1:1"), ("token", "opaque"),
        ("command", "prowler aws"), ("flags", ["--region", "all"]),
        ("path", "../tenant"), ("kubeconfig", "config"),
    ):
        with pytest.raises(ValidationError):
            CloudCompileRequest.model_validate(payload | {field: value})


def test_cloud_profiles_endpoint_requires_authentication() -> None:
    from fastapi.testclient import TestClient

    response = TestClient(create_app(test_issuer_enabled=True)).get("/api/v1/cloud-posture/profiles")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "security_context_required"
