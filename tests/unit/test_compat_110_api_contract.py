import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import ArtifactCompileRequest


def test_artifact_posture_routes_are_registered_once() -> None:
    paths = [route.path for route in create_app().routes]
    expected = {"/api/v1/artifact-posture/profiles", "/api/v1/artifact-posture/plans", "/api/v1/artifact-posture/runs", "/api/v1/artifact-posture/runs/{run_id}/cancel", "/api/v1/artifact-posture/dashboard"}
    assert expected <= set(paths) and all(paths.count(path) == 1 for path in expected)


def test_compile_schema_rejects_repository_content_credentials_rules_and_commands() -> None:
    payload = {"plan_id": "plan-r110", "profile_id": "r110-repository-snapshot-v1", "artifact_binding_id": "binding-r110",
        "policy_decision_id": "policy-r110", "policy_revision": "r110-v1", "roe_version_id": "roe-r110",
        "reservation_id": "reservation-r110", "artifact_lease_id": "binding-r110", "confirmation": "--confirm-r110-canonical-fixture"}
    assert ArtifactCompileRequest.model_validate(payload).profile_id == "r110-repository-snapshot-v1"
    for field, value in (("repository_url", "https://example.invalid/repo"), ("token", "opaque"), ("archive_path", "../input.zip"),
        ("content", "source"), ("command", "npm install"), ("scanner_flags", ["--all"]), ("rules", {"custom": True}),
        ("workflow", "dispatch"), ("mobile_binary", "app.apk")):
        with pytest.raises(ValidationError): ArtifactCompileRequest.model_validate(payload | {field: value})


def test_artifact_profiles_require_authentication() -> None:
    from fastapi.testclient import TestClient

    response = TestClient(create_app(test_issuer_enabled=True)).get("/api/v1/artifact-posture/profiles")
    assert response.status_code == 401 and response.json()["error"]["code"] == "security_context_required"


def test_artifact_dashboard_projects_only_domain_owned_execution_choices() -> None:
    schema = create_app().openapi()["components"]["schemas"]
    dashboard = schema["ArtifactDashboardData"]["properties"]
    assert {"binding_options", "runner_options", "job_options", "reservation_options"} <= dashboard.keys()
    assert set(schema["ArtifactBindingOptionData"]["properties"]) == {
        "binding_id", "artifact_kind", "declared_files", "declared_bytes", "binding_state", "expires_at",
    }
