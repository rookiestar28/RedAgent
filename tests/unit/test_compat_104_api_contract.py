from __future__ import annotations

from pydantic import ValidationError
import pytest

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import JobCreateRequest, ZapCompileRequest, ZapRunCreateRequest
from redagent_platform.persistence.models import metadata


def test_r104_routes_are_typed_and_separate_compile_run_cancel_and_dashboard() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    paths = schema["paths"]
    assert paths["/api/v1/zap/profiles"]["get"]["operationId"] == "list_zap_profiles"
    assert paths["/api/v1/zap/plans"]["post"]["operationId"] == "compile_zap_plan"
    assert paths["/api/v1/zap/runs"]["post"]["operationId"] == "create_zap_run"
    assert paths["/api/v1/zap/runs/{run_id}/cancel"]["post"]["operationId"] == "cancel_zap_run"
    assert paths["/api/v1/zap/dashboard"]["get"]["operationId"] == "get_zap_dashboard"
    for model in ("ZapCompileRequest", "ZapRunCreateRequest", "ZapCancelRequest"):
        assert schema["components"]["schemas"][model]["additionalProperties"] is False


def test_zap_dashboard_projects_only_domain_owned_target_and_runner_choices() -> None:
    schemas = create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]
    dashboard_properties = schemas["ZapDashboardData"]["properties"]
    assert {"target_options", "runner_options"} <= set(dashboard_properties)
    assert schemas["ZapTargetOptionData"]["additionalProperties"] is False
    assert schemas["ZapRunnerOptionData"]["additionalProperties"] is False
    assert set(schemas["ZapTargetOptionData"]["properties"]) == {
        "target_id", "attestation_sha256", "attestation_state", "non_production", "expires_at",
    }
    assert set(schemas["ZapRunnerOptionData"]["properties"]) == {
        "runner_id", "environment", "network_plane", "registration_state", "expires_at",
    }


def test_compile_and_run_contracts_have_no_target_url_yaml_script_addon_or_native_api_surface() -> None:
    compile_properties = set(create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]["ZapCompileRequest"]["properties"])
    assert compile_properties == {
        "plan_id", "profile_id", "target_id", "target_attestation_sha256",
        "policy_decision_id", "policy_revision", "roe_version_id", "credential_reference_ids",
    }
    assert not {
        "url", "target_url", "yaml", "script", "addon", "flags", "command",
        "native_api", "image", "headers", "cookie", "password", "token",
    }.intersection(compile_properties)
    run_properties = set(create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]["ZapRunCreateRequest"]["properties"])
    assert run_properties == {"run_id", "plan_id", "job_id", "runner_id"}


def test_compile_schema_accepts_only_owned_fixture_and_closed_profiles() -> None:
    base = {
        "plan_id": "plan-r104",
        "profile_id": "zap-passive-v1",
        "target_id": "r104-owned-web-fixture",
        "target_attestation_sha256": "a" * 64,
        "policy_decision_id": "decision-r104",
        "policy_revision": "r099-v1",
        "roe_version_id": "roe-r104",
        "credential_reference_ids": [],
    }
    assert ZapCompileRequest.model_validate(base).profile_id == "zap-passive-v1"
    with pytest.raises(ValidationError):
        ZapCompileRequest.model_validate({**base, "target_id": "example.com"})
    with pytest.raises(ValidationError):
        ZapCompileRequest.model_validate({**base, "profile_id": "zap-full-scan"})
    with pytest.raises(ValidationError):
        ZapCompileRequest.model_validate({**base, "url": "https://example.com"})
    with pytest.raises(ValidationError):
        ZapRunCreateRequest.model_validate({
            "run_id": "run-r104", "plan_id": "plan-r104", "job_id": "job-r104",
            "runner_id": "runner-r104", "flags": "-config api.disablekey=true",
        })


def test_zap_capability_is_admitted_only_as_a_typed_durable_job() -> None:
    job = JobCreateRequest.model_validate({
        "job_id": "job-r104", "engagement_id": "engagement-r104", "roe_version_id": "roe-r104",
        "request": {
            "capability": "zap-controlled-runtime", "approval_timeout_seconds": 600,
            "max_activity_attempts": 1, "budget_reference": "budget-r104",
        },
    })
    assert job.request.capability == "zap-controlled-runtime"
    with pytest.raises(ValidationError):
        JobCreateRequest.model_validate({
            **job.model_dump(), "request": {**job.request.model_dump(), "profile_id": "zap-passive-v1"},
        })


def test_revision_0011_tables_are_present_in_runtime_metadata() -> None:
    assert {
        "zap_profile_revisions", "zap_target_attestations", "zap_compiled_plans", "zap_runs", "zap_run_steps",
        "zap_gateway_decisions", "zap_normalized_alerts", "zap_cancellation_receipts",
        "zap_cleanup_receipts",
    } <= set(metadata.tables)
