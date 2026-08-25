from __future__ import annotations

import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import NetworkCompileRequest


def test_network_dashboard_projects_only_domain_owned_execution_choices() -> None:
    schemas = create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]
    properties = schemas["NetworkDashboardData"]["properties"]
    assert {"target_options", "runner_options", "job_options", "reservation_options"} <= set(properties)
    assert set(schemas["NetworkTargetOptionData"]["properties"]) == {
        "target_set_id", "target_set_state", "non_production", "no_public_route",
        "no_direct_target_route", "expires_at",
    }
    assert set(schemas["NetworkRunnerOptionData"]["properties"]) == {
        "runner_id", "environment", "network_plane", "required_policy_revision", "registration_state", "expires_at",
    }
    assert set(schemas["NetworkJobOptionData"]["properties"]) == {
        "job_id", "engagement_id", "roe_version_id", "status", "current_gate", "dispatch_blocked", "stop_requested",
    }
    assert set(schemas["NetworkReservationOptionData"]["properties"]) == {
        "reservation_id", "reserved_amount", "consumed_amount", "released_amount",
        "remaining_amount", "reservation_state", "expires_at",
    }
    assert "policy_revision" in schemas["NetworkPlanData"]["properties"]


def test_network_routes_are_registered_with_strict_stored_identifier_contracts() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    assert {
        "/api/v1/network-assessment/profiles",
        "/api/v1/network-assessment/plans",
        "/api/v1/network-assessment/runs",
        "/api/v1/network-assessment/runs/{run_id}/cancel",
        "/api/v1/network-assessment/dashboard",
    } <= set(schema["paths"])
    compile_schema = schema["components"]["schemas"]["NetworkCompileRequest"]
    assert compile_schema["additionalProperties"] is False
    assert set(compile_schema["properties"]) == {
        "plan_id", "profile_id", "target_set_id", "policy_decision_id",
        "policy_revision", "roe_version_id", "reservation_id", "confirmation",
    }
    operation = schema["paths"]["/api/v1/network-assessment/plans"]["post"]
    assert all(parameter["in"] == "header" for parameter in operation.get("parameters", []))
    assert operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/NetworkCompileRequest"
    }


def test_network_compile_schema_rejects_native_target_and_transport_fields() -> None:
    payload = {
        "plan_id": "plan-r107",
        "profile_id": "tcp-connect-discovery-v1",
        "target_set_id": "r107-local-fixture",
        "policy_decision_id": "decision-r107",
        "policy_revision": "r099-v1",
        "roe_version_id": "roe-r107",
        "reservation_id": "reservation-r107",
        "confirmation": "--confirm-r107-local-lab",
    }
    assert NetworkCompileRequest.model_validate(payload).target_set_id == "r107-local-fixture"
    for field, value in (
        ("hostname", "fixture.local"), ("cidr", "10.0.0.0/8"),
        ("ports", [1, 65535]), ("flags", ["-sS"]), ("command", "nmap"),
    ):
        with pytest.raises(ValidationError):
            NetworkCompileRequest.model_validate(payload | {field: value})
