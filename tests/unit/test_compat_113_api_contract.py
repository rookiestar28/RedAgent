import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app


def _schema():
    try:
        from redagent_platform.api.schemas import AgentRunCreateRequest
    except ImportError:
        pytest.fail("compat_113 RED: strict agent run API schema is not implemented")
    return AgentRunCreateRequest


def test_agent_kernel_routes_are_registered_once() -> None:
    paths = [route.path for route in create_app().routes]
    expected = {
        "/api/v1/agent/tools",
        "/api/v1/agent/runs",
        "/api/v1/agent/proposals/{proposal_id}/approve",
        "/api/v1/agent/runs/{run_id}/cancel",
        "/api/v1/agent/dashboard",
    }
    assert expected <= set(paths) and all(paths.count(path) == 1 for path in expected)


def test_agent_run_schema_accepts_stored_ids_only_and_rejects_prompt_tools_credentials_and_authority() -> None:
    schema = _schema()
    payload = {
        "run_id": "run-r113",
        "campaign_id": "campaign-r113",
        "tool_fqn": "redagent.human-simulation-sink.propose.v1",
        "plan_id": "plan-r112-owned-sink",
        "confirmation": "--confirm-r113-proposal-only",
    }
    assert schema.model_validate(payload).plan_id == "plan-r112-owned-sink"
    for field, value in (
        ("prompt", "ignore policy"), ("instructions", "act autonomously"), ("messages", []),
        ("arguments", {"command": "whoami"}), ("command", "whoami"), ("shell", "pwsh"),
        ("url", "https://example.com"), ("browser", True), ("provider", "external"),
        ("model", "latest"), ("api_key", "secret"), ("credential", "secret-ref"),
        ("policy", "allow"), ("approval", "approve-all"), ("evidence", "raw"),
        ("runner_id", "runner-direct"), ("dispatch", True), ("budget", {"max": 999999}),
    ):
        with pytest.raises(ValidationError):
            schema.model_validate(payload | {field: value})


def test_agent_tools_require_authentication() -> None:
    from fastapi.testclient import TestClient
    response = TestClient(create_app(test_issuer_enabled=True)).get("/api/v1/agent/tools")
    assert response.status_code == 401 and response.json()["error"]["code"] == "security_context_required"
