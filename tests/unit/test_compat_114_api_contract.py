import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app


def _schema(name: str):
    try:
        from redagent_platform.api import schemas
        return getattr(schemas, name)
    except (ImportError, AttributeError):
        pytest.fail(f"compat_114 RED: strict API schema {name} is not implemented")


def test_workbench_and_mcp_routes_are_registered_once() -> None:
    paths = [route.path for route in create_app().routes]
    expected = {"/api/v1/workbench/dashboard", "/api/v1/workbench/drafts",
                "/api/v1/workbench/drafts/{draft_id}/successors", "/api/v1/workbench/drafts/{draft_id}/review",
                "/api/v1/mcp/servers/{registration_id}/freeze"}
    assert expected <= set(paths) and all(paths.count(path) == 1 for path in expected)


def test_draft_schema_accepts_only_stored_ids_and_rejects_transport_prompt_credentials_and_authority() -> None:
    schema = _schema("WorkbenchDraftCreateRequest")
    payload = {"draft_id": "draft-r114", "campaign_id": "campaign-r114", "plan_id": "plan-r114",
               "target_id": "target-r114", "tool_fqn": "redagent.r114-mcp-fixture.propose.v1",
               "confirmation": "--confirm-r114-structured-draft"}
    assert schema(**payload).plan_id == "plan-r114"
    for field in ("prompt", "message", "url", "server_url", "command", "args", "environment", "headers",
                  "token", "credential", "policy", "approval", "raw_evidence", "reasoning", "dispatch"):
        with pytest.raises(ValidationError):
            schema(**(payload | {field: "forbidden"}))


def test_successor_review_and_freeze_schemas_are_exact_and_closed() -> None:
    successor = _schema("WorkbenchSuccessorRequest")
    review = _schema("WorkbenchReviewRequest")
    freeze = _schema("McpFreezeRequest")
    assert successor(successor_draft_id="draft-r114-v2", plan_id="plan-r114-v2",
                     confirmation="--confirm-r114-successor-invalidates-approval").plan_id == "plan-r114-v2"
    assert review(decision_id="decision-r114", expected_proposal_sha256="a" * 64, decision="approve_exact",
                  confirmation="--confirm-r114-exact-review").decision == "approve_exact"
    assert freeze(expected_inventory_sha256="b" * 64,
                  confirmation="--confirm-r114-freeze-and-invalidate").expected_inventory_sha256 == "b" * 64
    for model, payload in ((successor, {"successor_draft_id": "x", "plan_id": "x",
                                       "confirmation": "--confirm-r114-successor-invalidates-approval", "url": "x"}),
                           (review, {"decision_id": "x", "expected_proposal_sha256": "a" * 64,
                                     "decision": "approve_all", "confirmation": "--confirm-r114-exact-review"}),
                           (freeze, {"expected_inventory_sha256": "b" * 64,
                                     "confirmation": "--confirm-r114-freeze-and-invalidate", "command": "x"})):
        with pytest.raises(ValidationError):
            model(**payload)


def test_dashboard_requires_authentication() -> None:
    from fastapi.testclient import TestClient
    response = TestClient(create_app()).get("/api/v1/workbench/dashboard")
    assert response.status_code == 401


def test_dashboard_schema_projects_only_typed_fixture_binding_options() -> None:
    schema = _schema("WorkbenchDashboardData")
    binding = {
        "binding_id": "binding-r114-fixture", "campaign_id": "campaign-r114",
        "campaign_label": "compat_114 synthetic campaign", "plan_id": "plan-r114-stored",
        "plan_label": "Stored fixture plan", "successor_plan_id": "plan-r114-successor",
        "successor_plan_label": "Revised fixture plan", "target_id": "target-r114-owned",
        "target_label": "Owned synthetic target", "tool_fqn": "redagent.r114-mcp-fixture.propose.v1",
        "binding_state": "available", "fixture_only": True, "egress_class": "none",
    }
    dashboard = schema(binding_options=[binding], registrations=[], attestations=[], inventories=[], items=[],
                       freezes=[], drafts=[], trust_items=[], disclosures=[], decisions=[], lifecycle=[])
    assert dashboard.binding_options[0].fixture_only is True
    assert dashboard.binding_options[0].egress_class == "none"


def test_fixture_binding_rejects_each_caller_selected_resource_drift() -> None:
    from redagent_platform.api.app import (
        _r114_fixture_draft_binding,
        _r114_matches_fixture_draft_binding,
        _r114_matches_fixture_successor_plan,
    )

    binding = _r114_fixture_draft_binding()
    selected = {name: str(binding[name]) for name in ("campaign_id", "plan_id", "target_id", "tool_fqn")}
    assert _r114_matches_fixture_draft_binding(**selected)
    for name in selected:
        assert not _r114_matches_fixture_draft_binding(**(selected | {name: f"caller-selected-{name}"}))
    assert _r114_matches_fixture_successor_plan(str(binding["successor_plan_id"]))
    assert not _r114_matches_fixture_successor_plan("caller-selected-plan")
