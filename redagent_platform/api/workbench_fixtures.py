from __future__ import annotations


def _fixture_draft_binding() -> dict[str, object]:
    return {
        "binding_id": "binding-r114-fixture",
        "campaign_id": "campaign-r114",
        "campaign_label": "R114 synthetic campaign",
        "plan_id": "plan-r114-stored",
        "plan_label": "Stored fixture plan",
        "successor_plan_id": "plan-r114-successor",
        "successor_plan_label": "Revised fixture plan",
        "target_id": "target-r114-owned",
        "target_label": "Owned synthetic target",
        "tool_fqn": "redagent.r114-mcp-fixture.propose.v1",
        "binding_state": "available",
        "fixture_only": True,
        "egress_class": "none",
    }


def _matches_fixture_draft_binding(*, campaign_id: str, plan_id: str, target_id: str, tool_fqn: str) -> bool:
    binding = _fixture_draft_binding()
    return (campaign_id, plan_id, target_id, tool_fqn) == (
        binding["campaign_id"],
        binding["plan_id"],
        binding["target_id"],
        binding["tool_fqn"],
    )


def _matches_fixture_successor_plan(plan_id: str) -> bool:
    return plan_id == _fixture_draft_binding()["successor_plan_id"]
