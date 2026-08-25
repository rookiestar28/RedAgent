from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib

import pytest


NOW = datetime(2026, 7, 12, 8, 0, tzinfo=timezone.utc)


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.workbench.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_114 RED: workbench module {name!r} is not implemented")


def _proposal(**overrides: object):
    contracts = _module("contracts")
    values = {
        "proposal_id": "proposal-r114-v1",
        "campaign_id": "campaign-r114",
        "revision": 1,
        "predecessor_proposal_id": None,
        "server_id": "redagent-fixture",
        "server_inventory_sha256": "1" * 64,
        "tool_fqn": "redagent.fixture.campaign.propose.v1",
        "tool_schema_sha256": "2" * 64,
        "sanitized_arguments": {"plan_id": "plan-r114-stored"},
        "target_ids": ("target-r114-owned",),
        "roe_version_id": "roe-r114-approved",
        "policy_revision": "r099-v1",
        "policy_decision_id": "decision-r114-allow",
        "credential_class": "none",
        "egress_class": "none",
        "side_effects": ("proposal_only",),
        "disclosure_fields": ("stored_plan_id",),
        "budget_sha256": "3" * 64,
        "approval_id": "approval-r114-v1",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=2),
    }
    values.update(overrides)
    return contracts.WorkbenchProposal(**values)


def test_trust_lanes_are_closed_and_keep_reviewer_conclusion_separate() -> None:
    contracts = _module("contracts")
    assert {lane.value for lane in contracts.TrustLane} == {
        "trusted_operator", "immutable_authority", "untrusted_external", "ai_suggestion",
        "approval", "execution_result", "reviewer_conclusion",
    }
    with pytest.raises(ValueError, match="workbench_lane_invalid"):
        contracts.WorkbenchItem(item_id="item-1", lane="trusted", summary="not typed", provenance_sha256="a" * 64)


def test_exact_proposal_digest_binds_disclosure_authority_budget_inventory_and_expiry() -> None:
    contracts = _module("contracts")
    original = _proposal()
    digest = contracts.proposal_sha256(original)
    for field, value in (
        ("server_inventory_sha256", "9" * 64),
        ("sanitized_arguments", {"plan_id": "plan-r114-other"}),
        ("target_ids", ("target-r114-other",)),
        ("roe_version_id", "roe-r114-other"),
        ("disclosure_fields", ("stored_plan_id", "finding_summary")),
        ("budget_sha256", "8" * 64),
    ):
        assert digest != contracts.proposal_sha256(_proposal(**{field: value}))


def test_edit_creates_successor_and_invalidates_prior_approval_without_mutating_original() -> None:
    lifecycle = _module("lifecycle")
    original = _proposal()
    result = lifecycle.create_successor(original, proposal_id="proposal-r114-v2",
                                        sanitized_arguments={"plan_id": "plan-r114-revised"}, now=NOW + timedelta(seconds=10))
    assert result.predecessor == original
    assert result.successor.revision == 2 and result.successor.predecessor_proposal_id == original.proposal_id
    assert result.successor.approval_id is None
    assert result.invalidated_approval_id == "approval-r114-v1"


def test_workbench_contracts_never_store_raw_credentials_tokens_evidence_or_reasoning() -> None:
    contracts = _module("contracts")
    fields = set(contracts.WorkbenchProposal.__dataclass_fields__) | set(contracts.WorkbenchItem.__dataclass_fields__)
    assert not fields.intersection({"credential", "secret", "token", "raw_evidence", "reasoning", "prompt", "message"})
