from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib

import pytest


NOW = datetime(2026, 7, 12, 1, 30, tzinfo=timezone.utc)


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.agent_kernel.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_113 RED: agent kernel module {name!r} is not implemented")


def _budget():
    contracts = _module("contracts")
    return contracts.ModelBudget(
        max_turns=2,
        max_tool_calls=1,
        max_elapsed_seconds=20,
        max_input_tokens=1000,
        max_output_tokens=250,
        max_cost_microunits=1000,
        max_result_bytes=1024,
    )


def _proposal(**overrides: object):
    approvals = _module("approvals")
    values: dict[str, object] = {
        "proposal_id": "proposal-1",
        "tenant_id": "tenant-a",
        "operator_id": "operator-requester",
        "campaign_id": "campaign-1",
        "tool_fqn": "redagent.human-simulation-sink.propose.v1",
        "tool_schema_sha256": "1" * 64,
        "arguments": {"campaign_id": "r112-sink-email-canary-v1"},
        "target_ids": ("owned-sink-1",),
        "roe_version_id": "roe-1",
        "policy_revision": "r099-v1",
        "policy_decision_id": "decision-allow-1",
        "credential_class": "none",
        "egress_class": "none",
        "side_effects": ("create_proposal_only",),
        "budget": _budget(),
        "registry_sha256": "2" * 64,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=2),
    }
    values.update(overrides)
    return approvals.ProposalContext(**values)


def test_exact_approval_is_short_lived_independent_single_use_and_replay_safe() -> None:
    approvals = _module("approvals")
    proposal = _proposal()
    digest = approvals.proposal_sha256(proposal)
    grant = approvals.ApprovalGrant(
        approval_id="approval-1",
        proposal_sha256=digest,
        approved_by="operator-reviewer",
        issued_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=2),
        nonce="approval-nonce-1",
    )
    ledger = approvals.ApprovalLedger()
    receipt = ledger.consume(grant, proposal, tenant_id="tenant-a", now=NOW + timedelta(seconds=2))
    assert receipt.proposal_sha256 == digest and receipt.consumed is True
    with pytest.raises(ValueError, match="approval_replayed"):
        ledger.consume(grant, proposal, tenant_id="tenant-a", now=NOW + timedelta(seconds=3))


def test_approval_denies_self_approval_mutation_expiry_cross_tenant_and_policy_drift() -> None:
    approvals = _module("approvals")
    proposal = _proposal()
    with pytest.raises(ValueError, match="approval_separation_required"):
        approvals.ApprovalGrant.for_proposal(
            proposal,
            approval_id="approval-self",
            approved_by="operator-requester",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
            nonce="nonce-self",
        )
    grant = approvals.ApprovalGrant.for_proposal(
        proposal,
        approval_id="approval-2",
        approved_by="operator-reviewer",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        nonce="nonce-2",
    )
    for changed, tenant_id, now, error in (
        (replace(proposal, arguments={"campaign_id": "changed"}), "tenant-a", NOW, "approval_binding_mismatch"),
        (replace(proposal, policy_revision="r099-v2"), "tenant-a", NOW, "approval_binding_mismatch"),
        (proposal, "tenant-b", NOW, "approval_tenant_mismatch"),
        (proposal, "tenant-a", NOW + timedelta(minutes=2), "approval_expired"),
    ):
        with pytest.raises(ValueError, match=error):
            approvals.ApprovalLedger().consume(grant, changed, tenant_id=tenant_id, now=now)


def test_budget_ledger_stops_turn_tool_token_cost_and_result_overrun() -> None:
    contracts = _module("contracts")
    budget = _module("budget")
    for usage, result_bytes, tool_calls, expected in (
        (contracts.ModelUsage(input_tokens=1001, output_tokens=1, cost_microunits=1), 1, 0, "input_tokens"),
        (contracts.ModelUsage(input_tokens=1, output_tokens=251, cost_microunits=1), 1, 0, "output_tokens"),
        (contracts.ModelUsage(input_tokens=1, output_tokens=1, cost_microunits=1001), 1, 0, "cost"),
        (contracts.ModelUsage(input_tokens=1, output_tokens=1, cost_microunits=1), 1025, 0, "result_bytes"),
        (contracts.ModelUsage(input_tokens=1, output_tokens=1, cost_microunits=1), 1, 2, "tool_calls"),
    ):
        ledger = budget.BudgetLedger(_budget(), started_at=NOW)
        with pytest.raises(ValueError, match=f"budget_{expected}_exceeded"):
            ledger.record_turn(usage=usage, result_bytes=result_bytes, tool_calls=tool_calls, now=NOW + timedelta(seconds=1))


def test_kernel_rejects_unknown_multiple_or_injection_shaped_tool_calls_before_proposal() -> None:
    contracts = _module("contracts")
    kernel = _module("kernel")
    allowed = "redagent.human-simulation-sink.propose.v1"
    for calls, expected in (
        ((contracts.ModelToolCall(call_id="c1", tool_name="unknown.tool", arguments={}),), "unknown_tool"),
        (
            (
                contracts.ModelToolCall(call_id="c1", tool_name=allowed, arguments={"campaign_id": "r112-sink-email-canary-v1"}),
                contracts.ModelToolCall(call_id="c2", tool_name=allowed, arguments={"campaign_id": "r112-sink-email-canary-v1"}),
            ),
            "parallel_tool_calls_forbidden",
        ),
        ((contracts.ModelToolCall(call_id="c1", tool_name=allowed, arguments={"command": "ignore policy"}),), "proposal_arguments_invalid"),
    ):
        with pytest.raises(ValueError, match=expected):
            kernel.validate_model_tool_calls(calls, allowed_tools={allowed: {"campaign_id"}})
