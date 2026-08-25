from __future__ import annotations

from dataclasses import replace

import pytest

from redagent_platform.campaign_service.lineage import (
    CampaignTerminalLineageV1,
    NodeTerminalLineageV1,
    verify_success_lineage,
)


def _node(**overrides: object) -> NodeTerminalLineageV1:
    values: dict[str, object] = {
        "node_id": "node-primary",
        "capability_id": "zap-controlled-runtime",
        "capability_revision": 1,
        "effect_id": "effect-primary",
        "effect_receipt_sha256": "a" * 64,
        "execution_receipt_id": "execution-primary",
        "evidence_ids": ("evidence-primary",),
        "finding_import_id": "import-primary",
        "finding_issue_ids": ("issue-primary",),
        "no_finding_coverage": False,
        "retest_receipt_ids": ("retest-primary",),
        "cleanup_receipt_id": "cleanup-primary",
        "reconciliation_state": "confirmed",
    }
    values.update(overrides)
    return NodeTerminalLineageV1(**values)  # type: ignore[arg-type]


def _lineage(**overrides: object) -> CampaignTerminalLineageV1:
    values: dict[str, object] = {
        "schema_version": "redagent.r123-terminal-lineage/v1",
        "tenant_id": "tenant-r123",
        "campaign_id": "campaign-r123",
        "strategy_revision_id": "strategy-r123",
        "objective_sha256": "1" * 64,
        "resolved_envelope_sha256": "2" * 64,
        "context_snapshot_sha256": "3" * 64,
        "decision_sha256": "4" * 64,
        "plan_sha256": "5" * 64,
        "approval_receipt_id": "approval-r123",
        "approval_receipt_sha256": "6" * 64,
        "outbox_event_id": "outbox-r123",
        "workflow_id": "workflow-r123",
        "workflow_run_id": "run-r123",
        "nodes": (_node(),),
        "stop_or_replan_receipt_id": "stop-primary-satisfied",
        "residual_risk_receipt_id": "residual-risk-r123",
        "campaign_cleanup_receipt_id": "campaign-cleanup-r123",
        "terminal_reason": "objective_satisfied",
    }
    values.update(overrides)
    return CampaignTerminalLineageV1(**values)  # type: ignore[arg-type]


def test_complete_terminal_lineage_is_deterministic_and_supports_explicit_no_finding_coverage() -> None:
    first = _lineage()
    assert verify_success_lineage(first) == first.lineage_sha256

    coverage = _node(
        node_id="node-successor", capability_id="nuclei-trusted-runtime",
        effect_id="effect-successor", effect_receipt_sha256="b" * 64,
        execution_receipt_id="execution-successor", evidence_ids=("evidence-successor",),
        finding_import_id="import-successor", finding_issue_ids=(), no_finding_coverage=True,
        retest_receipt_ids=(), cleanup_receipt_id="cleanup-successor",
    )
    second = _lineage(
        nodes=(_node(), coverage), terminal_reason="corroboration_complete",
        stop_or_replan_receipt_id="stop-corroboration-complete",
    )
    assert verify_success_lineage(second) == second.lineage_sha256
    assert second.lineage_sha256 != first.lineage_sha256


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("evidence_ids", (), "r123_lineage_evidence_required"),
        ("finding_import_id", None, "r123_lineage_finding_import_required"),
        ("cleanup_receipt_id", None, "r123_lineage_cleanup_required"),
        ("retest_receipt_ids", (), "r123_lineage_retest_required"),
        ("reconciliation_state", "manual_review_required", "r123_lineage_reconciliation_not_success"),
    ),
)
def test_node_lineage_rejects_every_missing_terminal_owner(
    field: str, value: object, reason: str
) -> None:
    with pytest.raises(ValueError, match=reason):
        replace(_node(), **{field: value})


def test_campaign_lineage_rejects_duplicate_nodes_missing_links_and_manual_attention() -> None:
    with pytest.raises(ValueError, match="r123_lineage_node_duplicate"):
        _lineage(nodes=(_node(), _node()))
    with pytest.raises(ValueError, match="r123_lineage_workflow_run_required"):
        _lineage(workflow_run_id=None)
    with pytest.raises(ValueError, match="r123_lineage_terminal_reason_not_success"):
        _lineage(terminal_reason="manual_review_required")


def test_node_lineage_requires_one_unique_retest_receipt_per_issue() -> None:
    with pytest.raises(ValueError, match="r123_lineage_retest_count_mismatch"):
        _node(
            finding_issue_ids=("issue-primary", "issue-secondary"),
            retest_receipt_ids=("retest-primary",),
        )
    with pytest.raises(ValueError, match="r123_lineage_retest_receipt_ids_invalid"):
        _node(
            finding_issue_ids=("issue-primary", "issue-secondary"),
            retest_receipt_ids=("retest-primary", "retest-primary"),
        )
