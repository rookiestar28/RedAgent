from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.identity_saas.governance import (
    BaselineEvaluation, ExceptionAnnotation, GraphApproval, GraphEdge, GraphNode,
    apply_exception, build_sensitive_graph,
)


NOW = datetime(2026, 7, 11, 18, 30, tzinfo=timezone.utc)


def evaluation() -> BaselineEvaluation:
    return BaselineEvaluation(
        evaluation_id="evaluation-r109", tenant_id="tenant-r109",
        snapshot_sha256="1" * 64, baseline_id="scuba-local-v1", baseline_sha256="2" * 64,
        control_id="MS.AAD.3.1", resource_id="policy-mfa", passed=False,
        evaluated_at=NOW,
    )


def test_exception_is_independent_expiring_append_only_annotation() -> None:
    annotation = ExceptionAnnotation(
        exception_id="exception-r109", evaluation_id="evaluation-r109",
        tenant_id="tenant-r109", control_id="MS.AAD.3.1", resource_id="policy-mfa",
        justification="Approved temporary migration risk with compensating monitoring.",
        requested_by="requester-r109", approved_by="reviewer-r109",
        effective_at=NOW, expires_at=NOW + timedelta(days=7), supersedes_exception_id=None,
    )
    result = apply_exception(evaluation=evaluation(), annotation=annotation, now=NOW)
    assert result.evaluation.passed is False
    assert result.risk_state == "accepted-temporarily"
    assert result.annotation == annotation
    with pytest.raises(ValueError, match="identity_exception_separation_required"):
        apply_exception(evaluation=evaluation(), annotation=ExceptionAnnotation(
            **{**annotation.__dict__, "approved_by": "requester-r109"}
        ), now=NOW)
    with pytest.raises(ValueError, match="identity_exception_inactive"):
        apply_exception(evaluation=evaluation(), annotation=annotation, now=NOW + timedelta(days=8))


def test_sensitive_graph_requires_separate_approval_pseudonyms_and_closed_export_model_access() -> None:
    approval = GraphApproval(
        approval_id="graph-approval-r109", tenant_id="tenant-r109",
        approved_by="graph-reviewer-r109", approved_at=NOW,
        expires_at=NOW + timedelta(hours=4), restricted_role="identity-graph-reviewer",
        export_allowed=False, model_access_allowed=False, retention_hours=24,
    )
    graph = build_sensitive_graph(
        tenant_id="tenant-r109", approval=approval, now=NOW,
        nodes=(GraphNode(node_id="p:abc123", node_type="principal"), GraphNode(node_id="r:def456", node_type="role")),
        edges=(GraphEdge(source_id="p:abc123", target_id="r:def456", edge_type="assigned_role"),),
    )
    assert graph.classification == "highly-restricted-attack-path"
    assert graph.export_allowed is False and graph.model_access_allowed is False
    assert graph.retention_hours == 24
    with pytest.raises(ValueError, match="identity_graph_pseudonym_required"):
        build_sensitive_graph(
            tenant_id="tenant-r109", approval=approval, now=NOW,
            nodes=(GraphNode(node_id="alice@example.com", node_type="principal"),), edges=(),
        )
    with pytest.raises(ValueError, match="identity_graph_tenant_mismatch"):
        build_sensitive_graph(tenant_id="other-tenant", approval=approval, now=NOW, nodes=(), edges=())
