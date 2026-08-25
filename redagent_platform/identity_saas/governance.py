"""compat_109 immutable baseline exceptions and separately approved sensitive relationship graphs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re


_PSEUDONYM = re.compile(r"^[prag]:[0-9a-f]{6,64}$")


@dataclass(frozen=True, kw_only=True)
class BaselineEvaluation:
    evaluation_id: str; tenant_id: str; snapshot_sha256: str; baseline_id: str
    baseline_sha256: str; control_id: str; resource_id: str; passed: bool; evaluated_at: datetime


@dataclass(frozen=True, kw_only=True)
class ExceptionAnnotation:
    exception_id: str; evaluation_id: str; tenant_id: str; control_id: str; resource_id: str
    justification: str; requested_by: str; approved_by: str; effective_at: datetime
    expires_at: datetime; supersedes_exception_id: str | None


@dataclass(frozen=True, kw_only=True)
class AnnotatedEvaluation:
    evaluation: BaselineEvaluation; annotation: ExceptionAnnotation; risk_state: str


def apply_exception(*, evaluation: BaselineEvaluation, annotation: ExceptionAnnotation, now: datetime) -> AnnotatedEvaluation:
    _aware(now); _aware(evaluation.evaluated_at); _aware(annotation.effective_at); _aware(annotation.expires_at)
    if annotation.requested_by == annotation.approved_by:
        raise ValueError("identity_exception_separation_required")
    if (annotation.evaluation_id, annotation.tenant_id, annotation.control_id, annotation.resource_id) != (evaluation.evaluation_id, evaluation.tenant_id, evaluation.control_id, evaluation.resource_id):
        raise ValueError("identity_exception_scope_mismatch")
    if not annotation.effective_at <= now < annotation.expires_at:
        raise ValueError("identity_exception_inactive")
    if len(annotation.justification.strip()) < 20:
        raise ValueError("identity_exception_justification_required")
    return AnnotatedEvaluation(evaluation=evaluation, annotation=annotation, risk_state="accepted-temporarily")


@dataclass(frozen=True, kw_only=True)
class GraphApproval:
    approval_id: str; tenant_id: str; approved_by: str; approved_at: datetime; expires_at: datetime
    restricted_role: str; export_allowed: bool; model_access_allowed: bool; retention_hours: int


@dataclass(frozen=True, kw_only=True)
class GraphNode:
    node_id: str; node_type: str


@dataclass(frozen=True, kw_only=True)
class GraphEdge:
    source_id: str; target_id: str; edge_type: str


@dataclass(frozen=True, kw_only=True)
class SensitiveGraph:
    tenant_id: str; approval_id: str; nodes: tuple[GraphNode, ...]; edges: tuple[GraphEdge, ...]
    classification: str; restricted_role: str; export_allowed: bool; model_access_allowed: bool
    retention_hours: int


def build_sensitive_graph(*, tenant_id: str, approval: GraphApproval, now: datetime, nodes: tuple[GraphNode, ...], edges: tuple[GraphEdge, ...]) -> SensitiveGraph:
    _aware(now); _aware(approval.approved_at); _aware(approval.expires_at)
    if tenant_id != approval.tenant_id:
        raise ValueError("identity_graph_tenant_mismatch")
    if not approval.approved_at <= now < approval.expires_at:
        raise ValueError("identity_graph_approval_inactive")
    if approval.export_allowed or approval.model_access_allowed or not 1 <= approval.retention_hours <= 24 or approval.restricted_role != "identity-graph-reviewer":
        raise ValueError("identity_graph_boundary_invalid")
    if any(not _PSEUDONYM.fullmatch(node.node_id) for node in nodes):
        raise ValueError("identity_graph_pseudonym_required")
    identifiers = {node.node_id for node in nodes}
    if any(edge.source_id not in identifiers or edge.target_id not in identifiers or edge.edge_type not in {"assigned_role", "consented_permission", "member_of"} for edge in edges):
        raise ValueError("identity_graph_edge_invalid")
    return SensitiveGraph(
        tenant_id=tenant_id, approval_id=approval.approval_id, nodes=nodes, edges=edges,
        classification="highly-restricted-attack-path", restricted_role=approval.restricted_role,
        export_allowed=False, model_access_allowed=False, retention_hours=approval.retention_hours,
    )


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("identity_time_invalid")
