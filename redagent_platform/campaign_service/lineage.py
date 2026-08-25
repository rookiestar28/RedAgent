"""Closed, deterministic terminal-lineage barrier for compat_123 campaign success."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True, kw_only=True)
class NodeTerminalLineageV1:
    node_id: str
    capability_id: str
    capability_revision: int
    effect_id: str
    effect_receipt_sha256: str
    execution_receipt_id: str
    evidence_ids: tuple[str, ...]
    finding_import_id: str | None
    finding_issue_ids: tuple[str, ...]
    no_finding_coverage: bool
    retest_receipt_ids: tuple[str, ...]
    cleanup_receipt_id: str | None
    reconciliation_state: str

    def __post_init__(self) -> None:
        for name in ("node_id", "capability_id", "effect_id", "execution_receipt_id"):
            _identifier(name, getattr(self, name))
        if (
            isinstance(self.capability_revision, bool)
            or not 1 <= self.capability_revision <= 9999
        ):
            raise ValueError("r123_lineage_capability_revision_invalid")
        _sha256("effect_receipt_sha256", self.effect_receipt_sha256)
        if (
            not isinstance(self.evidence_ids, tuple)
            or not self.evidence_ids
            or len(self.evidence_ids) > 32
            or len(set(self.evidence_ids)) != len(self.evidence_ids)
        ):
            raise ValueError("r123_lineage_evidence_required")
        for value in self.evidence_ids:
            _identifier("evidence_id", value)
        if self.finding_import_id is None:
            raise ValueError("r123_lineage_finding_import_required")
        _identifier("finding_import_id", self.finding_import_id)
        if (
            not isinstance(self.finding_issue_ids, tuple)
            or len(self.finding_issue_ids) > 100
            or len(set(self.finding_issue_ids)) != len(self.finding_issue_ids)
        ):
            raise ValueError("r123_lineage_finding_issue_ids_invalid")
        for value in self.finding_issue_ids:
            _identifier("finding_issue_id", value)
        if not isinstance(self.no_finding_coverage, bool) or (
            bool(self.finding_issue_ids) == self.no_finding_coverage
        ):
            raise ValueError("r123_lineage_finding_or_coverage_required")
        if (
            not isinstance(self.retest_receipt_ids, tuple)
            or len(self.retest_receipt_ids) > 100
            or len(set(self.retest_receipt_ids)) != len(self.retest_receipt_ids)
        ):
            raise ValueError("r123_lineage_retest_receipt_ids_invalid")
        for value in self.retest_receipt_ids:
            _identifier("retest_receipt_id", value)
        if self.finding_issue_ids:
            if not self.retest_receipt_ids:
                raise ValueError("r123_lineage_retest_required")
            if len(self.retest_receipt_ids) != len(self.finding_issue_ids):
                raise ValueError("r123_lineage_retest_count_mismatch")
        elif self.retest_receipt_ids:
            raise ValueError("r123_lineage_retest_unexpected")
        if self.cleanup_receipt_id is None:
            raise ValueError("r123_lineage_cleanup_required")
        _identifier("cleanup_receipt_id", self.cleanup_receipt_id)
        if self.reconciliation_state not in {"confirmed", "compensated"}:
            raise ValueError("r123_lineage_reconciliation_not_success")


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignTerminalLineageV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    strategy_revision_id: str
    objective_sha256: str
    resolved_envelope_sha256: str
    context_snapshot_sha256: str
    decision_sha256: str
    plan_sha256: str
    approval_receipt_id: str
    approval_receipt_sha256: str
    outbox_event_id: str
    workflow_id: str
    workflow_run_id: str | None
    nodes: tuple[NodeTerminalLineageV1, ...]
    stop_or_replan_receipt_id: str
    residual_risk_receipt_id: str
    campaign_cleanup_receipt_id: str
    terminal_reason: str

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r123-terminal-lineage/v1":
            raise ValueError("r123_lineage_schema_invalid")
        for name in (
            "tenant_id", "campaign_id", "strategy_revision_id", "approval_receipt_id",
            "outbox_event_id", "workflow_id", "stop_or_replan_receipt_id",
            "residual_risk_receipt_id", "campaign_cleanup_receipt_id",
        ):
            _identifier(name, getattr(self, name))
        if self.workflow_run_id is None:
            raise ValueError("r123_lineage_workflow_run_required")
        _identifier("workflow_run_id", self.workflow_run_id)
        for name in (
            "objective_sha256", "resolved_envelope_sha256", "context_snapshot_sha256",
            "decision_sha256", "plan_sha256", "approval_receipt_sha256",
        ):
            _sha256(name, getattr(self, name))
        if (
            not isinstance(self.nodes, tuple)
            or not 1 <= len(self.nodes) <= 2
            or not all(isinstance(item, NodeTerminalLineageV1) for item in self.nodes)
        ):
            raise ValueError("r123_lineage_nodes_invalid")
        stable_keys = tuple((item.node_id, item.effect_id) for item in self.nodes)
        if len(set(stable_keys)) != len(stable_keys):
            raise ValueError("r123_lineage_node_duplicate")
        if self.terminal_reason not in {
            "objective_satisfied",
            "corroboration_complete",
            "redundant_successor_stopped",
        }:
            raise ValueError("r123_lineage_terminal_reason_not_success")

    @property
    def lineage_sha256(self) -> str:
        encoded = json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def verify_success_lineage(lineage: CampaignTerminalLineageV1) -> str:
    if not isinstance(lineage, CampaignTerminalLineageV1):
        raise ValueError("r123_terminal_lineage_invalid")
    # Construction validates every finalizer owner; recomputation gives deterministic regeneration.
    return lineage.lineage_sha256


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"r123_lineage_{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"r123_lineage_{name}_invalid")
