"""Closed contracts for immutable, residual-bound campaign replanning."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime
from enum import Enum
import re

from redagent_platform.campaign_service.admission_contracts import (
    CampaignBudgetVectorV1,
    PlanEnvelopeSubsetProofV1,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
)
from redagent_platform.campaign_service.planning.contracts import (
    PlanValidationCertificateV1,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search_contracts import (
    AttackPathDagRevisionV1,
    SearchReceiptV1,
)
from redagent_platform.campaign_service.trusted_observations import (
    TrustedObservationHistoryV1,
)


_ACCEPTED_REPLAN_TOKEN = object()


REPLAN_REQUEST_SCHEMA_VERSION = "redagent.bounded-replan-request/v1"
REPLAN_PROPOSAL_SCHEMA_VERSION = "redagent.bounded-replan-proposal/v1"
REPLAN_RESULT_SCHEMA_VERSION = "redagent.bounded-replan-result/v1"
ACCEPTED_REPLAN_SCHEMA_VERSION = "redagent.accepted-bounded-replan/v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,149}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,99}$")


class ReplanOutcome(str, Enum):
    CHILD_PROPOSED = "child_proposed"
    NO_PLAN = "no_plan"
    REPLAN_LIMIT_EXHAUSTED = "replan_limit_exhausted"
    EXPANSION_REQUIRED = "expansion_required"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class ReplanFrontierDisposition(str, Enum):
    STOP_PARENT = "stop_parent"
    WAIT_FOR_CONTAINMENT = "wait_for_containment"
    CHILD_START_ALLOWED = "child_start_allowed"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


@dataclass(frozen=True, slots=True, kw_only=True)
class ReplanRequestV1:
    schema_version: str
    request_id: str
    tenant_id: str
    campaign_id: str
    engagement_id: str
    parent_revision_id: str
    parent_revision_sha256: str
    parent_admission_receipt_id: str
    parent_admission_receipt_sha256: str
    observation_history: TrustedObservationHistoryV1
    consumed_replans: int
    requested_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != REPLAN_REQUEST_SCHEMA_VERSION:
            raise ValueError("replan_request_schema_unsupported")
        for name in (
            "request_id",
            "tenant_id",
            "campaign_id",
            "engagement_id",
            "parent_revision_id",
            "parent_admission_receipt_id",
        ):
            _identifier(f"replan_request_{name}", getattr(self, name))
        _sha256("replan_request_parent_revision", self.parent_revision_sha256)
        _sha256("replan_request_parent_admission", self.parent_admission_receipt_sha256)
        if not isinstance(self.observation_history, TrustedObservationHistoryV1):
            raise ValueError("replan_request_observation_history_invalid")
        _bounded_int("replan_request_consumed", self.consumed_replans, 0, 10_000)
        _aware("replan_request_time", self.requested_at)

    @property
    def request_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True)
class NodeSubstitutionV1:
    parent_node_id: str
    child_node_id: str
    reason_code: str

    def __post_init__(self) -> None:
        _identifier("replan_substitution_parent", self.parent_node_id)
        _identifier("replan_substitution_child", self.child_node_id)
        _reason("replan_substitution_reason", self.reason_code)


@dataclass(frozen=True, slots=True, kw_only=True)
class BoundedReplanProposalV1:
    schema_version: str
    request_sha256: str
    parent_revision_id: str
    parent_revision_sha256: str
    parent_admission_receipt_id: str
    parent_admission_receipt_sha256: str
    child_revision: AttackPathDagRevisionV1
    observation_history_sha256: str
    trusted_observation_sha256s: tuple[str, ...]
    invalidated_parent_node_ids: tuple[str, ...]
    retained_parent_node_ids: tuple[str, ...]
    substitutions: tuple[NodeSubstitutionV1, ...]
    residual_budget: CampaignBudgetVectorV1
    planned_budget: CampaignBudgetVectorV1
    validation_certificate: PlanValidationCertificateV1
    subset_proof: PlanEnvelopeSubsetProofV1
    search_receipt: SearchReceiptV1
    replan_sequence: int
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int

    def __post_init__(self) -> None:
        if self.schema_version != REPLAN_PROPOSAL_SCHEMA_VERSION:
            raise ValueError("replan_proposal_schema_unsupported")
        for name in (
            "request_sha256",
            "parent_revision_sha256",
            "parent_admission_receipt_sha256",
            "observation_history_sha256",
        ):
            _sha256(f"replan_proposal_{name}", getattr(self, name))
        for name in ("parent_revision_id", "parent_admission_receipt_id"):
            _identifier(f"replan_proposal_{name}", getattr(self, name))
        if not isinstance(self.child_revision, AttackPathDagRevisionV1):
            raise ValueError("replan_proposal_child_invalid")
        if self.child_revision.parent_revision_id != self.parent_revision_id:
            raise ValueError("replan_proposal_parent_binding_mismatch")
        _canonical_digests("replan_proposal_observations", self.trusted_observation_sha256s)
        _canonical_ids("replan_proposal_invalidated", self.invalidated_parent_node_ids, allow_empty=True)
        _canonical_ids("replan_proposal_retained", self.retained_parent_node_ids, allow_empty=True)
        if set(self.invalidated_parent_node_ids) & set(self.retained_parent_node_ids):
            raise ValueError("replan_proposal_node_partition_overlap")
        if (
            not isinstance(self.substitutions, tuple)
            or any(not isinstance(item, NodeSubstitutionV1) for item in self.substitutions)
            or tuple(sorted(self.substitutions, key=lambda item: (item.parent_node_id, item.child_node_id)))
            != self.substitutions
        ):
            raise ValueError("replan_proposal_substitutions_invalid")
        if not isinstance(self.residual_budget, CampaignBudgetVectorV1) or not isinstance(
            self.planned_budget, CampaignBudgetVectorV1
        ):
            raise ValueError("replan_proposal_budget_invalid")
        # CRITICAL: autonomous work spends the current residual ledger; original authority is never a reset button.
        if not self.planned_budget.fits_within(self.residual_budget):
            raise ValueError("replan_proposal_residual_budget_exceeded")
        if not isinstance(self.validation_certificate, PlanValidationCertificateV1) or not isinstance(
            self.subset_proof, PlanEnvelopeSubsetProofV1
        ) or not isinstance(self.search_receipt, SearchReceiptV1):
            raise ValueError("replan_proposal_proof_invalid")
        if (
            not self.validation_certificate.admissible
            or not self.subset_proof.admissible
            or self.validation_certificate.plan_sha256 != self.child_revision.candidate_plan.plan_sha256
            or self.subset_proof.plan_sha256 != self.child_revision.candidate_plan.plan_sha256
            or self.search_receipt.found_revision_sha256 != self.child_revision.revision_sha256
        ):
            raise ValueError("replan_proposal_proof_binding_mismatch")
        _bounded_int("replan_proposal_sequence", self.replan_sequence, 1, 10_000)
        for name in (
            "lifecycle_epoch",
            "policy_revocation_epoch",
            "roe_revocation_epoch",
            "kill_switch_epoch",
        ):
            _bounded_int(f"replan_proposal_{name}", getattr(self, name), 0, 2_147_483_647)

    @property
    def proposal_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class BoundedReplanResultV1:
    schema_version: str
    request_sha256: str
    outcome: ReplanOutcome
    reason_code: str
    proposal: BoundedReplanProposalV1 | None

    def __post_init__(self) -> None:
        if self.schema_version != REPLAN_RESULT_SCHEMA_VERSION:
            raise ValueError("replan_result_schema_unsupported")
        _sha256("replan_result_request", self.request_sha256)
        if not isinstance(self.outcome, ReplanOutcome):
            raise ValueError("replan_result_outcome_invalid")
        _reason("replan_result_reason", self.reason_code)
        if (self.outcome is ReplanOutcome.CHILD_PROPOSED) != isinstance(
            self.proposal, BoundedReplanProposalV1
        ):
            raise ValueError("replan_result_proposal_binding_invalid")

    @property
    def result_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class AcceptedBoundedReplanV1:
    schema_version: str
    proposal: BoundedReplanProposalV1
    child_admission_receipt_id: str
    child_admission_receipt_sha256: str
    reservation_id: str
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        # CRITICAL: only the admission binder may mint executable child authority.
        if _validation_token is not _ACCEPTED_REPLAN_TOKEN:
            raise ValueError("accepted_replan_admission_binding_required")
        if self.schema_version != ACCEPTED_REPLAN_SCHEMA_VERSION:
            raise ValueError("accepted_replan_schema_unsupported")
        if not isinstance(self.proposal, BoundedReplanProposalV1):
            raise ValueError("accepted_replan_proposal_invalid")
        _identifier("accepted_replan_admission", self.child_admission_receipt_id)
        _sha256("accepted_replan_admission", self.child_admission_receipt_sha256)
        _identifier("accepted_replan_reservation", self.reservation_id)

    @property
    def accepted_replan_sha256(self) -> str:
        return canonical_planning_sha256(self)


def _build_accepted_bounded_replan(
    *,
    proposal: BoundedReplanProposalV1,
    child_admission_receipt_id: str,
    child_admission_receipt_sha256: str,
    reservation_id: str,
) -> AcceptedBoundedReplanV1:
    return AcceptedBoundedReplanV1(
        schema_version=ACCEPTED_REPLAN_SCHEMA_VERSION,
        proposal=proposal,
        child_admission_receipt_id=child_admission_receipt_id,
        child_admission_receipt_sha256=child_admission_receipt_sha256,
        reservation_id=reservation_id,
        _validation_token=_ACCEPTED_REPLAN_TOKEN,
    )


def classify_replan_frontier(snapshot: DagExecutionSnapshotV1) -> ReplanFrontierDisposition:
    if not isinstance(snapshot, DagExecutionSnapshotV1):
        raise ValueError("replan_frontier_snapshot_invalid")
    if snapshot.current_node_state in {
        DagNodeState.RESERVED,
        DagNodeState.CLAIMED,
        DagNodeState.DISPATCHING,
        DagNodeState.RECONCILIATION_REQUIRED,
    }:
        # CRITICAL: never swap a parent while an effect may be in flight or ambiguously applied.
        return ReplanFrontierDisposition.RECONCILIATION_REQUIRED
    if snapshot.state in {
        DagRunState.RECONCILIATION_REQUIRED,
        DagRunState.MANUAL_REVIEW_REQUIRED,
        DagRunState.FAILED,
    }:
        return ReplanFrontierDisposition.MANUAL_REVIEW_REQUIRED
    if snapshot.state in {
        DagRunState.CONTAINED,
        DagRunState.COMPLETED,
        DagRunState.FAILED_BEFORE_IO,
    }:
        return ReplanFrontierDisposition.CHILD_START_ALLOWED
    if snapshot.state is DagRunState.STOPPING or snapshot.stop_requested:
        return ReplanFrontierDisposition.WAIT_FOR_CONTAINMENT
    return ReplanFrontierDisposition.STOP_PARENT


def _canonical_ids(name: str, values: tuple[str, ...], *, allow_empty: bool) -> None:
    if (
        not isinstance(values, tuple)
        or (not values and not allow_empty)
        or tuple(sorted(set(values))) != values
    ):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value)


def _canonical_digests(name: str, values: tuple[str, ...]) -> None:
    if not isinstance(values, tuple) or not values or tuple(sorted(set(values))) != values:
        raise ValueError(f"{name}_invalid")
    for value in values:
        _sha256(name, value)


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _reason(name: str, value: object) -> None:
    if not isinstance(value, str) or not _REASON.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _bounded_int(name: str, value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")
