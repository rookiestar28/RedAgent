"""Immutable contracts for deterministic bounded attack-path search."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from redagent_platform.campaign_service.planning.contracts import (
    CandidatePlanV1,
    ScalarValueV1,
    canonical_planning_sha256,
)


PLANNER_SEARCH_LIMITS_SCHEMA_VERSION = "redagent.planner-search-limits/v1"
SEARCH_RECEIPT_SCHEMA_VERSION = "redagent.attack-path-search-receipt/v1"
ATTACK_PATH_DAG_SCHEMA_VERSION = "redagent.attack-path-dag-revision/v1"
ATTACK_PATH_PLANNER_RESULT_SCHEMA_VERSION = "redagent.attack-path-planner-result/v1"
PREDICTED_GOAL_CLAIM_SCHEMA_VERSION = "redagent.predicted-goal-claim/v1"
PLAN_ORDERING_KEY_SCHEMA_VERSION = "redagent.attack-path-ordering-key/v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,149}$")
_REASON = re.compile(r"^[a-z][a-z0-9_:]{0,149}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AttackPathPlannerOutcome(str, Enum):
    PLAN_FOUND = "plan_found"
    NO_PLAN = "no_plan"
    UNSUPPORTED = "unsupported"
    BOUND_EXHAUSTED = "bound_exhausted"
    TIMEOUT = "timeout"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True, slots=True)
class PlannerSearchLimitsV1:
    max_expanded_states: int
    max_generated_states: int
    max_frontier: int
    max_search_ticks: int
    max_memory_units: int
    max_action_variants: int = 10_000
    schema_version: str = PLANNER_SEARCH_LIMITS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != PLANNER_SEARCH_LIMITS_SCHEMA_VERSION:
            raise ValueError("planner_search_limits_schema_unsupported")
        limits = {
            "max_expanded_states": 10_000_000,
            "max_generated_states": 10_000_000,
            "max_frontier": 1_000_000,
            "max_search_ticks": 1_000_000_000,
            "max_memory_units": 1_000_000_000,
            "max_action_variants": 10_000_000,
        }
        for name, maximum in limits.items():
            _integer(f"planner_limit_{name}", getattr(self, name), 1, maximum)

    @property
    def limits_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True)
class SearchReasonCountV1:
    reason: str
    count: int

    def __post_init__(self) -> None:
        _reason("planner_prune_reason", self.reason)
        _integer("planner_prune_count", self.count, 1, 1_000_000_000)


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanOrderingKeyV1:
    schema_version: str
    unsatisfied_required_count: int
    cumulative_risk_micropoints: int
    cumulative_cost_microunits: int
    depth: int
    path_action_sha256: str
    state_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_ORDERING_KEY_SCHEMA_VERSION:
            raise ValueError("planner_ordering_key_schema_unsupported")
        for name in (
            "unsatisfied_required_count",
            "cumulative_risk_micropoints",
            "cumulative_cost_microunits",
            "depth",
        ):
            _integer(f"planner_ordering_key_{name}", getattr(self, name), 0, 10**18)
        _sha256("planner_ordering_key_path_action_sha256", self.path_action_sha256)
        _sha256("planner_ordering_key_state_sha256", self.state_sha256)


@dataclass(frozen=True, slots=True, kw_only=True)
class PredictedGoalClaimV1:
    schema_version: str
    fact_id: str
    expected: ScalarValueV1
    predicted_value: ScalarValueV1
    source_node_id: str
    predicted_only: bool

    def __post_init__(self) -> None:
        if self.schema_version != PREDICTED_GOAL_CLAIM_SCHEMA_VERSION:
            raise ValueError("predicted_goal_claim_schema_unsupported")
        _identifier("predicted_goal_claim_fact", self.fact_id)
        _identifier("predicted_goal_claim_source_node", self.source_node_id)
        if not isinstance(self.expected, ScalarValueV1) or not isinstance(self.predicted_value, ScalarValueV1):
            raise ValueError("predicted_goal_claim_value_invalid")
        if self.predicted_only is not True:
            raise ValueError("predicted_goal_claim_must_remain_untrusted")


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackPathDagRevisionV1:
    schema_version: str
    revision_id: str
    parent_revision_id: None
    planner_version: str
    planner_sha256: str
    tenant_id: str
    engagement_id: str
    authority_sha256: str
    domain_sha256: str
    objective_sha256: str
    initial_state_sha256: str
    candidate_plan: CandidatePlanV1
    root_node_ids: tuple[str, ...]
    terminal_node_ids: tuple[str, ...]
    predicted_goal_claims: tuple[PredictedGoalClaimV1, ...]
    total_cost_microunits: int
    total_risk_micropoints: int
    depth: int
    width: int
    node_count: int
    ordering_key: PlanOrderingKeyV1

    def __post_init__(self) -> None:
        if self.schema_version != ATTACK_PATH_DAG_SCHEMA_VERSION:
            raise ValueError("attack_path_dag_schema_unsupported")
        for name in ("revision_id", "planner_version", "tenant_id", "engagement_id"):
            _identifier(f"attack_path_dag_{name}", getattr(self, name))
        if self.parent_revision_id is not None:
            raise ValueError("attack_path_dag_parent_must_be_none")
        for name in (
            "planner_sha256",
            "authority_sha256",
            "domain_sha256",
            "objective_sha256",
            "initial_state_sha256",
        ):
            _sha256(f"attack_path_dag_{name}", getattr(self, name))
        if not isinstance(self.candidate_plan, CandidatePlanV1):
            raise ValueError("attack_path_dag_candidate_invalid")
        if (
            self.tenant_id != self.candidate_plan.tenant_id
            or self.engagement_id != self.candidate_plan.engagement_id
            or self.authority_sha256 != self.candidate_plan.authority_sha256
            or self.domain_sha256 != self.candidate_plan.domain_sha256
            or self.initial_state_sha256 != self.candidate_plan.initial_state.state_sha256
        ):
            raise ValueError("attack_path_dag_candidate_binding_mismatch")
        _canonical_ids("attack_path_dag_roots", self.root_node_ids)
        _canonical_ids("attack_path_dag_terminals", self.terminal_node_ids)
        if (
            not isinstance(self.predicted_goal_claims, tuple)
            or not self.predicted_goal_claims
            or any(not isinstance(item, PredictedGoalClaimV1) for item in self.predicted_goal_claims)
            or tuple(sorted(self.predicted_goal_claims, key=lambda item: item.fact_id)) != self.predicted_goal_claims
        ):
            raise ValueError("attack_path_dag_goal_claims_invalid")
        for name in ("total_cost_microunits", "total_risk_micropoints", "depth", "width", "node_count"):
            _integer(
                f"attack_path_dag_{name}",
                getattr(self, name),
                1 if name in {"depth", "width", "node_count"} else 0,
                10**18,
            )
        if self.width != 1 or self.node_count != len(self.candidate_plan.nodes) or self.depth != self.node_count:
            raise ValueError("attack_path_dag_shape_invalid")
        if self.root_node_ids != (self.candidate_plan.nodes[0].node_id,):
            raise ValueError("attack_path_dag_root_invalid")
        if self.terminal_node_ids != (self.candidate_plan.nodes[-1].node_id,):
            raise ValueError("attack_path_dag_terminal_invalid")
        if not isinstance(self.ordering_key, PlanOrderingKeyV1):
            raise ValueError("attack_path_dag_ordering_key_invalid")
        if (
            self.ordering_key.unsatisfied_required_count != 0
            or self.ordering_key.cumulative_risk_micropoints != self.total_risk_micropoints
            or self.ordering_key.cumulative_cost_microunits != self.total_cost_microunits
            or self.ordering_key.depth != self.depth
        ):
            raise ValueError("attack_path_dag_ordering_mismatch")

    @property
    def revision_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class SearchReceiptV1:
    schema_version: str
    planner_version: str
    planner_sha256: str
    total_order_version: str
    outcome: AttackPathPlannerOutcome
    detail_code: str
    authority_sha256: str
    domain_sha256: str
    objective_sha256: str
    initial_state_sha256: str
    limits_sha256: str
    enumerated_action_variants: int
    expanded_states: int
    generated_states: int
    deduplicated_states: int
    pruned_states: int
    maximum_frontier_observed: int
    maximum_depth_observed: int
    maximum_memory_units_observed: int
    search_ticks: int
    pruned_reasons: tuple[SearchReasonCountV1, ...]
    found_revision_sha256: str | None

    def __post_init__(self) -> None:
        if self.schema_version != SEARCH_RECEIPT_SCHEMA_VERSION:
            raise ValueError("planner_search_receipt_schema_unsupported")
        for name in ("planner_version", "total_order_version"):
            _identifier(f"planner_search_receipt_{name}", getattr(self, name))
        if not isinstance(self.outcome, AttackPathPlannerOutcome):
            raise ValueError("planner_search_receipt_outcome_invalid")
        _reason("planner_search_receipt_detail", self.detail_code)
        for name in (
            "planner_sha256",
            "authority_sha256",
            "domain_sha256",
            "objective_sha256",
            "initial_state_sha256",
            "limits_sha256",
        ):
            _sha256(f"planner_search_receipt_{name}", getattr(self, name))
        for name in (
            "expanded_states",
            "enumerated_action_variants",
            "generated_states",
            "deduplicated_states",
            "pruned_states",
            "maximum_frontier_observed",
            "maximum_depth_observed",
            "maximum_memory_units_observed",
            "search_ticks",
        ):
            _integer(f"planner_search_receipt_{name}", getattr(self, name), 0, 10**18)
        if (
            not isinstance(self.pruned_reasons, tuple)
            or any(not isinstance(item, SearchReasonCountV1) for item in self.pruned_reasons)
            or tuple(sorted(self.pruned_reasons, key=lambda item: item.reason)) != self.pruned_reasons
        ):
            raise ValueError("planner_search_receipt_reasons_invalid")
        if self.outcome is AttackPathPlannerOutcome.PLAN_FOUND:
            _sha256("planner_search_receipt_found_revision", self.found_revision_sha256)
        elif self.found_revision_sha256 is not None:
            raise ValueError("planner_search_receipt_unexpected_revision")

    @property
    def receipt_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackPathPlannerResultV1:
    schema_version: str
    outcome: AttackPathPlannerOutcome
    revision: AttackPathDagRevisionV1 | None
    receipt: SearchReceiptV1

    def __post_init__(self) -> None:
        if self.schema_version != ATTACK_PATH_PLANNER_RESULT_SCHEMA_VERSION:
            raise ValueError("attack_path_planner_result_schema_unsupported")
        if not isinstance(self.outcome, AttackPathPlannerOutcome) or not isinstance(self.receipt, SearchReceiptV1):
            raise ValueError("attack_path_planner_result_invalid")
        if self.receipt.outcome is not self.outcome:
            raise ValueError("attack_path_planner_result_outcome_mismatch")
        if self.outcome is AttackPathPlannerOutcome.PLAN_FOUND:
            if not isinstance(self.revision, AttackPathDagRevisionV1):
                raise ValueError("attack_path_planner_result_revision_required")
            if self.receipt.found_revision_sha256 != self.revision.revision_sha256:
                raise ValueError("attack_path_planner_result_revision_mismatch")
            if (
                self.receipt.planner_version != self.revision.planner_version
                or self.receipt.planner_sha256 != self.revision.planner_sha256
                or self.receipt.authority_sha256 != self.revision.authority_sha256
                or self.receipt.domain_sha256 != self.revision.domain_sha256
                or self.receipt.objective_sha256 != self.revision.objective_sha256
                or self.receipt.initial_state_sha256 != self.revision.initial_state_sha256
            ):
                raise ValueError("attack_path_planner_result_receipt_binding_mismatch")
        elif self.revision is not None:
            raise ValueError("attack_path_planner_result_revision_forbidden")

    @property
    def result_sha256(self) -> str:
        return canonical_planning_sha256(self)


def _canonical_ids(name: str, values: tuple[str, ...]) -> None:
    if (
        not isinstance(values, tuple)
        or not values
        or tuple(sorted(values)) != values
        or len(set(values)) != len(values)
    ):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value)


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _reason(name: str, value: object) -> None:
    if not isinstance(value, str) or not _REASON.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _integer(name: str, value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")
