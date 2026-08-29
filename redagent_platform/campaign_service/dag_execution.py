"""Pure deterministic reduction for an already validated admitted DAG."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from redagent_platform.campaign_service.dag_execution_contracts import DagNodeState
from redagent_platform.campaign_service.planning.contracts import (
    PlanEdgeV1,
    PlanJoinPolicy,
    PlanningDomainV1,
    PredicateOperator,
    PredicateV1,
    ScalarValueV1,
)
from redagent_platform.campaign_service.planning.search_contracts import (
    AttackPathDagRevisionV1,
)


class DagFrontierOutcome(str, Enum):
    READY = "ready"
    ACTIVE = "active"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


@dataclass(frozen=True, slots=True)
class NodeExecutionFact:
    node_id: str
    state: DagNodeState

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id:
            raise ValueError("dag_execution_node_fact_invalid")
        if not isinstance(self.state, DagNodeState):
            raise ValueError("dag_execution_node_state_invalid")


@dataclass(frozen=True, slots=True)
class DagFrontier:
    outcome: DagFrontierOutcome
    ready_node_id: str | None
    active_node_id: str | None
    applied_node_ids: tuple[str, ...]
    reason: str


_ACTIVE_STATES = {
    DagNodeState.READY,
    DagNodeState.RESERVED,
    DagNodeState.CLAIMED,
    DagNodeState.DISPATCHING,
}


def derive_dag_frontier(
    revision: AttackPathDagRevisionV1,
    domain: PlanningDomainV1,
    node_facts: tuple[NodeExecutionFact, ...],
) -> DagFrontier:
    if not isinstance(revision, AttackPathDagRevisionV1) or not isinstance(
        domain, PlanningDomainV1
    ):
        raise ValueError("dag_execution_input_invalid")
    if revision.domain_sha256 != domain.domain_sha256:
        raise ValueError("dag_execution_domain_mismatch")
    _validate_supported_chain(revision)
    if not isinstance(node_facts, tuple) or any(
        not isinstance(item, NodeExecutionFact) for item in node_facts
    ):
        raise ValueError("dag_execution_node_facts_invalid")
    by_node = {item.node_id: item for item in node_facts}
    if len(by_node) != len(node_facts):
        raise ValueError("dag_execution_node_fact_duplicate")
    node_ids = {item.node_id for item in revision.candidate_plan.nodes}
    if not set(by_node) <= node_ids:
        raise ValueError("dag_execution_node_fact_unknown")

    operators = {item.operator_id: item for item in domain.operators}
    state = {item.fact_id: item.value for item in revision.candidate_plan.initial_state.values}
    incoming = {
        node.node_id: tuple(
            edge
            for edge in revision.candidate_plan.edges
            if edge.target_node_id == node.node_id
        )
        for node in revision.candidate_plan.nodes
    }
    applied: list[str] = []

    for node in revision.candidate_plan.nodes:
        fact = by_node.get(node.node_id)
        node_state = DagNodeState.PENDING if fact is None else fact.state
        operator = operators.get(node.operator_id)
        if operator is None:
            raise ValueError("dag_execution_operator_unknown")
        reachable = _reachable(node.join_policy, incoming[node.node_id], applied, state)

        if node_state is DagNodeState.CONFIRMED:
            if not reachable or not _predicates_true(operator.preconditions, state):
                raise ValueError("dag_execution_confirmed_node_invalid")
            for effect in operator.effects:
                state[effect.fact_id] = effect.value
            applied.append(node.node_id)
            continue
        if node_state is DagNodeState.RECONCILIATION_REQUIRED:
            return DagFrontier(
                DagFrontierOutcome.RECONCILIATION_REQUIRED,
                None,
                node.node_id,
                tuple(applied),
                "effect_reconciliation_required",
            )
        if node_state is DagNodeState.MANUAL_REVIEW_REQUIRED:
            return DagFrontier(
                DagFrontierOutcome.MANUAL_REVIEW_REQUIRED,
                None,
                node.node_id,
                tuple(applied),
                "effect_manual_review_required",
            )
        if node_state in {DagNodeState.FAILED, DagNodeState.CONTAINED, DagNodeState.SKIPPED}:
            return DagFrontier(
                DagFrontierOutcome.BLOCKED,
                None,
                node.node_id,
                tuple(applied),
                f"node_{node_state.value}",
            )
        if node_state in _ACTIVE_STATES:
            return DagFrontier(
                DagFrontierOutcome.ACTIVE,
                None,
                node.node_id,
                tuple(applied),
                "node_active",
            )
        if node_state in {DagNodeState.PENDING, DagNodeState.NOT_APPLIED}:
            if reachable and _predicates_true(operator.preconditions, state):
                return DagFrontier(
                    DagFrontierOutcome.READY,
                    node.node_id,
                    None,
                    tuple(applied),
                    "node_ready",
                )
            return DagFrontier(
                DagFrontierOutcome.BLOCKED,
                None,
                node.node_id,
                tuple(applied),
                "node_condition_unsatisfied",
            )
        raise ValueError("dag_execution_node_state_invalid")

    return DagFrontier(
        DagFrontierOutcome.COMPLETED,
        None,
        None,
        tuple(applied),
        "all_nodes_confirmed",
    )


def _validate_supported_chain(revision: AttackPathDagRevisionV1) -> None:
    plan = revision.candidate_plan
    if (
        revision.width != 1
        or revision.depth != revision.node_count
        or revision.node_count != len(plan.nodes)
        or revision.root_node_ids != (plan.nodes[0].node_id,)
        or revision.terminal_node_ids != (plan.nodes[-1].node_id,)
        or len(plan.edges) != len(plan.nodes) - 1
    ):
        raise ValueError("dag_execution_topology_unsupported")
    expected = tuple(
        (plan.nodes[index - 1].node_id, plan.nodes[index].node_id)
        for index in range(1, len(plan.nodes))
    )
    node_order = {node.node_id: node.order for node in plan.nodes}
    actual = tuple(
        (edge.source_node_id, edge.target_node_id)
        for edge in sorted(plan.edges, key=lambda item: node_order[item.target_node_id])
    )
    if actual != expected:
        raise ValueError("dag_execution_topology_unsupported")


def _reachable(
    join_policy: PlanJoinPolicy,
    incoming: tuple[PlanEdgeV1, ...],
    applied: list[str],
    state: dict[str, ScalarValueV1 | None],
) -> bool:
    if not incoming:
        return True
    results = tuple(
        edge.source_node_id in applied and _predicates_true(edge.conditions, state)
        for edge in incoming
    )
    return all(results) if join_policy is PlanJoinPolicy.ALL else any(results)


def _predicates_true(
    predicates: tuple[PredicateV1, ...], state: dict[str, ScalarValueV1 | None]
) -> bool:
    return all(_evaluate(item, state.get(item.fact_id)) for item in predicates)


def _evaluate(predicate: PredicateV1, actual: ScalarValueV1 | None) -> bool:
    if actual is None or actual.value_type is not predicate.expected.value_type:
        return False
    left = actual.value
    right = predicate.expected.value
    operation = predicate.operator
    if operation is PredicateOperator.EQUALS:
        return left == right
    if operation is PredicateOperator.NOT_EQUALS:
        return left != right
    if type(left) is not int or type(right) is not int:
        return False
    if operation is PredicateOperator.LESS_THAN:
        return left < right
    if operation is PredicateOperator.LESS_THAN_OR_EQUAL:
        return left <= right
    if operation is PredicateOperator.GREATER_THAN:
        return left > right
    if operation is PredicateOperator.GREATER_THAN_OR_EQUAL:
        return left >= right
    return False
