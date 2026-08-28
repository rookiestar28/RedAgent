"""Pure deterministic bounded search over closed campaign planning domains."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import heapq
from itertools import product
from typing import TypeAlias

from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityEnvelopeV2,
    CampaignEnvironmentClass,
)
from redagent_platform.campaign_service.planning.contracts import (
    CANDIDATE_PLAN_SCHEMA_VERSION,
    PLAN_EDGE_SCHEMA_VERSION,
    PLAN_NODE_SCHEMA_VERSION,
    CandidatePlanV1,
    CapabilityOperatorV1,
    FactDefinitionV1,
    FactValueV1,
    PlanEdgeV1,
    PlanJoinPolicy,
    PlanNodeV1,
    PlanningDomainV1,
    PredicateOperator,
    PredicateV1,
    ScalarType,
    ScalarValueV1,
    TypedParameterBindingV1,
    TypedParameterSpecV1,
    WorldStateV1,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search_contracts import (
    ATTACK_PATH_DAG_SCHEMA_VERSION,
    ATTACK_PATH_PLANNER_RESULT_SCHEMA_VERSION,
    PLAN_ORDERING_KEY_SCHEMA_VERSION,
    PREDICTED_GOAL_CLAIM_SCHEMA_VERSION,
    SEARCH_RECEIPT_SCHEMA_VERSION,
    AttackPathDagRevisionV1,
    AttackPathPlannerOutcome,
    AttackPathPlannerResultV1,
    PlanOrderingKeyV1,
    PlannerSearchLimitsV1,
    PredictedGoalClaimV1,
    SearchReasonCountV1,
    SearchReceiptV1,
)


PLANNER_VERSION = "redagent.attack-path-planner.v1"
TOTAL_ORDER_VERSION = "redagent.attack-path-order.v1"
PLANNER_TICKS_PER_SECOND = 10_000
PLANNER_SHA256 = hashlib.sha256(b"redagent.attack-path-planner/v1:closed-domain-best-first-width-one-dag").hexdigest()
# CRITICAL: keep this module model-free and validator-free; proposals gain no authority here.

_ActionKey: TypeAlias = tuple[str, str, str, str]
_PathKey: TypeAlias = tuple[_ActionKey, ...]
_Rank: TypeAlias = tuple[int, int, int, int, _PathKey, str]
_BestStateKey: TypeAlias = tuple[int, int, int, _PathKey]
_Truth: TypeAlias = bool | None


@dataclass(frozen=True, slots=True)
class _Action:
    operator: CapabilityOperatorV1
    target_id: str
    environment: CampaignEnvironmentClass
    arguments: tuple[TypedParameterBindingV1, ...]
    key: _ActionKey


@dataclass(frozen=True, slots=True)
class _Resources:
    duration_seconds: int = 0
    requests: int = 0
    rate_per_minute: int = 0
    concurrency: int = 0
    retries_per_node: int = 0
    risk_micropoints: int = 0
    cost_microunits: int = 0
    evidence_bytes: int = 0
    data_bytes: int = 0


@dataclass(frozen=True, slots=True)
class _SearchNode:
    state: WorldStateV1
    path: tuple[_Action, ...]
    path_key: _PathKey
    resources: _Resources


@dataclass(slots=True)
class _Metrics:
    enumerated_action_variants: int = 0
    expanded_states: int = 0
    generated_states: int = 0
    deduplicated_states: int = 0
    maximum_frontier_observed: int = 1
    maximum_depth_observed: int = 0
    maximum_memory_units_observed: int = 1
    search_ticks: int = 0
    pruned_reasons: Counter[str] | None = None

    def __post_init__(self) -> None:
        if self.pruned_reasons is None:
            self.pruned_reasons = Counter()

    def prune(self, reason: str) -> None:
        assert self.pruned_reasons is not None
        self.pruned_reasons[reason] += 1


class _SearchTimeout(Exception):
    pass


class _InitialStateMismatch(Exception):
    pass


@dataclass(slots=True)
class _TickBudget:
    maximum: int
    metrics: _Metrics

    def charge(self, amount: int = 1) -> None:
        if self.metrics.search_ticks + amount > self.maximum:
            self.metrics.search_ticks = self.maximum
            raise _SearchTimeout
        self.metrics.search_ticks += amount


def plan_attack_path(
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    initial_state: WorldStateV1,
    limits: PlannerSearchLimitsV1,
) -> AttackPathPlannerResultV1:
    """Return a proposal-only result; this boundary performs no I/O or validation."""
    if (
        not isinstance(domain, PlanningDomainV1)
        or not isinstance(authority, CampaignAuthorityEnvelopeV2)
        or not isinstance(initial_state, WorldStateV1)
        or not isinstance(limits, PlannerSearchLimitsV1)
    ):
        raise ValueError("attack_path_planner_input_invalid")
    try:
        return _search_attack_path(domain, authority, initial_state, limits)
    except Exception:  # noqa: BLE001 - this fail-closed API must emit the declared INTERNAL_ERROR outcome.
        # CRITICAL: unexpected failures must not leak internals or return a partially authoritative proposal.
        return _result(
            AttackPathPlannerOutcome.INTERNAL_ERROR,
            "planner_internal_error",
            domain,
            authority,
            initial_state,
            limits,
            _Metrics(),
            None,
        )


def _search_attack_path(
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    initial_state: WorldStateV1,
    limits: PlannerSearchLimitsV1,
) -> AttackPathPlannerResultV1:
    metrics = _Metrics()
    tick_limit = min(
        limits.max_search_ticks,
        authority.bounds.max_search_seconds * PLANNER_TICKS_PER_SECOND,
    )
    ticks = _TickBudget(tick_limit, metrics)
    try:
        if domain.objective.objective_id not in authority.objective_ids or not all(
            predicate.fact_id in authority.success_condition_ids for predicate in domain.objective.required_predicates
        ):
            return _result(
                AttackPathPlannerOutcome.UNSUPPORTED,
                "authority_domain_binding_unsupported",
                domain,
                authority,
                initial_state,
                limits,
                metrics,
                None,
            )

        try:
            canonical_initial = _closed_initial_state(domain, initial_state, ticks)
        except _InitialStateMismatch:
            return _result(
                AttackPathPlannerOutcome.UNSUPPORTED,
                "initial_state_domain_mismatch",
                domain,
                authority,
                initial_state,
                limits,
                metrics,
                None,
            )
        if not _state_is_safe(domain, canonical_initial, ticks):
            return _result(
                AttackPathPlannerOutcome.UNSUPPORTED,
                "initial_state_safety_unsupported",
                domain,
                authority,
                initial_state,
                limits,
                metrics,
                None,
            )
        if _goal_satisfied(domain, canonical_initial, ticks):
            return _result(
                AttackPathPlannerOutcome.UNSUPPORTED,
                "initial_objective_already_satisfied",
                domain,
                authority,
                initial_state,
                limits,
                metrics,
                None,
            )

        actions, has_unsupported, catalog_bound = _enumerate_actions(
            domain,
            authority,
            limits,
            metrics,
            ticks,
        )
        if catalog_bound is not None:
            return _result(
                AttackPathPlannerOutcome.BOUND_EXHAUSTED,
                catalog_bound,
                domain,
                authority,
                initial_state,
                limits,
                metrics,
                None,
            )
        initial_node = _SearchNode(canonical_initial, (), (), _Resources())
        initial_sha = canonical_initial.state_sha256
        initial_rank = _rank(domain, initial_node, ticks)
        frontier: list[tuple[_Rank, int, _SearchNode]] = [(initial_rank, 0, initial_node)]
        best_by_state: dict[str, _BestStateKey] = {initial_sha: _best_state_key(initial_node)}
        width_by_depth: Counter[int] = Counter({0: 1})
        generation_serial = 0
        hit_bound = False
        first_bound_reason: str | None = None
        effective_frontier = min(limits.max_frontier, authority.bounds.max_frontier)
        initial_memory = _memory_units(best_by_state, frontier, len(actions))
        metrics.maximum_memory_units_observed = max(
            metrics.maximum_memory_units_observed,
            initial_memory,
        )
        if initial_memory > limits.max_memory_units:
            return _result(
                AttackPathPlannerOutcome.BOUND_EXHAUSTED,
                "max_memory_units_exhausted",
                domain,
                authority,
                initial_state,
                limits,
                metrics,
                None,
            )

        while frontier:
            rank, _, current = heapq.heappop(frontier)
            state_sha = current.state.state_sha256
            if best_by_state.get(state_sha) != _best_state_key(current):
                metrics.deduplicated_states += 1
                continue
            if current.path and _goal_satisfied(domain, current.state, ticks):
                # CRITICAL: charge proposal construction before allocation; success cannot bypass hard bounds.
                completion_memory = (
                    _memory_units(best_by_state, frontier, len(actions))
                    + len(current.path)
                    + len(current.path)
                    + max(len(current.path) - 1, 0)
                    + len(domain.objective.required_predicates)
                )
                metrics.maximum_memory_units_observed = max(
                    metrics.maximum_memory_units_observed,
                    completion_memory,
                )
                if completion_memory > limits.max_memory_units:
                    return _result(
                        AttackPathPlannerOutcome.BOUND_EXHAUSTED,
                        "max_memory_units_exhausted",
                        domain,
                        authority,
                        initial_state,
                        limits,
                        metrics,
                        None,
                    )
                ticks.charge(
                    len(current.path) + max(len(current.path) - 1, 0) + len(domain.objective.required_predicates)
                )
                revision = _build_revision(domain, authority, initial_state, current, rank)
                return _result(
                    AttackPathPlannerOutcome.PLAN_FOUND,
                    "plan_found",
                    domain,
                    authority,
                    initial_state,
                    limits,
                    metrics,
                    revision,
                )
            if metrics.expanded_states >= limits.max_expanded_states:
                return _result(
                    AttackPathPlannerOutcome.BOUND_EXHAUSTED,
                    "max_expanded_states_exhausted",
                    domain,
                    authority,
                    initial_state,
                    limits,
                    metrics,
                    None,
                )
            metrics.expanded_states += 1

            for action in actions:
                ticks.charge()
                if not _predicates_all_true(action.operator.preconditions, current.state, ticks):
                    metrics.prune("precondition_not_satisfied")
                    continue
                depth = len(current.path) + 1
                if depth > authority.bounds.max_depth or depth > authority.bounds.max_nodes:
                    hit_bound = True
                    first_bound_reason = first_bound_reason or "authority_graph_bound_exhausted"
                    metrics.prune("authority_graph_bound_exhausted")
                    continue
                resources = _add_resources(current.resources, action.operator)
                if not _resources_within_authority(resources, authority):
                    hit_bound = True
                    first_bound_reason = first_bound_reason or "authority_resource_bound_exhausted"
                    metrics.prune("authority_resource_bound_exhausted")
                    continue
                if metrics.generated_states >= limits.max_generated_states:
                    return _result(
                        AttackPathPlannerOutcome.BOUND_EXHAUSTED,
                        "max_generated_states_exhausted",
                        domain,
                        authority,
                        initial_state,
                        limits,
                        metrics,
                        None,
                    )
                successor_state = _apply_effects(current.state, action.operator, ticks)
                metrics.generated_states += 1
                if not _state_is_safe(domain, successor_state, ticks):
                    metrics.prune("unsafe_transition")
                    continue
                path = (*current.path, action)
                path_key = (*current.path_key, action.key)
                successor = _SearchNode(successor_state, path, path_key, resources)
                successor_sha = successor_state.state_sha256
                successor_best = _best_state_key(successor)
                previous_best = best_by_state.get(successor_sha)
                if previous_best is not None and previous_best <= successor_best:
                    metrics.deduplicated_states += 1
                    metrics.prune("state_deduplicated")
                    continue
                if width_by_depth[depth] >= authority.bounds.max_width:
                    hit_bound = True
                    first_bound_reason = first_bound_reason or "authority_width_bound_exhausted"
                    metrics.prune("authority_width_bound_exhausted")
                    continue
                if len(frontier) >= effective_frontier:
                    return _result(
                        AttackPathPlannerOutcome.BOUND_EXHAUSTED,
                        "max_frontier_exhausted",
                        domain,
                        authority,
                        initial_state,
                        limits,
                        metrics,
                        None,
                    )
                best_by_state[successor_sha] = successor_best
                width_by_depth[depth] += 1
                generation_serial += 1
                heapq.heappush(frontier, (_rank(domain, successor, ticks), generation_serial, successor))
                metrics.maximum_frontier_observed = max(metrics.maximum_frontier_observed, len(frontier))
                metrics.maximum_depth_observed = max(metrics.maximum_depth_observed, depth)
                memory_units = _memory_units(best_by_state, frontier, len(actions))
                metrics.maximum_memory_units_observed = max(
                    metrics.maximum_memory_units_observed,
                    memory_units,
                )
                # CRITICAL: this deterministic proxy is checked after every enqueue before more state is explored.
                if memory_units > limits.max_memory_units:
                    return _result(
                        AttackPathPlannerOutcome.BOUND_EXHAUSTED,
                        "max_memory_units_exhausted",
                        domain,
                        authority,
                        initial_state,
                        limits,
                        metrics,
                        None,
                    )

        if hit_bound:
            return _result(
                AttackPathPlannerOutcome.BOUND_EXHAUSTED,
                first_bound_reason or "search_bound_exhausted",
                domain,
                authority,
                initial_state,
                limits,
                metrics,
                None,
            )
        if has_unsupported:
            detail = (
                "unsupported_open_required_parameter"
                if metrics.pruned_reasons and metrics.pruned_reasons["unsupported_open_required_parameter"]
                else "unsupported_operator_semantics"
            )
            return _result(
                AttackPathPlannerOutcome.UNSUPPORTED,
                detail,
                domain,
                authority,
                initial_state,
                limits,
                metrics,
                None,
            )
        return _result(
            AttackPathPlannerOutcome.NO_PLAN,
            "reachable_state_space_exhausted",
            domain,
            authority,
            initial_state,
            limits,
            metrics,
            None,
        )
    except _SearchTimeout:
        return _result(
            AttackPathPlannerOutcome.TIMEOUT,
            "deterministic_search_ticks_exhausted",
            domain,
            authority,
            initial_state,
            limits,
            metrics,
            None,
        )


def _closed_initial_state(
    domain: PlanningDomainV1,
    supplied: WorldStateV1,
    ticks: _TickBudget,
) -> WorldStateV1:
    definitions = {item.fact_id: item for item in domain.facts}
    supplied_values = {item.fact_id: item.value for item in supplied.values}
    if set(supplied_values) - set(definitions):
        raise _InitialStateMismatch
    values: list[FactValueV1] = []
    for fact_id, definition in sorted(definitions.items()):
        ticks.charge()
        value = supplied_values.get(fact_id)
        if value is not None and not _value_matches_definition(value, definition):
            raise _InitialStateMismatch
        values.append(FactValueV1(fact_id, value))
    return WorldStateV1(tuple(values))


def _value_matches_definition(value: ScalarValueV1, definition: FactDefinitionV1) -> bool:
    return value.value_type is definition.value_type and (
        not definition.allowed_values or value in definition.allowed_values
    )


def _enumerate_actions(
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    limits: PlannerSearchLimitsV1,
    metrics: _Metrics,
    ticks: _TickBudget,
) -> tuple[tuple[_Action, ...], bool, str | None]:
    actions: list[_Action] = []
    has_unsupported = False
    for operator in domain.operators:
        ticks.charge()
        if operator.unsupported_condition_ids:
            has_unsupported = True
            metrics.prune("unsupported_operator_semantics")
            continue
        if not _operator_is_authority_permitted(operator, authority):
            metrics.prune("operator_outside_authority")
            continue
        open_required = tuple(
            spec for spec in operator.parameters if spec.required and not spec.binds_target and not spec.allowed_values
        )
        if open_required:
            has_unsupported = True
            metrics.prune("unsupported_open_required_parameter")
            continue
        finite_specs = tuple(spec for spec in operator.parameters if spec.required and not spec.binds_target)
        finite_domains = tuple(spec.allowed_values for spec in finite_specs)
        environments = tuple(
            sorted(
                set(operator.supported_environments) & set(authority.allowed_environment_classes),
                key=lambda item: item.value,
            )
        )
        for target_id in authority.target_ids:
            for environment in environments:
                for selected_values in product(*finite_domains):
                    # CRITICAL: stop before constructing variant limit + 1; eager products can exhaust memory.
                    if metrics.enumerated_action_variants >= limits.max_action_variants:
                        return (
                            tuple(sorted(actions, key=lambda item: item.key)),
                            has_unsupported,
                            ("max_action_variants_exhausted"),
                        )
                    ticks.charge()
                    metrics.enumerated_action_variants += 1
                    arguments = _arguments(operator.parameters, target_id, finite_specs, selected_values)
                    if arguments is None:
                        metrics.prune("target_parameter_value_denied")
                        continue
                    prospective_memory = len(actions) + 2
                    if prospective_memory > limits.max_memory_units:
                        return (
                            tuple(sorted(actions, key=lambda item: item.key)),
                            has_unsupported,
                            ("max_memory_units_exhausted"),
                        )
                    argument_sha = canonical_planning_sha256(arguments)
                    key = (operator.operator_id, target_id, environment.value, argument_sha)
                    actions.append(_Action(operator, target_id, environment, arguments, key))
                    metrics.maximum_memory_units_observed = max(
                        metrics.maximum_memory_units_observed,
                        prospective_memory,
                    )
    return tuple(sorted(actions, key=lambda item: item.key)), has_unsupported, None


def _operator_is_authority_permitted(
    operator: CapabilityOperatorV1,
    authority: CampaignAuthorityEnvelopeV2,
) -> bool:
    return (
        operator.capability.capability_id in authority.capability_ids
        and operator.effect_class in authority.allowed_effect_classes
        and operator.effect_class not in authority.forbidden_effect_classes
        and operator.data_access_class in authority.allowed_data_access_classes
        and operator.credential_class in authority.allowed_credential_classes
    )


def _arguments(
    specs: tuple[TypedParameterSpecV1, ...],
    target_id: str,
    finite_specs: tuple[TypedParameterSpecV1, ...],
    selected_values: tuple[ScalarValueV1, ...],
) -> tuple[TypedParameterBindingV1, ...] | None:
    selected = {spec.name: value for spec, value in zip(finite_specs, selected_values, strict=True)}
    if any(not _parameter_value_permitted(spec, selected[spec.name]) for spec in finite_specs):
        return None
    bindings: list[TypedParameterBindingV1] = []
    for spec in specs:
        if spec.binds_target:
            target_value = ScalarValueV1(ScalarType.STRING, target_id)
            if spec.allowed_values and target_value not in spec.allowed_values:
                return None
            bindings.append(TypedParameterBindingV1(spec.name, target_value))
        elif spec.required:
            bindings.append(TypedParameterBindingV1(spec.name, selected[spec.name]))
    return tuple(bindings)


def _parameter_value_permitted(spec: TypedParameterSpecV1, value: ScalarValueV1) -> bool:
    if value.value_type is not spec.value_type:
        return False
    if spec.value_type is not ScalarType.INTEGER:
        return True
    if type(value.value) is not int:
        return False
    if spec.minimum is not None and value.value < spec.minimum:
        return False
    return spec.maximum is None or value.value <= spec.maximum


def _rank(domain: PlanningDomainV1, node: _SearchNode, ticks: _TickBudget) -> _Rank:
    # IMPORTANT: preserve every tuple component and order; shortening it makes equal inputs host-order dependent.
    distance = 0
    for predicate in domain.objective.required_predicates:
        if _evaluate_predicate(predicate, node.state, ticks) is not True:
            distance += 1
    return (
        distance,
        node.resources.risk_micropoints,
        node.resources.cost_microunits,
        len(node.path),
        node.path_key,
        node.state.state_sha256,
    )


def _best_state_key(node: _SearchNode) -> _BestStateKey:
    return (
        node.resources.risk_micropoints,
        node.resources.cost_microunits,
        len(node.path),
        node.path_key,
    )


def _predicates_all_true(
    predicates: tuple[PredicateV1, ...],
    state: WorldStateV1,
    ticks: _TickBudget,
) -> bool:
    return all(_evaluate_predicate(predicate, state, ticks) is True for predicate in predicates)


def _state_is_safe(domain: PlanningDomainV1, state: WorldStateV1, ticks: _TickBudget) -> bool:
    if not _predicates_all_true(domain.invariants, state, ticks):
        return False
    return all(
        _evaluate_predicate(predicate, state, ticks) is False for predicate in domain.objective.forbidden_predicates
    )


def _goal_satisfied(domain: PlanningDomainV1, state: WorldStateV1, ticks: _TickBudget) -> bool:
    return _predicates_all_true(domain.objective.required_predicates, state, ticks)


def _evaluate_predicate(predicate: PredicateV1, state: WorldStateV1, ticks: _TickBudget) -> _Truth:
    ticks.charge()
    values = {item.fact_id: item.value for item in state.values}
    actual = values.get(predicate.fact_id)
    if actual is None or actual.value_type is not predicate.expected.value_type:
        return None
    left = actual.value
    right = predicate.expected.value
    if predicate.operator is PredicateOperator.EQUALS:
        return left == right
    if predicate.operator is PredicateOperator.NOT_EQUALS:
        return left != right
    if type(left) is not int or type(right) is not int:
        return False
    if predicate.operator is PredicateOperator.LESS_THAN:
        return left < right
    if predicate.operator is PredicateOperator.LESS_THAN_OR_EQUAL:
        return left <= right
    if predicate.operator is PredicateOperator.GREATER_THAN:
        return left > right
    return left >= right


def _apply_effects(
    state: WorldStateV1,
    operator: CapabilityOperatorV1,
    ticks: _TickBudget,
) -> WorldStateV1:
    values = {item.fact_id: item.value for item in state.values}
    # CRITICAL: only closed typed effects are simulated; no action hook or producer callback is permitted here.
    for effect in operator.effects:
        ticks.charge()
        values[effect.fact_id] = effect.value
    return WorldStateV1(tuple(FactValueV1(fact_id, value) for fact_id, value in sorted(values.items())))


def _add_resources(current: _Resources, operator: CapabilityOperatorV1) -> _Resources:
    return _Resources(
        duration_seconds=current.duration_seconds + operator.max_duration_seconds,
        requests=current.requests + operator.max_requests,
        rate_per_minute=current.rate_per_minute + operator.max_rate_per_minute,
        concurrency=max(current.concurrency, operator.concurrency_weight),
        retries_per_node=max(current.retries_per_node, operator.max_retries),
        risk_micropoints=current.risk_micropoints + operator.max_risk_micropoints,
        cost_microunits=current.cost_microunits + operator.max_cost_microunits,
        evidence_bytes=current.evidence_bytes + operator.max_evidence_bytes,
        data_bytes=current.data_bytes + operator.max_data_bytes,
    )


def _resources_within_authority(
    resources: _Resources,
    authority: CampaignAuthorityEnvelopeV2,
) -> bool:
    bounds = authority.bounds
    return (
        resources.duration_seconds <= bounds.max_duration_seconds
        and resources.requests <= bounds.max_requests
        and resources.rate_per_minute <= bounds.max_rate_per_minute
        and resources.concurrency <= bounds.max_concurrency
        and resources.retries_per_node <= bounds.max_retries_per_node
        and resources.risk_micropoints <= bounds.max_risk_micropoints
        and resources.cost_microunits <= bounds.max_cost_microunits
        and resources.evidence_bytes <= bounds.max_evidence_bytes
        and resources.data_bytes <= bounds.max_data_bytes
    )


def _memory_units(
    best_by_state: dict[str, _BestStateKey],
    frontier: list[tuple[_Rank, int, _SearchNode]],
    action_count: int,
) -> int:
    return action_count + len(best_by_state) + len(frontier) + sum(len(item[2].path) for item in frontier)


def _build_revision(
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    initial_state: WorldStateV1,
    winner: _SearchNode,
    rank: _Rank,
) -> AttackPathDagRevisionV1:
    path_sha = canonical_planning_sha256(winner.path_key)
    plan_id = f"plan-{canonical_planning_sha256((domain.domain_sha256, authority.authority_sha256, initial_state.state_sha256, path_sha))[:24]}"
    nodes: list[PlanNodeV1] = []
    for index, action in enumerate(winner.path):
        node_suffix = canonical_planning_sha256((index, action.key))[:12]
        nodes.append(
            PlanNodeV1(
                schema_version=PLAN_NODE_SCHEMA_VERSION,
                node_id=f"node-{index:04d}-{node_suffix}",
                operator_id=action.operator.operator_id,
                target_id=action.target_id,
                environment=action.environment,
                arguments=action.arguments,
                order=index,
                join_policy=PlanJoinPolicy.ALL,
            )
        )
    edges = tuple(
        PlanEdgeV1(
            schema_version=PLAN_EDGE_SCHEMA_VERSION,
            edge_id=f"edge-{index - 1:04d}-{index:04d}",
            source_node_id=nodes[index - 1].node_id,
            target_node_id=nodes[index].node_id,
            conditions=winner.path[index].operator.preconditions,
        )
        for index in range(1, len(nodes))
    )
    candidate = CandidatePlanV1(
        schema_version=CANDIDATE_PLAN_SCHEMA_VERSION,
        plan_id=plan_id,
        tenant_id=authority.tenant_id,
        engagement_id=authority.engagement_id,
        authority_sha256=authority.authority_sha256,
        domain_sha256=domain.domain_sha256,
        objective_id=domain.objective.objective_id,
        initial_state=initial_state,
        nodes=tuple(nodes),
        edges=edges,
    )
    final_values = {item.fact_id: item.value for item in winner.state.values}
    claims = tuple(
        PredictedGoalClaimV1(
            schema_version=PREDICTED_GOAL_CLAIM_SCHEMA_VERSION,
            fact_id=predicate.fact_id,
            expected=predicate.expected,
            predicted_value=_required_value(final_values[predicate.fact_id]),
            source_node_id=nodes[-1].node_id,
            predicted_only=True,
        )
        for predicate in domain.objective.required_predicates
    )
    ordering_key = PlanOrderingKeyV1(
        schema_version=PLAN_ORDERING_KEY_SCHEMA_VERSION,
        unsatisfied_required_count=rank[0],
        cumulative_risk_micropoints=winner.resources.risk_micropoints,
        cumulative_cost_microunits=winner.resources.cost_microunits,
        depth=len(nodes),
        path_action_sha256=path_sha,
        state_sha256=winner.state.state_sha256,
    )
    revision_material = (
        authority.authority_sha256,
        domain.domain_sha256,
        canonical_planning_sha256(domain.objective),
        initial_state.state_sha256,
        candidate.plan_sha256,
        PLANNER_SHA256,
    )
    return AttackPathDagRevisionV1(
        schema_version=ATTACK_PATH_DAG_SCHEMA_VERSION,
        revision_id=f"revision-{canonical_planning_sha256(revision_material)[:24]}",
        parent_revision_id=None,
        planner_version=PLANNER_VERSION,
        planner_sha256=PLANNER_SHA256,
        tenant_id=authority.tenant_id,
        engagement_id=authority.engagement_id,
        authority_sha256=authority.authority_sha256,
        domain_sha256=domain.domain_sha256,
        objective_sha256=canonical_planning_sha256(domain.objective),
        initial_state_sha256=initial_state.state_sha256,
        candidate_plan=candidate,
        root_node_ids=(nodes[0].node_id,),
        terminal_node_ids=(nodes[-1].node_id,),
        predicted_goal_claims=claims,
        total_cost_microunits=winner.resources.cost_microunits,
        total_risk_micropoints=winner.resources.risk_micropoints,
        depth=len(nodes),
        width=1,
        node_count=len(nodes),
        ordering_key=ordering_key,
    )


def _required_value(value: ScalarValueV1 | None) -> ScalarValueV1:
    if value is None:
        raise ValueError("planner_goal_value_missing")
    return value


def _result(
    outcome: AttackPathPlannerOutcome,
    detail_code: str,
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    initial_state: WorldStateV1,
    limits: PlannerSearchLimitsV1,
    metrics: _Metrics,
    revision: AttackPathDagRevisionV1 | None,
) -> AttackPathPlannerResultV1:
    reasons = metrics.pruned_reasons or Counter()
    receipt = SearchReceiptV1(
        schema_version=SEARCH_RECEIPT_SCHEMA_VERSION,
        planner_version=PLANNER_VERSION,
        planner_sha256=PLANNER_SHA256,
        total_order_version=TOTAL_ORDER_VERSION,
        outcome=outcome,
        detail_code=detail_code,
        authority_sha256=authority.authority_sha256,
        domain_sha256=domain.domain_sha256,
        objective_sha256=canonical_planning_sha256(domain.objective),
        initial_state_sha256=initial_state.state_sha256,
        limits_sha256=limits.limits_sha256,
        enumerated_action_variants=metrics.enumerated_action_variants,
        expanded_states=metrics.expanded_states,
        generated_states=metrics.generated_states,
        deduplicated_states=metrics.deduplicated_states,
        pruned_states=sum(reasons.values()),
        maximum_frontier_observed=metrics.maximum_frontier_observed,
        maximum_depth_observed=metrics.maximum_depth_observed,
        maximum_memory_units_observed=metrics.maximum_memory_units_observed,
        search_ticks=metrics.search_ticks,
        pruned_reasons=tuple(SearchReasonCountV1(reason, count) for reason, count in sorted(reasons.items())),
        found_revision_sha256=revision.revision_sha256 if revision is not None else None,
    )
    return AttackPathPlannerResultV1(
        schema_version=ATTACK_PATH_PLANNER_RESULT_SCHEMA_VERSION,
        outcome=outcome,
        revision=revision,
        receipt=receipt,
    )
