"""Deterministic, side-effect-free validation for campaign plan candidates."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
from typing import TypeAlias

from redagent_platform.campaign_service.authority_envelope import CampaignAuthorityEnvelopeV2
from redagent_platform.campaign_service.planning.contracts import (
    PLAN_VALIDATION_CERTIFICATE_SCHEMA_VERSION,
    CandidatePlanV1,
    CapabilityOperatorV1,
    FactDefinitionV1,
    PlanEdgeV1,
    PlanNodeV1,
    PlanValidationCertificateV1,
    PlanningDomainV1,
    PlanJoinPolicy,
    PredicateOperator,
    PredicateV1,
    ScalarType,
    ScalarValueV1,
    ValidationCounterexampleV1,
    ValidationLimitsV1,
    ValidationResult,
)


VALIDATOR_VERSION = "redagent-independent-plan-validator.v1"
VALIDATOR_SHA256 = hashlib.sha256(
    b"redagent-independent-plan-validator/v1:closed-world-dag-state-authority-bounds"
).hexdigest()

_Truth: TypeAlias = bool | None


def validate_candidate_plan(
    plan: CandidatePlanV1,
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    *,
    limits: ValidationLimitsV1,
    validated_at: datetime,
) -> PlanValidationCertificateV1:
    """Validate a candidate without trusting its producer or performing I/O."""
    if (
        not isinstance(plan, CandidatePlanV1)
        or not isinstance(domain, PlanningDomainV1)
        or not isinstance(authority, CampaignAuthorityEnvelopeV2)
        or not isinstance(limits, ValidationLimitsV1)
        or not isinstance(validated_at, datetime)
        or validated_at.tzinfo is None
        or validated_at.utcoffset() is None
    ):
        raise ValueError("plan_validation_input_invalid")

    if len(plan.nodes) > limits.max_nodes:
        return _unknown(plan, domain, authority, validated_at, "validation_resource_limit:max_nodes")
    if len(plan.edges) > limits.max_edges:
        return _unknown(plan, domain, authority, validated_at, "validation_resource_limit:max_edges")
    estimated_transitions = _estimated_transitions(plan, domain)
    if estimated_transitions > limits.max_state_transitions:
        return _unknown(
            plan,
            domain,
            authority,
            validated_at,
            "validation_resource_limit:max_state_transitions",
        )

    failures: set[tuple[str, str | None]] = set()
    checked_invariants = tuple(f"invariant:{index:04d}" for index, _ in enumerate(domain.invariants))

    _check_bindings(plan, domain, authority, validated_at, failures)
    definitions = {definition.fact_id: definition for definition in domain.facts}
    state = _initial_state(plan, definitions, failures)
    nodes = {node.node_id: node for node in plan.nodes}
    operators = {operator.operator_id: operator for operator in domain.operators}
    incoming: dict[str, list[PlanEdgeV1]] = defaultdict(list)
    outgoing: dict[str, list[PlanEdgeV1]] = defaultdict(list)

    _check_graph_shape(plan, nodes, definitions, incoming, outgoing, failures)
    depth_by_node = _graph_depths(plan.nodes, incoming, failures)
    active_nodes: set[str] = set()
    active_depth_weights: Counter[int] = Counter()
    totals: Counter[str] = Counter()
    maximum_retry = 0
    unsupported_semantics = False

    for node in plan.nodes:
        if not _node_is_reachable(node, incoming[node.node_id], active_nodes, state):
            failures.add(("graph_node_unreachable", node.node_id))
            continue
        operator = operators.get(node.operator_id)
        if operator is None:
            failures.add(("operator_unknown", node.node_id))
            continue
        _check_operator_authority(node, operator, authority, failures)
        _check_arguments(node, operator, failures)
        if operator.unsupported_condition_ids:
            unsupported_semantics = True
        _check_predicates(
            operator.preconditions,
            state,
            node.node_id,
            "operator_precondition_false",
            "operator_precondition_unknown",
            failures,
        )
        # CRITICAL: apply only declared typed effects here; sharing producer transition code defeats independence.
        for effect in operator.effects:
            state[effect.fact_id] = effect.value
        _check_predicates(
            domain.invariants,
            state,
            node.node_id,
            "domain_invariant_violated",
            "domain_invariant_violated",
            failures,
        )
        active_nodes.add(node.node_id)
        depth = depth_by_node.get(node.node_id, 1)
        active_depth_weights[depth] += operator.concurrency_weight
        totals["max_duration_seconds"] += operator.max_duration_seconds
        totals["max_requests"] += operator.max_requests
        totals["max_rate_per_minute"] += operator.max_rate_per_minute
        totals["max_risk_micropoints"] += operator.max_risk_micropoints
        totals["max_cost_microunits"] += operator.max_cost_microunits
        totals["max_evidence_bytes"] += operator.max_evidence_bytes
        totals["max_data_bytes"] += operator.max_data_bytes
        maximum_retry = max(maximum_retry, operator.max_retries)

    _check_graph_bounds(plan, depth_by_node, outgoing, authority, active_depth_weights, failures)
    _check_resource_bounds(totals, maximum_retry, authority, failures)
    _check_objective(domain, state, failures)

    if failures:
        return _certificate(
            plan,
            domain,
            authority,
            validated_at,
            ValidationResult.INVALID,
            checked_invariants,
            failures,
            None,
        )
    if unsupported_semantics:
        # CRITICAL: incomplete semantics are proof failure, never implicit authorization.
        return _unknown(
            plan,
            domain,
            authority,
            validated_at,
            "validation_unsupported_operator_semantics",
            checked_invariants,
        )
    return _certificate(
        plan,
        domain,
        authority,
        validated_at,
        ValidationResult.VALID,
        checked_invariants,
        set(),
        None,
    )


def _estimated_transitions(plan: CandidatePlanV1, domain: PlanningDomainV1) -> int:
    operator_costs = {
        operator.operator_id: len(operator.preconditions) + len(operator.effects) + len(domain.invariants) + 1
        for operator in domain.operators
    }
    node_cost = sum(operator_costs.get(node.operator_id, 1) for node in plan.nodes)
    edge_cost = sum(len(edge.conditions) + 1 for edge in plan.edges)
    return len(plan.initial_state.values) + node_cost + edge_cost + len(domain.objective.required_predicates)


def _check_bindings(
    plan: CandidatePlanV1,
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    validated_at: datetime,
    failures: set[tuple[str, str | None]],
) -> None:
    checks = (
        (plan.tenant_id == authority.tenant_id, "binding_mismatch:tenant_id"),
        (plan.engagement_id == authority.engagement_id, "binding_mismatch:engagement_id"),
        (plan.authority_sha256 == authority.authority_sha256, "binding_mismatch:authority_sha256"),
        (plan.domain_sha256 == domain.domain_sha256, "binding_mismatch:domain_sha256"),
        (
            plan.objective_id == domain.objective.objective_id and plan.objective_id in authority.objective_ids,
            "binding_mismatch:objective_id",
        ),
        (
            all(
                predicate.fact_id in authority.success_condition_ids
                for predicate in domain.objective.required_predicates
            ),
            "authority_success_condition_denied",
        ),
        (authority.valid_from <= validated_at < authority.expires_at, "authority_time_window_invalid"),
    )
    for passed, code in checks:
        if not passed:
            failures.add((code, plan.plan_id))


def _initial_state(
    plan: CandidatePlanV1,
    definitions: dict[str, FactDefinitionV1],
    failures: set[tuple[str, str | None]],
) -> dict[str, ScalarValueV1 | None]:
    state: dict[str, ScalarValueV1 | None] = {fact_id: None for fact_id in definitions}
    for fact in plan.initial_state.values:
        definition = definitions.get(fact.fact_id)
        if definition is None:
            failures.add(("world_state_fact_unknown", fact.fact_id))
            continue
        if fact.value is not None and (
            fact.value.value_type is not definition.value_type
            or (definition.allowed_values and fact.value not in definition.allowed_values)
        ):
            failures.add(("world_state_value_invalid", fact.fact_id))
            continue
        state[fact.fact_id] = fact.value
    return state


def _check_graph_shape(
    plan: CandidatePlanV1,
    nodes: dict[str, PlanNodeV1],
    definitions: dict[str, FactDefinitionV1],
    incoming: dict[str, list[PlanEdgeV1]],
    outgoing: dict[str, list[PlanEdgeV1]],
    failures: set[tuple[str, str | None]],
) -> None:
    orders = [node.order for node in plan.nodes]
    if len(set(orders)) != len(orders):
        failures.add(("graph_cycle_or_order_invalid", plan.plan_id))
    for edge in plan.edges:
        source = nodes.get(edge.source_node_id)
        target = nodes.get(edge.target_node_id)
        if source is None or target is None:
            failures.add(("graph_edge_endpoint_unknown", edge.edge_id))
            continue
        incoming[target.node_id].append(edge)
        outgoing[source.node_id].append(edge)
        if source.order >= target.order:
            failures.add(("graph_cycle_or_order_invalid", edge.edge_id))
        for condition in edge.conditions:
            definition = definitions.get(condition.fact_id)
            if (
                definition is None
                or condition.expected.value_type is not definition.value_type
                or (definition.allowed_values and condition.expected not in definition.allowed_values)
            ):
                failures.add(("graph_edge_condition_invalid", edge.edge_id))


def _graph_depths(
    nodes: tuple[PlanNodeV1, ...],
    incoming: dict[str, list[PlanEdgeV1]],
    failures: set[tuple[str, str | None]],
) -> dict[str, int]:
    depths: dict[str, int] = {}
    for node in nodes:
        predecessors = incoming[node.node_id]
        if not predecessors:
            depths[node.node_id] = 1
            continue
        known = [depths[edge.source_node_id] for edge in predecessors if edge.source_node_id in depths]
        if len(known) != len(predecessors):
            failures.add(("graph_cycle_or_order_invalid", node.node_id))
            continue
        depths[node.node_id] = max(known) + 1
    return depths


def _node_is_reachable(
    node: PlanNodeV1,
    incoming: list[PlanEdgeV1],
    active_nodes: set[str],
    state: dict[str, ScalarValueV1 | None],
) -> bool:
    if not incoming:
        return True
    edge_results = [
        edge.source_node_id in active_nodes
        and all(_evaluate_predicate(condition, state) is True for condition in edge.conditions)
        for edge in incoming
    ]
    if node.join_policy is PlanJoinPolicy.ALL:
        return all(edge_results)
    return any(edge_results)


def _check_operator_authority(
    node: PlanNodeV1,
    operator: CapabilityOperatorV1,
    authority: CampaignAuthorityEnvelopeV2,
    failures: set[tuple[str, str | None]],
) -> None:
    checks = (
        (node.target_id in authority.target_ids, "authority_target_denied"),
        (operator.capability.capability_id in authority.capability_ids, "authority_capability_denied"),
        (
            operator.effect_class in authority.allowed_effect_classes
            and operator.effect_class not in authority.forbidden_effect_classes,
            "authority_effect_denied",
        ),
        (operator.data_access_class in authority.allowed_data_access_classes, "authority_data_access_denied"),
        (operator.credential_class in authority.allowed_credential_classes, "authority_credential_denied"),
        (
            node.environment in authority.allowed_environment_classes
            and node.environment in operator.supported_environments,
            "authority_environment_denied",
        ),
    )
    for passed, code in checks:
        if not passed:
            failures.add((code, node.node_id))


def _check_arguments(
    node: PlanNodeV1,
    operator: CapabilityOperatorV1,
    failures: set[tuple[str, str | None]],
) -> None:
    specs = {spec.name: spec for spec in operator.parameters}
    arguments = {argument.name: argument.value for argument in node.arguments}
    if set(arguments) - set(specs):
        failures.add(("operator_argument_unknown", node.node_id))
    for spec in operator.parameters:
        value = arguments.get(spec.name)
        if value is None:
            if spec.required:
                failures.add(("operator_argument_required", node.node_id))
            continue
        if value.value_type is not spec.value_type:
            failures.add(("operator_argument_type_mismatch", node.node_id))
            continue
        if spec.allowed_values and value not in spec.allowed_values:
            failures.add(("operator_argument_value_denied", node.node_id))
        if spec.value_type is ScalarType.INTEGER:
            integer = value.value
            if type(integer) is not int:
                failures.add(("operator_argument_type_mismatch", node.node_id))
                continue
            if spec.minimum is not None and integer < spec.minimum:
                failures.add(("operator_argument_value_denied", node.node_id))
            if spec.maximum is not None and integer > spec.maximum:
                failures.add(("operator_argument_value_denied", node.node_id))
        if spec.binds_target and value.value != node.target_id:
            failures.add(("operator_target_binding_mismatch", node.node_id))


def _check_predicates(
    predicates: tuple[PredicateV1, ...],
    state: dict[str, ScalarValueV1 | None],
    subject_id: str,
    false_code: str,
    unknown_code: str,
    failures: set[tuple[str, str | None]],
) -> None:
    for predicate in predicates:
        result = _evaluate_predicate(predicate, state)
        if result is False:
            failures.add((false_code, subject_id))
        elif result is None:
            failures.add((unknown_code, subject_id))


def _evaluate_predicate(
    predicate: PredicateV1,
    state: dict[str, ScalarValueV1 | None],
) -> _Truth:
    actual = state.get(predicate.fact_id)
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


def _check_graph_bounds(
    plan: CandidatePlanV1,
    depths: dict[str, int],
    outgoing: dict[str, list[PlanEdgeV1]],
    authority: CampaignAuthorityEnvelopeV2,
    depth_weights: Counter[int],
    failures: set[tuple[str, str | None]],
) -> None:
    bounds = authority.bounds
    depth_counts = Counter(depths.values())
    maximum_depth = max(depths.values(), default=0)
    maximum_width = max(depth_counts.values(), default=0)
    maximum_frontier = max(maximum_width, max((len(edges) for edges in outgoing.values()), default=0))
    comparisons = (
        (len(plan.nodes), bounds.max_nodes, "max_nodes"),
        (maximum_depth, bounds.max_depth, "max_depth"),
        (maximum_width, bounds.max_width, "max_width"),
        (maximum_frontier, bounds.max_frontier, "max_frontier"),
        (max(depth_weights.values(), default=0), bounds.max_concurrency, "max_concurrency"),
    )
    for actual, allowed, name in comparisons:
        if actual > allowed:
            failures.add((f"authority_bound_exceeded:{name}", plan.plan_id))


def _check_resource_bounds(
    totals: Counter[str],
    maximum_retry: int,
    authority: CampaignAuthorityEnvelopeV2,
    failures: set[tuple[str, str | None]],
) -> None:
    bounds = authority.bounds
    comparisons = (
        (totals["max_duration_seconds"], bounds.max_duration_seconds, "max_duration_seconds"),
        (totals["max_requests"], bounds.max_requests, "max_requests"),
        (totals["max_rate_per_minute"], bounds.max_rate_per_minute, "max_rate_per_minute"),
        (maximum_retry, bounds.max_retries_per_node, "max_retries_per_node"),
        (totals["max_risk_micropoints"], bounds.max_risk_micropoints, "max_risk_micropoints"),
        (totals["max_cost_microunits"], bounds.max_cost_microunits, "max_cost_microunits"),
        (totals["max_evidence_bytes"], bounds.max_evidence_bytes, "max_evidence_bytes"),
        (totals["max_data_bytes"], bounds.max_data_bytes, "max_data_bytes"),
    )
    for actual, allowed, name in comparisons:
        if actual > allowed:
            failures.add((f"authority_bound_exceeded:{name}", None))


def _check_objective(
    domain: PlanningDomainV1,
    state: dict[str, ScalarValueV1 | None],
    failures: set[tuple[str, str | None]],
) -> None:
    for predicate in domain.objective.required_predicates:
        if _evaluate_predicate(predicate, state) is not True:
            failures.add(("objective_not_satisfied", domain.objective.objective_id))
    for predicate in domain.objective.forbidden_predicates:
        forbidden_result = _evaluate_predicate(predicate, state)
        if forbidden_result is True:
            failures.add(("objective_forbidden_state", domain.objective.objective_id))
        elif forbidden_result is None:
            failures.add(("objective_forbidden_state_unknown", domain.objective.objective_id))


def _unknown(
    plan: CandidatePlanV1,
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    validated_at: datetime,
    reason: str,
    checked_invariants: tuple[str, ...] = (),
) -> PlanValidationCertificateV1:
    return _certificate(
        plan,
        domain,
        authority,
        validated_at,
        ValidationResult.UNKNOWN,
        checked_invariants,
        set(),
        reason,
    )


def _certificate(
    plan: CandidatePlanV1,
    domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2,
    validated_at: datetime,
    result: ValidationResult,
    checked_invariants: tuple[str, ...],
    failures: set[tuple[str, str | None]],
    bounded_reason: str | None,
) -> PlanValidationCertificateV1:
    counterexamples = tuple(
        ValidationCounterexampleV1(code, subject_id)
        for code, subject_id in sorted(failures, key=lambda item: (item[0], item[1] or ""))
    )
    return PlanValidationCertificateV1(
        schema_version=PLAN_VALIDATION_CERTIFICATE_SCHEMA_VERSION,
        validator_version=VALIDATOR_VERSION,
        validator_sha256=VALIDATOR_SHA256,
        tenant_id=plan.tenant_id,
        engagement_id=plan.engagement_id,
        authority_sha256=authority.authority_sha256,
        domain_sha256=domain.domain_sha256,
        plan_sha256=plan.plan_sha256,
        validated_at=validated_at,
        result=result,
        checked_invariant_ids=checked_invariants,
        counterexamples=counterexamples,
        bounded_reason=bounded_reason,
    )
