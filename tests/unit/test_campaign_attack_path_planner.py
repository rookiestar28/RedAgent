from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import os
from pathlib import Path
import subprocess
import sys

import pytest

from redagent_platform.campaign_service.planning.contracts import (
    FactAssignmentV1,
    FactDefinitionV1,
    FactValueV1,
    PlanningDomainV1,
    PlanningObjectiveV1,
    ScalarType,
    TypedParameterSpecV1,
    ValidationResult,
    WorldStateV1,
    canonical_planning_bytes,
)
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.search_contracts import (
    AttackPathPlannerOutcome,
    PlannerSearchLimitsV1,
)
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan
from tests.unit.test_campaign_planning_contracts import (
    NOW,
    authority,
    domain,
    limits as validation_limits,
    operator,
    predicate,
    scalar,
    world,
)


ROOT = Path(__file__).resolve().parents[2]


def search_limits(**overrides: int) -> PlannerSearchLimitsV1:
    values = {
        "max_expanded_states": 100,
        "max_generated_states": 1_000,
        "max_frontier": 100,
        "max_search_ticks": 100_000,
        "max_memory_units": 10_000,
    }
    values.update(overrides)
    return PlannerSearchLimitsV1(**values)


def test_search_limits_are_immutable_canonical_and_strictly_typed() -> None:
    current = search_limits()
    assert current.schema_version == "redagent.planner-search-limits/v1"
    assert current.max_action_variants == 10_000
    assert current.limits_sha256 == search_limits().limits_sha256
    with pytest.raises(FrozenInstanceError):
        current.max_frontier = 2  # type: ignore[misc]
    with pytest.raises(ValueError, match="planner_limit_max_frontier_invalid"):
        replace(current, max_frontier=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="planner_search_limits_schema_unsupported"):
        replace(current, schema_version="redagent.planner-search-limits/v2")


def test_one_step_plan_is_byte_deterministic_and_independently_valid() -> None:
    current_domain = domain()
    current_authority = authority()
    first = plan_attack_path(current_domain, current_authority, world(), search_limits())
    repeated = plan_attack_path(current_domain, current_authority, world(), search_limits())

    assert first.outcome is AttackPathPlannerOutcome.PLAN_FOUND
    assert first.revision is not None
    assert canonical_planning_bytes(first) == canonical_planning_bytes(repeated)
    assert first.result_sha256 == repeated.result_sha256
    assert first.receipt.found_revision_sha256 == first.revision.revision_sha256
    assert first.revision.parent_revision_id is None
    assert first.revision.root_node_ids == (first.revision.candidate_plan.nodes[0].node_id,)
    assert first.revision.terminal_node_ids == (first.revision.candidate_plan.nodes[-1].node_id,)
    assert first.revision.node_count == 1
    assert first.revision.depth == 1
    assert first.revision.width == 1
    assert all(claim.predicted_only for claim in first.revision.predicted_goal_claims)

    certificate = validate_candidate_plan(
        first.revision.candidate_plan,
        current_domain,
        current_authority,
        limits=validation_limits(),
        validated_at=NOW.replace(second=30),
    )
    assert certificate.result is ValidationResult.VALID
    assert certificate.plan_sha256 == first.revision.candidate_plan.plan_sha256
    assert not hasattr(first, "validation_certificate")


def _two_step_domain() -> tuple[PlanningDomainV1, WorldStateV1]:
    discover = replace(
        operator(),
        operator_id="discover-posture-source",
        effects=(FactAssignmentV1("source-discovered", scalar(ScalarType.BOOLEAN, True)),),
        observation_fact_ids=("source-discovered",),
    )
    collect = replace(
        operator(),
        preconditions=(predicate("source-discovered", ScalarType.BOOLEAN, True),),
    )
    current_domain = domain(
        facts=(
            FactDefinitionV1("authorized", ScalarType.BOOLEAN, ()),
            FactDefinitionV1("finding-count", ScalarType.INTEGER, ()),
            FactDefinitionV1("posture-collected", ScalarType.BOOLEAN, ()),
            FactDefinitionV1("source-discovered", ScalarType.BOOLEAN, ()),
        ),
        operators=tuple(sorted((collect, discover), key=lambda item: item.operator_id)),
    )
    initial = WorldStateV1(
        tuple(
            sorted(
                (*world().values, FactValueV1("source-discovered", scalar(ScalarType.BOOLEAN, False))),
                key=lambda item: item.fact_id,
            )
        )
    )
    return current_domain, initial


def test_multi_step_winner_is_a_canonical_path_dag_with_explicit_conditions() -> None:
    current_domain, initial = _two_step_domain()
    result = plan_attack_path(current_domain, authority(), initial, search_limits())

    assert result.outcome is AttackPathPlannerOutcome.PLAN_FOUND
    assert result.revision is not None
    plan = result.revision.candidate_plan
    assert tuple(node.operator_id for node in plan.nodes) == (
        "discover-posture-source",
        "collect-artifact-posture",
    )
    assert len(plan.edges) == 1
    assert plan.edges[0].source_node_id == plan.nodes[0].node_id
    assert plan.edges[0].target_node_id == plan.nodes[1].node_id
    assert plan.edges[0].conditions == current_domain.operators[0].preconditions
    assert result.revision.total_cost_microunits == 200
    assert result.revision.total_risk_micropoints == 20


def test_total_order_prefers_lower_risk_then_cost_before_lexical_action_key() -> None:
    expensive = replace(
        operator(),
        operator_id="alpha-expensive",
        max_risk_micropoints=20,
        max_cost_microunits=10,
    )
    safer = replace(
        operator(),
        operator_id="zeta-safer",
        max_risk_micropoints=10,
        max_cost_microunits=100,
    )
    result = plan_attack_path(
        domain(operators=(expensive, safer)),
        authority(),
        world(),
        search_limits(),
    )
    assert result.outcome is AttackPathPlannerOutcome.PLAN_FOUND
    assert result.revision is not None
    assert result.revision.candidate_plan.nodes[0].operator_id == "zeta-safer"
    assert result.revision.ordering_key.cumulative_risk_micropoints == 10


def test_supported_state_space_exhaustion_is_no_plan() -> None:
    inert = replace(
        operator(),
        effects=(FactAssignmentV1("posture-collected", scalar(ScalarType.BOOLEAN, False)),),
    )
    result = plan_attack_path(domain(operators=(inert,)), authority(), world(), search_limits())
    assert result.outcome is AttackPathPlannerOutcome.NO_PLAN
    assert result.revision is None
    assert result.receipt.detail_code == "reachable_state_space_exhausted"


@pytest.mark.parametrize(
    ("current_domain", "initial", "detail"),
    (
        (
            domain(operators=(operator(unsupported_condition_ids=("opaque-condition",)),)),
            world(),
            "unsupported_operator_semantics",
        ),
        (
            domain(
                operators=(
                    replace(
                        operator(),
                        parameters=(
                            TypedParameterSpecV1(
                                name="mode",
                                value_type=ScalarType.STRING,
                                required=True,
                                allowed_values=(),
                                minimum=None,
                                maximum=None,
                                binds_target=False,
                            ),
                            operator().parameters[0],
                        ),
                    ),
                )
            ),
            world(),
            "unsupported_open_required_parameter",
        ),
        (
            domain(),
            WorldStateV1(
                tuple(
                    replace(item, value=scalar(ScalarType.BOOLEAN, True))
                    if item.fact_id == "posture-collected"
                    else item
                    for item in world().values
                )
            ),
            "initial_objective_already_satisfied",
        ),
    ),
)
def test_opaque_or_unrepresentable_semantics_are_truthfully_unsupported(
    current_domain: PlanningDomainV1,
    initial: WorldStateV1,
    detail: str,
) -> None:
    result = plan_attack_path(current_domain, authority(), initial, search_limits())
    assert result.outcome is AttackPathPlannerOutcome.UNSUPPORTED
    assert result.revision is None
    assert result.receipt.detail_code == detail


@pytest.mark.parametrize(
    "initial",
    (
        WorldStateV1((*world().values, FactValueV1("unknown-fact", scalar(ScalarType.BOOLEAN, True)))),
        WorldStateV1(
            tuple(
                replace(item, value=scalar(ScalarType.STRING, "wrong-type"))
                if item.fact_id == "finding-count"
                else item
                for item in world().values
            )
        ),
    ),
)
def test_initial_state_domain_mismatch_is_unsupported_not_internal_error(initial: WorldStateV1) -> None:
    result = plan_attack_path(domain(), authority(), initial, search_limits())
    assert result.outcome is AttackPathPlannerOutcome.UNSUPPORTED
    assert result.receipt.detail_code == "initial_state_domain_mismatch"


def test_finite_parameter_values_are_range_filtered_before_independent_validation() -> None:
    allowed = tuple(
        sorted(
            (scalar(ScalarType.INTEGER, 5), scalar(ScalarType.INTEGER, 100)),
            key=canonical_planning_bytes,
        )
    )
    ranged = replace(
        operator(),
        parameters=(
            TypedParameterSpecV1(
                name="mode",
                value_type=ScalarType.INTEGER,
                required=True,
                allowed_values=allowed,
                minimum=0,
                maximum=10,
                binds_target=False,
            ),
            operator().parameters[0],
        ),
    )
    current_domain = domain(operators=(ranged,))
    result = plan_attack_path(current_domain, authority(), world(), search_limits())
    assert result.outcome is AttackPathPlannerOutcome.PLAN_FOUND
    assert result.revision is not None
    arguments = {item.name: item.value.value for item in result.revision.candidate_plan.nodes[0].arguments}
    assert arguments == {"mode": 5, "target": "target-a"}
    certificate = validate_candidate_plan(
        result.revision.candidate_plan,
        current_domain,
        authority(),
        limits=validation_limits(),
        validated_at=NOW.replace(second=30),
    )
    assert certificate.result is ValidationResult.VALID


def test_action_catalog_is_bounded_before_cartesian_materialization() -> None:
    finite = replace(
        operator(),
        parameters=(
            TypedParameterSpecV1(
                name="mode",
                value_type=ScalarType.STRING,
                required=True,
                allowed_values=(
                    scalar(ScalarType.STRING, "mode-a"),
                    scalar(ScalarType.STRING, "mode-b"),
                ),
                minimum=None,
                maximum=None,
                binds_target=False,
            ),
            operator().parameters[0],
        ),
    )
    current_domain = domain(operators=(finite,))
    result = plan_attack_path(
        current_domain,
        authority(),
        world(),
        replace(search_limits(), max_action_variants=1),
    )
    assert result.outcome is AttackPathPlannerOutcome.BOUND_EXHAUSTED
    assert result.receipt.detail_code == "max_action_variants_exhausted"
    assert result.receipt.enumerated_action_variants == 1
    assert result.receipt.maximum_memory_units_observed <= 2
    assert result.revision is None


def test_initial_frontier_and_final_proposal_are_both_charged_to_memory_proxy() -> None:
    no_authorized_action = plan_attack_path(
        domain(),
        authority(capability_ids=("other-capability",)),
        world(),
        search_limits(max_memory_units=1),
    )
    proposal_allocation = plan_attack_path(
        domain(),
        authority(),
        world(),
        search_limits(max_memory_units=5),
    )
    for result in (no_authorized_action, proposal_allocation):
        assert result.outcome is AttackPathPlannerOutcome.BOUND_EXHAUSTED
        assert result.receipt.detail_code == "max_memory_units_exhausted"
        assert result.revision is None


def test_final_proposal_construction_is_charged_to_search_ticks() -> None:
    result = plan_attack_path(
        domain(),
        authority(),
        world(),
        search_limits(max_search_ticks=16),
    )
    assert result.outcome is AttackPathPlannerOutcome.TIMEOUT
    assert result.receipt.detail_code == "deterministic_search_ticks_exhausted"
    assert result.revision is None


def test_unsafe_intermediate_transition_is_pruned_not_repaired() -> None:
    unsafe = replace(
        operator(),
        operator_id="alpha-unsafe",
        effects=(FactAssignmentV1("authorized", scalar(ScalarType.BOOLEAN, False)),),
        observation_fact_ids=("authorized",),
    )
    safe = replace(operator(), operator_id="zeta-safe")
    result = plan_attack_path(domain(operators=(unsafe, safe)), authority(), world(), search_limits())
    assert result.outcome is AttackPathPlannerOutcome.PLAN_FOUND
    assert result.revision is not None
    assert result.revision.candidate_plan.nodes[0].operator_id == "zeta-safe"
    assert ("unsafe_transition", 1) in tuple((item.reason, item.count) for item in result.receipt.pruned_reasons)


def test_non_time_and_time_limits_have_distinct_truthful_outcomes() -> None:
    current_domain, initial = _two_step_domain()
    bounded = plan_attack_path(
        current_domain,
        authority(),
        initial,
        search_limits(max_expanded_states=1),
    )
    timed_out = plan_attack_path(
        current_domain,
        authority(),
        initial,
        search_limits(max_search_ticks=1),
    )
    assert bounded.outcome is AttackPathPlannerOutcome.BOUND_EXHAUSTED
    assert bounded.receipt.detail_code == "max_expanded_states_exhausted"
    assert timed_out.outcome is AttackPathPlannerOutcome.TIMEOUT
    assert timed_out.receipt.detail_code == "deterministic_search_ticks_exhausted"
    assert bounded.revision is timed_out.revision is None


@pytest.mark.parametrize(
    ("limit_overrides", "detail"),
    (
        ({"max_generated_states": 1}, "max_generated_states_exhausted"),
        ({"max_memory_units": 1}, "max_memory_units_exhausted"),
    ),
)
def test_each_server_search_resource_ceiling_is_truthful(limit_overrides: dict[str, int], detail: str) -> None:
    current_domain, initial = _two_step_domain()
    result = plan_attack_path(current_domain, authority(), initial, search_limits(**limit_overrides))
    assert result.outcome is AttackPathPlannerOutcome.BOUND_EXHAUSTED
    assert result.receipt.detail_code == detail
    assert result.revision is None


def test_frontier_ceiling_stops_before_selecting_from_an_incomplete_goal_frontier() -> None:
    first = replace(
        operator(),
        operator_id="first-goal",
        effects=(
            FactAssignmentV1("finding-count", scalar(ScalarType.INTEGER, 1)),
            operator().effects[0],
        ),
        observation_fact_ids=("finding-count", "posture-collected"),
    )
    second = replace(
        operator(),
        operator_id="second-goal",
        effects=(
            FactAssignmentV1("finding-count", scalar(ScalarType.INTEGER, 2)),
            operator().effects[0],
        ),
        observation_fact_ids=("finding-count", "posture-collected"),
    )
    result = plan_attack_path(
        domain(operators=(first, second)),
        authority(),
        world(),
        search_limits(max_frontier=1),
    )
    assert result.outcome is AttackPathPlannerOutcome.BOUND_EXHAUSTED
    assert result.receipt.detail_code == "max_frontier_exhausted"
    assert result.revision is None


@pytest.mark.parametrize(
    ("bound_overrides", "detail"),
    (
        ({"max_depth": 1}, "authority_graph_bound_exhausted"),
        ({"max_risk_micropoints": 15}, "authority_resource_bound_exhausted"),
        ({"max_cost_microunits": 150}, "authority_resource_bound_exhausted"),
    ),
)
def test_authority_depth_cost_and_risk_bounds_never_return_partial_plan(
    bound_overrides: dict[str, int], detail: str
) -> None:
    current_domain, initial = _two_step_domain()
    current_authority = authority(bounds=replace(authority().bounds, **bound_overrides))
    result = plan_attack_path(current_domain, current_authority, initial, search_limits())
    assert result.outcome is AttackPathPlannerOutcome.BOUND_EXHAUSTED
    assert result.receipt.detail_code == detail
    assert result.revision is None


def test_unexpected_internal_error_is_redacted_and_never_returns_partial_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    import redagent_platform.campaign_service.planning.search as search_module

    def fail(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr(search_module, "_search_attack_path", fail)
    result = search_module.plan_attack_path(domain(), authority(), world(), search_limits())
    assert result.outcome is AttackPathPlannerOutcome.INTERNAL_ERROR
    assert result.revision is None
    assert result.receipt.detail_code == "planner_internal_error"
    assert b"sensitive" not in canonical_planning_bytes(result)


def test_canonical_result_is_stable_across_hash_seeds_and_processes() -> None:
    script = """
from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.search_contracts import PlannerSearchLimitsV1
from tests.unit.test_campaign_planning_contracts import authority, domain, world
limits = PlannerSearchLimitsV1(100, 1000, 100, 100000, 10000)
print(canonical_planning_bytes(plan_attack_path(domain(), authority(), world(), limits)).hex())
"""
    outputs = []
    for seed in ("1", "73"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(completed.stdout.strip())
    assert outputs[0] == outputs[1]


def test_small_chain_search_matches_exhaustive_shortest_depth_oracle() -> None:
    for chain_length in (1, 2, 3):
        fact_ids = tuple(f"stage-{index}" for index in range(chain_length + 1))
        facts = tuple(FactDefinitionV1(fact_id, ScalarType.BOOLEAN, ()) for fact_id in fact_ids)
        operators = []
        for index in range(chain_length):
            operators.append(
                replace(
                    operator(),
                    operator_id=f"advance-{index:02d}",
                    preconditions=(predicate(fact_ids[index], ScalarType.BOOLEAN, True),),
                    effects=(FactAssignmentV1(fact_ids[index + 1], scalar(ScalarType.BOOLEAN, True)),),
                    observation_fact_ids=(fact_ids[index + 1],),
                )
            )
        objective = PlanningObjectiveV1(
            objective_id="collect-posture",
            required_predicates=(predicate(fact_ids[-1], ScalarType.BOOLEAN, True),),
            forbidden_predicates=(),
        )
        current_domain = domain(
            facts=facts,
            operators=tuple(operators),
            invariants=(),
            objective=objective,
        )
        initial = WorldStateV1(
            tuple(
                FactValueV1(fact_id, scalar(ScalarType.BOOLEAN, index == 0)) for index, fact_id in enumerate(fact_ids)
            )
        )
        result = plan_attack_path(
            current_domain,
            authority(success_condition_ids=(fact_ids[-1],)),
            initial,
            search_limits(),
        )
        assert result.outcome is AttackPathPlannerOutcome.PLAN_FOUND
        assert result.revision is not None
        assert result.revision.depth == chain_length
