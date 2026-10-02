from __future__ import annotations

from dataclasses import replace
from dataclasses import fields
import importlib

import pytest

from redagent_platform.campaign_service.planning.contracts import (
    FactAssignmentV1, FactDefinitionV1, FactValueV1, PlanningObjectiveV1,
    ScalarType, WorldStateV1,
)
from redagent_platform.campaign_service.registry import closed_execution_binding_for
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import (
    authority, capability, domain, operator, predicate, scalar,
)


def owned_planning_material():
    completed = ("owned.zap.passive.completed", "owned.nuclei.header.completed")
    operators = []
    for cap_id, fact, profile, evidence in (
        ("zap-controlled-runtime", completed[0], "zap-passive-v1", 10),
        ("nuclei-trusted-runtime", completed[1], "nuclei-http-header-v1", 2),
    ):
        binding = closed_execution_binding_for(cap_id)
        cap = replace(capability(), **{field.name: getattr(binding, field.name) for field in fields(capability())
                                      if hasattr(binding, field.name)})
        conditions = (predicate("authorized", ScalarType.BOOLEAN, True),)
        if cap_id.startswith("nuclei"):
            conditions += (predicate(completed[0], ScalarType.BOOLEAN, True),)
        operators.append(operator(
            operator_id="complete-" + cap_id, capability=cap,
            preconditions=tuple(sorted(conditions, key=lambda p: p.fact_id)),
            effects=(FactAssignmentV1(fact, scalar(ScalarType.BOOLEAN, True)),),
            observation_fact_ids=(fact,), max_duration_seconds=60, max_requests=20,
            max_rate_per_minute=60, max_evidence_bytes=evidence * 1024 * 1024,
            max_data_bytes=20 * 1024 * 1024,
        ))
    current_domain = domain(
        domain_id="owned-completion-domain",
        facts=tuple(FactDefinitionV1(f, ScalarType.BOOLEAN, ()) for f in sorted(("authorized", *completed))),
        operators=tuple(sorted(operators, key=lambda o: o.operator_id)),
        objective=PlanningObjectiveV1(
            objective_id="complete-owned-profiles",
            required_predicates=tuple(predicate(f, ScalarType.BOOLEAN, True) for f in sorted(completed)),
            forbidden_predicates=(predicate("authorized", ScalarType.BOOLEAN, False),),
        ),
    )
    human = authority(capability_ids=tuple(sorted(o.capability.capability_id for o in operators)),
                      objective_ids=(current_domain.objective.objective_id,),
                      success_condition_ids=tuple(sorted(completed)))
    human = replace(human, bounds=replace(human.bounds, max_duration_seconds=180, max_requests=60,
        max_rate_per_minute=60, max_concurrency=1, max_evidence_bytes=14 * 1024 * 1024,
        max_data_bytes=60 * 1024 * 1024, max_width=1, max_depth=2, max_nodes=2, max_frontier=1))
    initial = WorldStateV1(tuple(FactValueV1(f, scalar(ScalarType.BOOLEAN, f == "authorized"))
                                 for f in sorted(("authorized", *completed))))
    return current_domain, human, initial, completed


def owned_parent_child():
    current_domain, human, initial, completed = owned_planning_material()
    try:
        closed = importlib.import_module("redagent_platform.campaign_service.planning.owned_sequential")
    except ModuleNotFoundError:
        pytest.fail("Closed owned-sequential planning profile is missing; generic rate summation cannot form this parent")
    planned = closed.plan_owned_sequential_attack_path(current_domain, human, initial, search_limits())
    assert planned.revision is not None, planned.receipt
    parent = planned.revision
    observed = FactValueV1(completed[0], scalar(ScalarType.BOOLEAN, True))
    child_state = WorldStateV1(tuple(observed if v.fact_id == observed.fact_id else v for v in initial.values))
    planned_child = closed.plan_owned_sequential_attack_path(current_domain, human, child_state, search_limits())
    assert planned_child.revision is not None
    child = replace(planned_child.revision, parent_revision_id=parent.revision_id)
    assert len(parent.candidate_plan.nodes) == 2 and len(child.candidate_plan.nodes) == 1
    return current_domain, human, parent, child, observed


def _proof(**overrides):
    current_domain, _, parent, child, observed = owned_parent_child()
    values = dict(parent=parent, child=child, domain=current_domain,
                  completed_parent_node_ids=(parent.candidate_plan.nodes[0].node_id,),
                  observed_values=(observed,), observation_history_sha256="a" * 64)
    values.update(overrides)
    function = getattr(importlib.import_module("redagent_platform.campaign_service.child_replan_contracts"),
                       "prove_canonical_child_subset", None)
    assert callable(function), "Canonical child must prove a strict subset of its parent, not only human authority"
    return function(**values)


def test_child_proof_binds_strict_parent_subset_and_completion_history():
    _, _, parent, child, _ = owned_parent_child()
    proof = _proof()
    assert proof.parent_revision_sha256 == parent.revision_sha256
    assert proof.child_revision_sha256 == child.revision_sha256
    assert proof.removed_parent_node_ids == (parent.candidate_plan.nodes[0].node_id,)
    assert proof.observation_history_sha256 == "a" * 64
    assert proof.proof_sha256 == _proof().proof_sha256


@pytest.mark.parametrize("kind", ["target", "operator", "arguments", "parent", "authority", "domain", "no_shrink", "reexecute", "invented_state"])
def test_expansion_reexecution_or_invented_state_is_denied(kind):
    _, _, parent, child, _ = owned_parent_child()
    node = child.candidate_plan.nodes[0]
    if kind == "target":
        child = replace(child, candidate_plan=replace(child.candidate_plan, nodes=(replace(node, target_id="other-target"),)))
    elif kind == "operator":
        child = replace(child, candidate_plan=replace(child.candidate_plan, nodes=(replace(node, operator_id="invented-operator"),)))
    elif kind == "arguments":
        child = replace(child, candidate_plan=replace(child.candidate_plan, nodes=(replace(node, arguments=()),)))
    elif kind == "parent":
        child = replace(child, parent_revision_id="other-parent")
    elif kind == "authority":
        child = replace(child, authority_sha256="b" * 64, candidate_plan=replace(child.candidate_plan, authority_sha256="b" * 64))
    elif kind == "domain":
        child = replace(child, domain_sha256="b" * 64, candidate_plan=replace(child.candidate_plan, domain_sha256="b" * 64))
    elif kind == "no_shrink":
        child = replace(parent, revision_id="child-repeated", parent_revision_id=parent.revision_id)
    elif kind == "reexecute":
        repeated = replace(parent.candidate_plan.nodes[0], node_id=node.node_id, order=0)
        child = replace(child, candidate_plan=replace(child.candidate_plan, nodes=(repeated,)))
    else:
        new_values = tuple(replace(v, value=scalar(ScalarType.BOOLEAN, False)) if v.fact_id == "authorized" else v
                           for v in child.candidate_plan.initial_state.values)
        state = WorldStateV1(new_values)
        child = replace(child, initial_state_sha256=state.state_sha256, candidate_plan=replace(child.candidate_plan, initial_state=state))
    with pytest.raises(ValueError, match="child_subset"):
        _proof(child=child)
