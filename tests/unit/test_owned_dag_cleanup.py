from copy import deepcopy
from dataclasses import asdict
import importlib

import pytest

from redagent_platform.campaign_service.application_repository import _json_payload
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from tests.unit.test_child_replan_subset import owned_parent_child


def _frontier():
    domain, _, parent, _, _ = owned_parent_child()
    payload = _json_payload({"revision": asdict(parent), "domain": asdict(domain)})
    run = {"id": "owned-parent", "campaign_id": "owned-campaign", "tenant_id": parent.tenant_id,
           "input_payload": payload, "input_sha256": canonical_planning_sha256(payload),
           "run_state": "running", "active_concurrency": 0, "plan_sha256": parent.candidate_plan.plan_sha256}
    nodes = tuple({"node_id": node.node_id, "operator_id": node.operator_id, "target_id": node.target_id,
                   "node_sha256": canonical_planning_sha256(node), "arguments_sha256": canonical_planning_sha256(node.arguments),
                   "node_state": "confirmed" if index == 0 else "pending"}
                  for index, node in enumerate(parent.candidate_plan.nodes))
    effect = {"node_id": nodes[0]["node_id"], "effect_state": "confirmed"}
    return run, nodes, (effect,)


def _validate(*args):
    owner = importlib.import_module("redagent_platform.campaign_service.owned_dag_cleanup")
    return owner.validate_owned_stop_frontier(*args)


def test_only_completed_first_node_and_never_dispatched_second_node_are_a_stop_frontier():
    run, nodes, effects = _frontier()
    assert _validate(run, nodes, effects) == effects[0]


@pytest.mark.parametrize("mutation", ["inflight", "terminal", "input", "plan", "node", "second_effect", "unknown", "second_running"])
def test_owned_stop_frontier_denies_ambiguous_or_changed_owners(mutation):
    run, nodes, effects = deepcopy(_frontier())
    if mutation == "inflight":
        run["active_concurrency"] = 1
    elif mutation == "terminal":
        run["run_state"] = "manual_review_required"
    elif mutation == "input":
        run["input_sha256"] = "a" * 64
    elif mutation == "plan":
        run["plan_sha256"] = "a" * 64
    elif mutation == "node":
        nodes[0]["node_sha256"] = "a" * 64
    elif mutation == "second_effect":
        effects += ({"node_id": nodes[1]["node_id"], "effect_state": "confirmed"},)
    elif mutation == "unknown":
        effects[0]["effect_state"] = "unknown"
    elif mutation == "second_running":
        nodes[1]["node_state"] = "dispatching"
    with pytest.raises(ValueError, match="owned_stop"):
        _validate(run, nodes, effects)
