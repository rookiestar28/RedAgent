from __future__ import annotations

from dataclasses import replace

import pytest

from redagent_platform.campaign_service.dag_execution import (
    DagFrontierOutcome,
    NodeExecutionFact,
    derive_dag_frontier,
)
from redagent_platform.campaign_service.dag_execution_contracts import DagNodeState
from redagent_platform.campaign_service.planning.search import plan_attack_path
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import authority, domain, world


def revision():
    result = plan_attack_path(domain(), authority(), world(), search_limits())
    assert result.revision is not None
    return result.revision


def test_frontier_selects_the_only_root_then_completes_only_after_confirmation() -> None:
    current = revision()
    pending = derive_dag_frontier(current, domain(), ())
    assert pending.outcome is DagFrontierOutcome.READY
    assert pending.ready_node_id == current.root_node_ids[0]
    assert pending.applied_node_ids == ()

    confirmed = derive_dag_frontier(
        current,
        domain(),
        (NodeExecutionFact(current.root_node_ids[0], DagNodeState.CONFIRMED),),
    )
    assert confirmed.outcome is DagFrontierOutcome.COMPLETED
    assert confirmed.ready_node_id is None
    assert confirmed.applied_node_ids == current.root_node_ids


def test_frontier_never_applies_predicted_or_ambiguous_effects() -> None:
    current = revision()
    ambiguous = derive_dag_frontier(
        current,
        domain(),
        (NodeExecutionFact(current.root_node_ids[0], DagNodeState.RECONCILIATION_REQUIRED),),
    )
    assert ambiguous.outcome is DagFrontierOutcome.RECONCILIATION_REQUIRED
    assert ambiguous.applied_node_ids == ()


def test_frontier_fails_closed_for_unadmitted_width_or_unknown_node_state() -> None:
    current = revision()
    object.__setattr__(current, "width", 2)
    with pytest.raises(ValueError, match="dag_execution_topology_unsupported"):
        derive_dag_frontier(current, domain(), ())

    current = revision()
    with pytest.raises(ValueError, match="dag_execution_node_fact_unknown"):
        derive_dag_frontier(
            current,
            domain(),
            (NodeExecutionFact("unknown-node", DagNodeState.CONFIRMED),),
        )


def test_frontier_rejects_domain_substitution() -> None:
    current = revision()
    substituted = replace(domain(), domain_id="other-domain")
    with pytest.raises(ValueError, match="dag_execution_domain_mismatch"):
        derive_dag_frontier(current, substituted, ())
