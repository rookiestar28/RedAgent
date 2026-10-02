from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import importlib

import pytest

from redagent_platform.campaign_service.admission import authority_budget, calculate_plan_budget
from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1
from redagent_platform.campaign_service.planning.owned_sequential import (
    OWNED_SEQUENTIAL_VALIDATOR_SHA256, OWNED_SEQUENTIAL_VALIDATOR_VERSION,
    validate_owned_sequential_candidate_plan,
)
from redagent_platform.campaign_service.replanning_contracts import ReplanOutcome
from redagent_platform.campaign_service.trusted_observations import (
    _TRUSTED_OBSERVATION_TOKEN, TrustedObservationV1, evaluate_observation_history,
)
from tests.unit.test_campaign_planning_contracts import NOW
from tests.unit.test_campaign_replanning import _lifecycle, _parent_receipt, _request
from tests.unit.test_child_replan_subset import owned_parent_child
from tests.unit.test_trusted_observations import _candidate


def _inputs():
    current_domain, human, parent, _, fact = owned_parent_child()
    certificate = validate_owned_sequential_candidate_plan(
        parent.candidate_plan, current_domain, human,
        limits=ValidationLimitsV1(2, 1, 32), validated_at=NOW,
    )
    assert certificate.admissible
    receipt = replace(
        _parent_receipt(), authority_sha256=parent.authority_sha256,
        domain_sha256=parent.domain_sha256, plan_sha256=parent.candidate_plan.plan_sha256,
        reserved_budget=calculate_plan_budget(parent, current_domain),
        validator_version=certificate.validator_version, validator_sha256=certificate.validator_sha256,
        certificate_sha256=certificate.certificate_sha256,
    )
    candidate = _candidate(
        authority_sha256=human.authority_sha256, fact_id=fact.fact_id, value=fact.value,
        lifecycle_epoch=human.lifecycle_epoch, policy_revocation_epoch=human.policy_revocation_epoch,
        roe_revocation_epoch=human.roe_revocation_epoch, kill_switch_epoch=human.kill_switch_epoch,
        observed_at=NOW, received_at=NOW + timedelta(seconds=1),
    )
    # This isolated pure-helper fixture supplies trusted history only; physical provenance is tested at its owner.
    observation = TrustedObservationV1(
        schema_version="redagent.trusted-observation/v1", candidate=candidate,
        source_record_id="effect-parent", source_execution_run_id="run-parent",
        source_node_id=parent.candidate_plan.nodes[0].node_id, provenance_sha256="a" * 64,
        promoted_at=NOW + timedelta(seconds=2), _validation_token=_TRUSTED_OBSERVATION_TOKEN,
    )
    request = _request(
        parent_revision_id=parent.revision_id, parent_revision_sha256=parent.revision_sha256,
        parent_admission_receipt_id=receipt.receipt_id, parent_admission_receipt_sha256=receipt.receipt_sha256,
        observation_history=evaluate_observation_history((observation,)),
    )
    return dict(request=request, parent_revision=parent, parent_admission_receipt=receipt,
                authority=human, lifecycle=_lifecycle(authority_sha256=human.authority_sha256),
                domain=current_domain, residual_budget=authority_budget(human),
                now=NOW + timedelta(seconds=3))


def _prepare(values):
    function = getattr(importlib.import_module("redagent_platform.campaign_service.replanning"),
                       "prepare_owned_bounded_replan", None)
    assert callable(function), "Closed child preparation must use its exact validator and semantic transition bounds"
    return function(**values)


def test_closed_child_preparation_uses_exact_profile_and_preserves_parent_lineage():
    values = _inputs()
    result = _prepare(values)
    assert result.outcome is ReplanOutcome.CHILD_PROPOSED, result.reason_code
    proposal = result.proposal
    assert proposal is not None and len(proposal.child_revision.candidate_plan.nodes) == 1
    assert proposal.child_revision.parent_revision_id == values["parent_revision"].revision_id
    assert proposal.replan_sequence == 1
    assert proposal.validation_certificate.validator_version == OWNED_SEQUENTIAL_VALIDATOR_VERSION
    assert proposal.validation_certificate.validator_sha256 == OWNED_SEQUENTIAL_VALIDATOR_SHA256
    assert proposal.invalidated_parent_node_ids == (values["parent_revision"].candidate_plan.nodes[0].node_id,)
    assert _prepare(values).proposal.proposal_sha256 == proposal.proposal_sha256


@pytest.mark.parametrize("kind", ["exhausted", "expired", "future", "residual", "parent_profile", "receipt_profile", "wrong_source"])
def test_closed_child_preparation_denies_exhaustion_stale_truth_and_expansion(kind):
    values = _inputs()
    if kind == "exhausted":
        values["request"] = replace(values["request"], consumed_replans=1)
    elif kind == "expired":
        values["now"] = NOW + timedelta(minutes=2)
    elif kind == "future":
        values["now"] = NOW + timedelta(seconds=1)
    elif kind == "residual":
        values["residual_budget"] = replace(values["residual_budget"], requests=0)
    elif kind == "parent_profile":
        values["parent_revision"] = replace(values["parent_revision"], planner_sha256="b" * 64)
    elif kind == "receipt_profile":
        values["parent_admission_receipt"] = replace(values["parent_admission_receipt"], validator_sha256="b" * 64)
    else:
        observation = values["request"].observation_history.trusted_observations[0]
        altered = replace(observation, source_node_id="other-node", _validation_token=_TRUSTED_OBSERVATION_TOKEN)
        values["request"] = replace(values["request"], observation_history=evaluate_observation_history((altered,)))
    result = _prepare(values)
    assert result.outcome is not ReplanOutcome.CHILD_PROPOSED and result.proposal is None
