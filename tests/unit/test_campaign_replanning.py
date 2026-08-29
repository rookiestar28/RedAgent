from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import inspect

import pytest

from redagent_platform.campaign_service.admission import authority_budget, calculate_plan_budget
from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.admission_contracts import (
    PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
    AdmissionOutcome,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
)
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.replanning import (
    bind_replan_admission,
    derive_replan_search_limits,
    prepare_bounded_replan,
)
from redagent_platform.campaign_service.replanning_contracts import (
    AcceptedBoundedReplanV1,
    REPLAN_REQUEST_SCHEMA_VERSION,
    ReplanFrontierDisposition,
    ReplanOutcome,
    ReplanRequestV1,
    ACCEPTED_REPLAN_SCHEMA_VERSION,
    classify_replan_frontier,
)
from redagent_platform.campaign_service.trusted_observations import evaluate_observation_history
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import NOW, authority, domain, world
from tests.unit.test_trusted_observations import _candidate, _policy, _trusted


def _parent():
    result = plan_attack_path(domain(), authority(), world(), search_limits())
    assert result.revision is not None
    return result.revision


def _lifecycle(**overrides: object) -> CampaignAuthorityLifecycleV2:
    current = authority()
    values: dict[str, object] = {
        "schema_version": "redagent.campaign-authority-lifecycle/v2",
        "authority_sha256": current.authority_sha256,
        "tenant_id": current.tenant_id,
        "engagement_id": current.engagement_id,
        "state": CampaignAuthorityLifecycleState.ACTIVE,
        "lifecycle_epoch": current.lifecycle_epoch,
        "policy_revocation_epoch": current.policy_revocation_epoch,
        "roe_revocation_epoch": current.roe_revocation_epoch,
        "kill_switch_epoch": current.kill_switch_epoch,
        "observed_at": NOW,
        "valid_until": NOW + timedelta(seconds=45),
        "revoked_at": None,
        "reason_code": None,
    }
    values.update(overrides)
    return CampaignAuthorityLifecycleV2(**values)  # type: ignore[arg-type]


def _parent_receipt(parent=None, **overrides: object) -> PlanAdmissionReceiptV1:
    parent = parent or _parent()
    values: dict[str, object] = {
        "schema_version": PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
        "receipt_id": "admission-parent",
        "tenant_id": "tenant-a",
        "campaign_id": "campaign-a",
        "engagement_id": "engagement-a",
        "signed_authority_sha256": "5" * 64,
        "authority_sha256": parent.authority_sha256,
        "domain_sha256": parent.domain_sha256,
        "plan_sha256": parent.candidate_plan.plan_sha256,
        "certificate_sha256": "6" * 64,
        "validator_version": "validator-v1",
        "validator_sha256": "7" * 64,
        "subset_proof_sha256": "8" * 64,
        "policy_decision_id": "decision-parent",
        "policy_input_sha256": "9" * 64,
        "policy_bundle_revision": "policy-a",
        "policy_bundle_sha256": "a" * 64,
        "pre_residual_budget_sha256": "b" * 64,
        "post_residual_budget_sha256": "c" * 64,
        "reserved_budget": calculate_plan_budget(parent, domain()),
        "reservation_id": "reservation-parent",
        "idempotency_key": "admit-parent",
        "request_sha256": "d" * 64,
        "lifecycle_epoch": 1,
        "policy_revocation_epoch": 1,
        "roe_revocation_epoch": 1,
        "kill_switch_epoch": 1,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(seconds=30),
        "outcome": AdmissionOutcome.ADMITTED,
        "denial_stage": None,
        "reason_code": "admitted",
        "audit_id": "audit-parent",
        "outbox_id": "outbox-parent",
    }
    values.update(overrides)
    return PlanAdmissionReceiptV1(**values)  # type: ignore[arg-type]


def _request(**overrides: object) -> ReplanRequestV1:
    parent = _parent()
    parent_receipt = _parent_receipt(parent)
    observed_candidate = replace(
            _candidate(),
            authority_sha256=authority().authority_sha256,
            lifecycle_epoch=authority().lifecycle_epoch,
            policy_revocation_epoch=authority().policy_revocation_epoch,
            roe_revocation_epoch=authority().roe_revocation_epoch,
            kill_switch_epoch=authority().kill_switch_epoch,
        )
    observed = _trusted(
        observed_candidate,
        _policy(
            authority_sha256=authority().authority_sha256,
            lifecycle_epoch=authority().lifecycle_epoch,
            policy_revocation_epoch=authority().policy_revocation_epoch,
            roe_revocation_epoch=authority().roe_revocation_epoch,
            kill_switch_epoch=authority().kill_switch_epoch,
        ),
    )
    values: dict[str, object] = {
        "schema_version": REPLAN_REQUEST_SCHEMA_VERSION,
        "request_id": "replan-request-a",
        "tenant_id": "tenant-a",
        "campaign_id": "campaign-a",
        "engagement_id": "engagement-a",
        "parent_revision_id": parent.revision_id,
        "parent_revision_sha256": parent.revision_sha256,
        "parent_admission_receipt_id": parent_receipt.receipt_id,
        "parent_admission_receipt_sha256": parent_receipt.receipt_sha256,
        "observation_history": evaluate_observation_history((observed,)),
        "consumed_replans": 0,
        "requested_at": NOW + timedelta(seconds=2),
    }
    values.update(overrides)
    return ReplanRequestV1(**values)  # type: ignore[arg-type]


def test_replan_is_parent_linked_deterministic_and_residual_bound() -> None:
    parent = _parent()
    current_authority = authority()
    residual = authority_budget(current_authority)
    first = prepare_bounded_replan(
        request=_request(),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=current_authority,
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=residual,
        now=NOW + timedelta(seconds=3),
    )
    second = prepare_bounded_replan(
        request=_request(),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=current_authority,
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=residual,
        now=NOW + timedelta(seconds=3),
    )
    storm_replay = prepare_bounded_replan(
        request=_request(request_id="replan-request-storm-replay"),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=current_authority,
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=residual,
        now=NOW + timedelta(seconds=3),
    )
    assert first.outcome is ReplanOutcome.CHILD_PROPOSED
    assert first.proposal is not None
    assert first.result_sha256 == second.result_sha256
    assert storm_replay.proposal is not None
    assert (
        storm_replay.proposal.child_revision.revision_sha256
        == first.proposal.child_revision.revision_sha256
    )
    assert first.proposal.child_revision.parent_revision_id == parent.revision_id
    assert first.proposal.parent_revision_sha256 == parent.revision_sha256
    assert first.proposal.campaign_id == "campaign-a"
    assert first.proposal.engagement_id == "engagement-a"
    assert first.proposal.parent_plan_sha256 == parent.candidate_plan.plan_sha256
    assert first.proposal.parent_authority_sha256 == parent.authority_sha256
    assert first.proposal.parent_domain_sha256 == parent.domain_sha256
    assert (
        first.proposal.search_receipt.limits_sha256
        == derive_replan_search_limits(current_authority).limits_sha256
    )
    assert first.proposal.observation_history_sha256 == _request().observation_history.history_sha256
    assert first.proposal.validation_certificate.admissible is True
    assert first.proposal.subset_proof.admissible is True
    assert first.proposal.subset_proof.checked_dimensions == (
        "tenant",
        "engagement",
        "objective",
        "success_conditions",
        "targets",
        "capabilities",
        "effects",
        "data_access",
        "credentials",
        "environment",
        "graph_bounds",
        "resource_bounds",
        "operator_arguments",
        "time_window",
    )
    assert first.proposal.planned_budget.fits_within(residual)
    assert first.proposal.child_revision.initial_state_sha256 == parent.initial_state_sha256
    assert first.proposal.child_revision.revision_sha256 != parent.revision_sha256
    assert first.proposal.parent_admission_receipt_id == "admission-parent"
    with pytest.raises(FrozenInstanceError):
        first.proposal.parent_revision_sha256 = "f" * 64  # type: ignore[misc]


def test_replan_limit_lifecycle_drift_and_residual_exhaustion_fail_closed() -> None:
    parent = _parent()
    current_authority = authority()
    exhausted = prepare_bounded_replan(
        request=_request(consumed_replans=current_authority.bounds.max_replans),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=current_authority,
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=authority_budget(current_authority),
        now=NOW + timedelta(seconds=3),
    )
    assert exhausted.outcome is ReplanOutcome.REPLAN_LIMIT_EXHAUSTED

    revoked = prepare_bounded_replan(
        request=_request(),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=current_authority,
        lifecycle=_lifecycle(state=CampaignAuthorityLifecycleState.REVOKED, revoked_at=NOW, reason_code="owner_revoked"),
        domain=domain(),
        residual_budget=authority_budget(current_authority),
        now=NOW + timedelta(seconds=3),
    )
    assert revoked.outcome is ReplanOutcome.MANUAL_REVIEW_REQUIRED
    assert revoked.reason_code == "campaign_authority_not_active"

    zero = CampaignBudgetVectorV1(0, 0, 0, 0, 0, 0, 0, 0)
    budget = prepare_bounded_replan(
        request=_request(),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=current_authority,
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=zero,
        now=NOW + timedelta(seconds=3),
    )
    assert budget.outcome is ReplanOutcome.EXPANSION_REQUIRED
    assert budget.reason_code == "replan_residual_budget_exceeded"


def test_replan_requires_exact_parent_admission_and_current_observation_freshness() -> None:
    parent = _parent()
    current_authority = authority()
    request = _request()
    wrong_parent_receipt = replace(_parent_receipt(parent), receipt_id="admission-sibling")
    swapped = prepare_bounded_replan(
        request=request,
        parent_revision=parent,
        parent_admission_receipt=wrong_parent_receipt,
        authority=current_authority,
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=authority_budget(current_authority),
        now=NOW + timedelta(seconds=3),
    )
    assert swapped.outcome is ReplanOutcome.MANUAL_REVIEW_REQUIRED
    assert swapped.reason_code == "replan_parent_admission_binding_mismatch"

    expiring_candidate = replace(
        _candidate(),
        authority_sha256=current_authority.authority_sha256,
        lifecycle_epoch=current_authority.lifecycle_epoch,
        policy_revocation_epoch=current_authority.policy_revocation_epoch,
        roe_revocation_epoch=current_authority.roe_revocation_epoch,
        kill_switch_epoch=current_authority.kill_switch_epoch,
        expires_at=NOW + timedelta(seconds=5),
    )
    expiring = _trusted(
        expiring_candidate,
        _policy(
            authority_sha256=current_authority.authority_sha256,
            lifecycle_epoch=current_authority.lifecycle_epoch,
            policy_revocation_epoch=current_authority.policy_revocation_epoch,
            roe_revocation_epoch=current_authority.roe_revocation_epoch,
            kill_switch_epoch=current_authority.kill_switch_epoch,
        ),
    )
    expired = prepare_bounded_replan(
        request=_request(observation_history=evaluate_observation_history((expiring,))),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=current_authority,
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=authority_budget(current_authority),
        now=NOW + timedelta(seconds=6),
    )
    assert expired.outcome is ReplanOutcome.MANUAL_REVIEW_REQUIRED
    assert expired.reason_code == "replan_observation_expired"


@pytest.mark.parametrize(
    ("state", "node_state", "stop", "expected"),
    (
        (DagRunState.RUNNING, DagNodeState.DISPATCHING, False, ReplanFrontierDisposition.RECONCILIATION_REQUIRED),
        (DagRunState.RUNNING, DagNodeState.CONFIRMED, False, ReplanFrontierDisposition.STOP_PARENT),
        (DagRunState.STOPPING, DagNodeState.CONFIRMED, True, ReplanFrontierDisposition.WAIT_FOR_CONTAINMENT),
        (DagRunState.CONTAINED, DagNodeState.CONTAINED, True, ReplanFrontierDisposition.CHILD_START_ALLOWED),
        (DagRunState.FAILED_BEFORE_IO, DagNodeState.NOT_APPLIED, False, ReplanFrontierDisposition.CHILD_START_ALLOWED),
        (DagRunState.FAILED, DagNodeState.FAILED, False, ReplanFrontierDisposition.MANUAL_REVIEW_REQUIRED),
        (DagRunState.MANUAL_REVIEW_REQUIRED, DagNodeState.MANUAL_REVIEW_REQUIRED, True, ReplanFrontierDisposition.MANUAL_REVIEW_REQUIRED),
    ),
)
def test_frontier_switch_never_mutates_or_bypasses_in_flight_parent(
    state: DagRunState,
    node_state: DagNodeState,
    stop: bool,
    expected: ReplanFrontierDisposition,
) -> None:
    snapshot = DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id="execution-parent",
        workflow_request_sha256="7" * 64,
        state=state,
        revision=2,
        transition_count=2,
        current_node_id="node-a",
        current_node_state=node_state,
        stop_requested=stop,
        terminal_reason="owner_stop" if stop else None,
    )
    assert classify_replan_frontier(snapshot) is expected


def test_parentless_initial_revision_remains_valid_but_child_requires_direct_parent_binding() -> None:
    parent = _parent()
    assert parent.parent_revision_id is None
    with pytest.raises(ValueError, match="attack_path_dag_parent_invalid"):
        replace(parent, parent_revision_id="")


def test_planned_budget_is_not_reset_to_original_authority() -> None:
    current_domain = domain()
    parent = _parent()
    planned = calculate_plan_budget(parent, current_domain)
    residual = authority_budget(authority()).subtract(planned)
    result = prepare_bounded_replan(
        request=_request(),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=authority(),
        lifecycle=_lifecycle(),
        domain=current_domain,
        residual_budget=residual,
        now=NOW + timedelta(seconds=3),
    )
    assert result.outcome in {ReplanOutcome.CHILD_PROPOSED, ReplanOutcome.EXPANSION_REQUIRED}
    if result.proposal is not None:
        assert result.proposal.planned_budget.fits_within(residual)


@pytest.mark.parametrize(
    "dimension",
    (
        "duration_seconds",
        "requests",
        "rate_per_minute",
        "concurrency",
        "risk_micropoints",
        "cost_microunits",
        "evidence_bytes",
        "data_bytes",
    ),
)
def test_each_residual_budget_dimension_fails_closed_without_reset(dimension: str) -> None:
    parent = _parent()
    planned = calculate_plan_budget(parent, domain())
    residual = replace(planned, **{dimension: getattr(planned, dimension) - 1})
    result = prepare_bounded_replan(
        request=_request(),
        parent_revision=parent,
        parent_admission_receipt=_parent_receipt(parent),
        authority=authority(),
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=residual,
        now=NOW + timedelta(seconds=3),
    )
    assert result.outcome is ReplanOutcome.EXPANSION_REQUIRED
    assert result.reason_code == "replan_residual_budget_exceeded"


def test_child_requires_new_exact_r158_admission_and_parent_receipt_cannot_transfer() -> None:
    result = prepare_bounded_replan(
        request=_request(),
        parent_revision=_parent(),
        parent_admission_receipt=_parent_receipt(),
        authority=authority(),
        lifecycle=_lifecycle(),
        domain=domain(),
        residual_budget=authority_budget(authority()),
        now=NOW + timedelta(seconds=3),
    )
    assert result.proposal is not None
    proposal = result.proposal
    receipt = PlanAdmissionReceiptV1(
        schema_version=PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
        receipt_id="admission-child",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        engagement_id="engagement-a",
        signed_authority_sha256="a" * 64,
        authority_sha256=proposal.child_revision.authority_sha256,
        domain_sha256=proposal.child_revision.domain_sha256,
        plan_sha256=proposal.child_revision.candidate_plan.plan_sha256,
        certificate_sha256=proposal.validation_certificate.certificate_sha256,
        validator_version=proposal.validation_certificate.validator_version,
        validator_sha256=proposal.validation_certificate.validator_sha256,
        subset_proof_sha256=proposal.subset_proof.proof_sha256,
        policy_decision_id="decision-child",
        policy_input_sha256="b" * 64,
        policy_bundle_revision="policy-a",
        policy_bundle_sha256="c" * 64,
        pre_residual_budget_sha256=proposal.residual_budget.budget_sha256,
        post_residual_budget_sha256="d" * 64,
        reserved_budget=proposal.planned_budget,
        reservation_id="reservation-child",
        idempotency_key="admit-child",
        request_sha256="e" * 64,
        lifecycle_epoch=1,
        policy_revocation_epoch=1,
        roe_revocation_epoch=1,
        kill_switch_epoch=1,
        issued_at=NOW + timedelta(seconds=4),
        expires_at=NOW + timedelta(seconds=30),
        outcome=AdmissionOutcome.ADMITTED,
        denial_stage=None,
        reason_code="admitted",
        audit_id="audit-child",
        outbox_id="outbox-child",
    )
    accepted = bind_replan_admission(
        proposal=proposal,
        admission_receipt=receipt,
        now=NOW + timedelta(seconds=5),
    )
    assert accepted.schema_version == ACCEPTED_REPLAN_SCHEMA_VERSION
    assert accepted.child_admission_receipt_sha256 == receipt.receipt_sha256
    with pytest.raises(ValueError, match="accepted_replan_admission_binding_required"):
        AcceptedBoundedReplanV1(
            schema_version=ACCEPTED_REPLAN_SCHEMA_VERSION,
            proposal=proposal,
            child_admission_receipt_id=receipt.receipt_id,
            child_admission_receipt_sha256=receipt.receipt_sha256,
            reservation_id=receipt.reservation_id or "reservation-child",
        )
    with pytest.raises(ValueError, match="replan_parent_admission_transfer_forbidden"):
        bind_replan_admission(
            proposal=proposal,
            admission_receipt=replace(receipt, receipt_id=proposal.parent_admission_receipt_id),
            now=NOW + timedelta(seconds=5),
        )
    with pytest.raises(ValueError, match="replan_child_admission_binding_mismatch"):
        bind_replan_admission(
            proposal=proposal,
            admission_receipt=replace(receipt, plan_sha256="f" * 64),
            now=NOW + timedelta(seconds=5),
        )

    with pytest.raises(ValueError, match="replan_child_admission_binding_mismatch"):
        bind_replan_admission(
            proposal=proposal,
            admission_receipt=replace(receipt, campaign_id="campaign-swapped"),
            now=NOW + timedelta(seconds=5),
        )
    with pytest.raises(ValueError, match="replan_child_admission_binding_mismatch"):
        bind_replan_admission(
            proposal=proposal,
            admission_receipt=replace(receipt, engagement_id="engagement-swapped"),
            now=NOW + timedelta(seconds=5),
        )
    with pytest.raises(ValueError, match="replan_child_admission_binding_mismatch"):
        bind_replan_admission(
            proposal=proposal,
            admission_receipt=receipt,
            now=receipt.expires_at,
        )
    with pytest.raises(ValueError, match="replan_child_admission_binding_mismatch"):
        bind_replan_admission(
            proposal=proposal,
            admission_receipt=receipt,
            now=receipt.issued_at - timedelta(microseconds=1),
        )


def test_replan_search_limits_are_server_owned_not_a_caller_parameter() -> None:
    assert "search_limits" not in inspect.signature(prepare_bounded_replan).parameters
