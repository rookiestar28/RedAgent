from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pytest

from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
    DagExecutionMode,
)
from redagent_platform.campaign_service.dag_execution_service import DagExecutionStartService
from redagent_platform.campaign_service.planning.contracts import (
    FactValueV1,
    ScalarType,
    WorldStateV1,
)
from redagent_platform.campaign_service.execution import (
    EffectReceiptV1,
    NodeObservedV1,
    ReconciliationState,
)
from redagent_platform.campaign_service.contracts import canonical_sha256
from redagent_platform.campaign_service.detection_feedback import (
    correlate_detection_observations,
    promote_detection_observation_by_correlation,
)
from redagent_platform.campaign_service.trusted_observations import (
    DAG_RESULT_PRODUCER_V1,
    DETECTION_CORRELATION_PRODUCER_V1,
    OBSERVATION_CANDIDATE_SCHEMA_VERSION,
    OBSERVATION_POLICY_SCHEMA_VERSION,
    PREDICTED_STATE_SCHEMA_VERSION,
    TRUSTED_OBSERVATION_PRODUCER_REGISTRY_SHA256,
    ObservationCandidateV1,
    ObservationProducerIdentityV1,
    ObservationProducerKind,
    ObservationPromotionOutcome,
    ObservationPromotionPolicyV1,
    PredictedStateV1,
    VerifiedObservationEvidenceV1,
    evaluate_observation_history,
    promote_observation,
    verify_dag_node_observation_evidence,
    verify_detection_correlation_evidence,
)
from tests.unit.test_detection_feedback import NOW as DETECTION_NOW
from tests.unit.test_detection_feedback import _confirmed, _observation, _ref
from tests.unit.test_campaign_dag_execution_start import Store as DagStartStore
from tests.unit.test_campaign_dag_execution_start import _request as dag_start_request
from tests.unit.test_campaign_planning_contracts import scalar


NOW = datetime(2026, 8, 29, 8, 0, tzinfo=timezone.utc)


def _effect_receipt(
    state: ReconciliationState = ReconciliationState.NOT_APPLIED,
) -> EffectReceiptV1:
    confirmed = state is ReconciliationState.CONFIRMED
    return EffectReceiptV1(
        schema_version="redagent.r123-effect-receipt/v1",
        effect_id="effect-observation-a",
        effect_intent_sha256="a" * 64,
        envelope_sha256="b" * 64,
        dispatch_attempt=1,
        dispatch_generation=1,
        runner_id="runner-a",
        workload_identity="spiffe://redagent.test/runner/runner-a",
        request_sha256="c" * 64,
        started_at=NOW - timedelta(seconds=8),
        completed_at=NOW - timedelta(seconds=6),
        adapter_accepted=confirmed,
        external_status="succeeded" if confirmed else "not_applied",
        external_receipt_id="external-observation-a",
        evidence_ids=("evidence-observation-a",),
        cleanup_receipt_id="cleanup-observation-a",
        output_complete=True,
        external_contact_count=0,
        reconciliation_state=state,
        reconciliation_evidence_ids=("reconciliation-observation-a",),
        redispatch_permitted=not confirmed,
        failure_code=None,
    )


def _node_observed(receipt: EffectReceiptV1) -> NodeObservedV1:
    return NodeObservedV1(
        schema_version="redagent.r123-node-observed/v1",
        effect_state=receipt.reconciliation_state.value,
        attempt_count=1,
        next_retry_at=None,
        receipt_state=receipt.reconciliation_state,
        effect_receipt_sha256=receipt.receipt_sha256,
        evidence_complete=True,
        report_safe_evidence_complete=True,
        finding_or_coverage_complete=True,
        retest_complete=True,
        secret_revocation_complete=True,
        containment_complete=True,
        cleanup_complete=True,
        reconciliation_complete=True,
        residual_risk_complete=True,
        infrastructure_available=True,
    )


@lru_cache(maxsize=1)
def _material():
    store = DagStartStore()
    asyncio.run(
        DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, store).start(
            dag_start_request(), now=NOW + timedelta(seconds=40)
        )
    )
    return store.materials[0][0]


def _material_for(candidate: ObservationCandidateV1):
    base = _material()
    workflow_input = replace(base.workflow_input, tenant_id=candidate.tenant_id)
    node = replace(base.nodes[0], target_id=candidate.target_id)
    return replace(
        base,
        tenant_id=candidate.tenant_id,
        campaign_id=candidate.campaign_id,
        engagement_id=candidate.engagement_id,
        authority_sha256=candidate.authority_sha256,
        lifecycle_epoch=candidate.lifecycle_epoch,
        policy_revocation_epoch=candidate.policy_revocation_epoch,
        roe_revocation_epoch=candidate.roe_revocation_epoch,
        kill_switch_epoch=candidate.kill_switch_epoch,
        workflow_input=workflow_input,
        workflow_request_sha256=dag_workflow_request_sha256(workflow_input),
        nodes=(node,),
    )


def _candidate(**overrides: object) -> ObservationCandidateV1:
    values: dict[str, object] = {
        "schema_version": OBSERVATION_CANDIDATE_SCHEMA_VERSION,
        "observation_id": "observation-a",
        "tenant_id": "tenant-a",
        "campaign_id": "campaign-a",
        "engagement_id": "engagement-a",
        "target_id": "target-a",
        "authority_sha256": "1" * 64,
        "lifecycle_epoch": 1,
        "policy_revocation_epoch": 2,
        "roe_revocation_epoch": 3,
        "kill_switch_epoch": 4,
        "fact_id": "posture-collected",
        "value": scalar(ScalarType.BOOLEAN, False),
        "producer": DAG_RESULT_PRODUCER_V1,
        "source_result_sha256": _effect_receipt().receipt_sha256,
        "evidence_sha256": _effect_receipt().receipt_sha256,
        "observed_at": NOW - timedelta(seconds=5),
        "received_at": NOW - timedelta(seconds=4),
        "expires_at": NOW + timedelta(minutes=1),
    }
    values.update(overrides)
    return ObservationCandidateV1(**values)  # type: ignore[arg-type]


def _request() -> DagWorkflowInputV1:
    return _material().workflow_input


def _snapshot(request: DagWorkflowInputV1 | None = None, **overrides: object) -> DagExecutionSnapshotV1:
    request = request or _request()
    values: dict[str, object] = {
        "schema_version": DAG_EXECUTION_SCHEMA_VERSION,
        "execution_run_id": request.execution_run_id,
        "workflow_request_sha256": dag_workflow_request_sha256(request),
        "state": DagRunState.RUNNING,
        "revision": 4,
        "transition_count": 3,
        "current_node_id": _material().nodes[0].node_id,
        "current_node_state": DagNodeState.CONFIRMED,
        "stop_requested": False,
        "terminal_reason": None,
    }
    values.update(overrides)
    return DagExecutionSnapshotV1(**values)  # type: ignore[arg-type]


def _evidence(candidate: ObservationCandidateV1 | None = None) -> VerifiedObservationEvidenceV1:
    candidate = candidate or _candidate()
    material = _material_for(candidate)
    source = dag_start_request()
    state = (
        ReconciliationState.CONFIRMED
        if candidate.value == scalar(ScalarType.BOOLEAN, True)
        else ReconciliationState.NOT_APPLIED
    )
    receipt = _effect_receipt(state)
    return verify_dag_node_observation_evidence(
        candidate=candidate,
        request=material.workflow_input,
        snapshot=_snapshot(
            material.workflow_input,
            current_node_id=material.nodes[0].node_id,
            current_node_state=(
                DagNodeState.CONFIRMED
                if state is ReconciliationState.CONFIRMED
                else DagNodeState.NOT_APPLIED
            ),
        ),
        execution_material=material,
        domain=source.domain,
        revision=source.revision,
        observed=_node_observed(receipt),
        effect_receipt=receipt,
        node_id=material.nodes[0].node_id,
        verified_at=max(NOW - timedelta(seconds=1), candidate.received_at),
    )


def _policy(**overrides: object) -> ObservationPromotionPolicyV1:
    values: dict[str, object] = {
        "schema_version": OBSERVATION_POLICY_SCHEMA_VERSION,
        "tenant_id": "tenant-a",
        "campaign_id": "campaign-a",
        "engagement_id": "engagement-a",
        "authority_sha256": "1" * 64,
        "target_ids": ("target-a",),
        "producer_registry_sha256": TRUSTED_OBSERVATION_PRODUCER_REGISTRY_SHA256,
        "lifecycle_epoch": 1,
        "policy_revocation_epoch": 2,
        "roe_revocation_epoch": 3,
        "kill_switch_epoch": 4,
        "max_age_seconds": 30,
    }
    values.update(overrides)
    return ObservationPromotionPolicyV1(**values)  # type: ignore[arg-type]


def _trusted(
    candidate: ObservationCandidateV1 | None = None,
    policy: ObservationPromotionPolicyV1 | None = None,
):
    candidate = candidate or _candidate()
    decision = promote_observation(candidate, _evidence(candidate), policy or _policy(), now=NOW)
    assert decision.outcome is ObservationPromotionOutcome.TRUSTED
    assert decision.trusted_observation is not None
    return decision.trusted_observation


def test_predicted_state_and_verified_observation_evidence_are_non_interchangeable() -> None:
    predicted = PredictedStateV1(
        schema_version=PREDICTED_STATE_SCHEMA_VERSION,
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        planner_sha256="a" * 64,
        revision_sha256="b" * 64,
        world_state=WorldStateV1((FactValueV1("finding-count", scalar(ScalarType.INTEGER, 1)),)),
    )
    with pytest.raises(ValueError, match="trusted_observation_candidate_required"):
        promote_observation(predicted, _evidence(), _policy(), now=NOW)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="verified_observation_evidence_factory_required"):
        VerifiedObservationEvidenceV1(
            observation_sha256="a" * 64,
            producer=ObservationProducerIdentityV1(
                ObservationProducerKind.DAG_RUNNER_RESULT,
                "owned-loopback-runner",
                "runner-v1",
            ),
            source_result_sha256="b" * 64,
            evidence_sha256="c" * 64,
            source_record_id="source-a",
            source_execution_run_id="run-a",
            source_node_id="node-a",
            fact_id="posture-collected",
            value=scalar(ScalarType.BOOLEAN, False),
            verification_sha256="d" * 64,
            verified_at=NOW,
        )


def test_dag_evidence_requires_exact_workflow_node_result_and_confirmed_fact() -> None:
    candidate = _candidate()
    evidence = _evidence(candidate)
    assert evidence.source_result_sha256 == candidate.source_result_sha256
    source = dag_start_request()
    receipt = _effect_receipt()
    common = {
        "domain": source.domain,
        "revision": source.revision,
        "observed": _node_observed(receipt),
        "effect_receipt": receipt,
    }
    with pytest.raises(ValueError, match="observation_dag_node_not_terminal"):
        verify_dag_node_observation_evidence(
            candidate=candidate,
            request=_request(),
            snapshot=_snapshot(current_node_state=DagNodeState.DISPATCHING),
            execution_material=_material_for(candidate),
            node_id=_material().nodes[0].node_id,
            verified_at=NOW,
            **common,
        )
    with pytest.raises(ValueError, match="observation_dag_result_binding_mismatch"):
        verify_dag_node_observation_evidence(
            candidate=replace(candidate, source_result_sha256="f" * 64),
            request=_request(),
            snapshot=_snapshot(current_node_state=DagNodeState.NOT_APPLIED),
            execution_material=_material_for(candidate),
            node_id=_material().nodes[0].node_id,
            verified_at=NOW,
            **common,
        )
    with pytest.raises(ValueError, match="observation_dag_evidence_time_invalid"):
        verify_dag_node_observation_evidence(
            candidate=candidate,
            request=_request(),
            snapshot=_snapshot(current_node_state=DagNodeState.NOT_APPLIED),
            execution_material=_material_for(candidate),
            node_id=_material().nodes[0].node_id,
            verified_at=candidate.received_at - timedelta(microseconds=1),
            **common,
        )
    with pytest.raises(ValueError, match="observation_dag_scope_binding_mismatch"):
        verify_dag_node_observation_evidence(
            candidate=replace(candidate, campaign_id="campaign-b"),
            request=_request(),
            snapshot=_snapshot(current_node_state=DagNodeState.NOT_APPLIED),
            execution_material=_material(),
            node_id=_material().nodes[0].node_id,
            verified_at=NOW,
            **common,
        )


@pytest.mark.parametrize(
    ("candidate", "policy", "now", "outcome"),
    (
        (_candidate(), _policy(tenant_id="tenant-b"), NOW, ObservationPromotionOutcome.SCOPE_MISMATCH),
        (_candidate(authority_sha256="9" * 64), _policy(), NOW, ObservationPromotionOutcome.CAMPAIGN_DRIFT),
        (_candidate(observed_at=NOW - timedelta(minutes=2)), _policy(), NOW, ObservationPromotionOutcome.STALE),
        (_candidate(observed_at=NOW + timedelta(seconds=1), received_at=NOW + timedelta(seconds=2)), _policy(), NOW, ObservationPromotionOutcome.FUTURE),
        (_candidate(expires_at=NOW), _policy(), NOW, ObservationPromotionOutcome.EXPIRED),
    ),
)
def test_promotion_failures_are_explicit_and_never_return_trusted_truth(
    candidate: ObservationCandidateV1,
    policy: ObservationPromotionPolicyV1,
    now: datetime,
    outcome: ObservationPromotionOutcome,
) -> None:
    # Evidence remains factory-bound to the exact candidate, so policy/freshness is the rejected seam.
    decision = promote_observation(candidate, _evidence(candidate), policy, now=now)
    assert decision.outcome is outcome
    assert decision.trusted_observation is None


def test_history_is_deterministic_deduplicated_and_conflict_fail_closed() -> None:
    first = _trusted(_candidate(observation_id="observation-a"))
    same = _trusted(_candidate(observation_id="observation-b"))
    conflicting_candidate = _candidate(
        observation_id="observation-c",
        value=scalar(ScalarType.BOOLEAN, True),
        source_result_sha256=_effect_receipt(ReconciliationState.CONFIRMED).receipt_sha256,
        evidence_sha256=_effect_receipt(ReconciliationState.CONFIRMED).receipt_sha256,
    )
    conflicting = _trusted(conflicting_candidate)
    one = evaluate_observation_history((first, same, conflicting))
    two = evaluate_observation_history((conflicting, first, same, first))
    assert one.history_sha256 == two.history_sha256
    assert one.trusted_observations == ()
    assert one.conflicted_fact_keys == ("tenant-a:campaign-a:target-a:posture-collected",)
    with pytest.raises(FrozenInstanceError):
        first.candidate.fact_id = "different"  # type: ignore[misc]


def test_exact_nonconflicting_history_collapses_duplicate_digest_only() -> None:
    first = _trusted()
    history = evaluate_observation_history((first,) * 1_000)
    assert history.trusted_observations == (first,)
    assert history.conflicted_fact_keys == ()


def test_explicit_negative_fact_is_preserved_as_trusted_value_not_treated_as_missing() -> None:
    negative = _trusted(
        _candidate(
            fact_id="posture-collected",
            value=scalar(ScalarType.BOOLEAN, False),
        )
    )
    history = evaluate_observation_history((negative,))
    assert history.trusted_observations == (negative,)
    assert history.trusted_observations[0].value.value is False


def test_only_exact_r138_deterministic_correlation_receipt_can_mint_detection_provenance() -> None:
    store = DagStartStore()
    asyncio.run(
        DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, store).start(
            dag_start_request(), now=NOW + timedelta(seconds=40)
        )
    )
    execution_material, _ = store.materials[0]
    correlation_key = f"{execution_material.execution_run_id}:zap-invocation"
    seed = _confirmed(correlation_key=correlation_key)
    sibling = _observation(observation_id="correlated-sibling", correlation_key=correlation_key)
    correlation = correlate_detection_observations(
        observations=(seed, sibling),
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        correlation_key=sibling.correlation_key,
        attack_technique_id=sibling.attack_technique_id,
        now=DETECTION_NOW,
        max_age_seconds=300,
    )
    promoted = promote_detection_observation_by_correlation(
        observation=sibling,
        correlation=correlation,
        receipt_ref=_ref("correlation-receipt", "correlation-a", correlation.correlation_sha256),
    )
    producer = DETECTION_CORRELATION_PRODUCER_V1
    candidate = _candidate(
        producer=producer,
        authority_sha256=execution_material.authority_sha256,
        lifecycle_epoch=execution_material.lifecycle_epoch,
        policy_revocation_epoch=execution_material.policy_revocation_epoch,
        roe_revocation_epoch=execution_material.roe_revocation_epoch,
        kill_switch_epoch=execution_material.kill_switch_epoch,
        fact_id="posture-collected",
        value=scalar(ScalarType.BOOLEAN, True),
        source_result_sha256=canonical_sha256(promoted),
        evidence_sha256=promoted.evidence_ref.sha256,
        observed_at=promoted.observed_at,
        received_at=promoted.ingested_at,
        expires_at=promoted.expires_at,
    )
    evidence = verify_detection_correlation_evidence(
        candidate=candidate,
        observation=promoted,
        correlation=correlation,
        execution_material=execution_material,
        domain=dag_start_request().domain,
        verified_at=DETECTION_NOW,
    )
    decision = promote_observation(
        candidate,
        evidence,
        _policy(
            authority_sha256=execution_material.authority_sha256,
            lifecycle_epoch=execution_material.lifecycle_epoch,
            policy_revocation_epoch=execution_material.policy_revocation_epoch,
            roe_revocation_epoch=execution_material.roe_revocation_epoch,
            kill_switch_epoch=execution_material.kill_switch_epoch,
        ),
        now=DETECTION_NOW,
    )
    assert decision.outcome is ObservationPromotionOutcome.TRUSTED
    with pytest.raises(ValueError, match="observation_detection_correlation_binding_mismatch"):
        verify_detection_correlation_evidence(
            candidate=replace(candidate, source_result_sha256="f" * 64),
            observation=promoted,
            correlation=correlation,
            execution_material=execution_material,
            domain=dag_start_request().domain,
            verified_at=DETECTION_NOW,
        )


def test_verified_evidence_rejects_caller_forged_fact_value_and_producer_identity() -> None:
    candidate = _candidate()
    with pytest.raises(ValueError, match="observation_dag_fact_projection_mismatch"):
        _evidence(replace(candidate, value=scalar(ScalarType.INTEGER, 999)))
    with pytest.raises(ValueError, match="observation_dag_producer_invalid"):
        _evidence(
            replace(
                candidate,
                producer=ObservationProducerIdentityV1(
                    ObservationProducerKind.DAG_RUNNER_RESULT,
                    "caller-selected-runner",
                    "runner-v1",
                ),
            )
        )


def test_trusted_decision_cannot_bind_a_different_candidate_digest() -> None:
    candidate = _candidate()
    decision = promote_observation(candidate, _evidence(candidate), _policy(), now=NOW)
    with pytest.raises(ValueError, match="observation_promotion_candidate_binding_invalid"):
        replace(decision, candidate_sha256="f" * 64)
