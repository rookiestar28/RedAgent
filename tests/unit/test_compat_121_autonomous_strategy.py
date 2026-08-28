from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redagent_platform.agent_kernel.qualification import build_projection_catalog
from redagent_platform.campaign_service.context import (
    build_decision_context_snapshot,
    build_first_slice_semantics,
    build_first_slice_target_mapping,
    canonical_sha256,
)
from redagent_platform.campaign_service.contracts import (
    AuthorityContextV1,
    CollectionState,
    EvidenceFactV1,
    InvalidationState,
    ModelStrategyProposalV1,
    ObservationFactV1,
    ObservationKind,
    StrategyBudgetV1,
    StrategyObjectiveKind,
    StrategyObjectiveV1,
    StrategyOutcome,
    StrategySignalsV1,
    TrustLevel,
    Confidence,
    Completeness,
    TruthValue,
    TypedReferenceV1,
    _validated_plan_revision,
)
from redagent_platform.campaign_service.strategy import (
    DECISION_TABLE_REVISION,
    decide_strategy,
    validate_strategy_result,
)
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.nuclei_service.contracts import NucleiBundleManifest
from redagent_platform.zap_service.capability import build_zap_capability_manifest


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 24, 10, 30, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def ref(kind: str, value: str, digest: str = SHA_A) -> TypedReferenceV1:
    return TypedReferenceV1(kind=kind, reference_id=value, sha256=digest)


def source_values():
    zap = build_zap_capability_manifest(
        platform="linux/amd64", artifact_receipt_id="artifact-r104-zap-2170-r104-2"
    )
    nuclei = build_nuclei_capability_manifest(
        platform="linux/amd64", artifact_receipt_id="artifact-r105-nuclei-3111-r105-2"
    )
    bundle = NucleiBundleManifest(
        bundle_id="r105-http-header-bundle",
        revision=2,
        template_id="redagent-r105-missing-header",
        template_relative_path="templates/redagent-r105-missing-header.yaml",
        template_sha256="7f0689cdad1a2daf912de264a4c4894f7cd136f4936767bad06ea8d10d8965a8",
        bundle_sha256="6903c7fe75c14c67e3b3fe0d41ab52da9ef9e6790b5062d79fcf68ce7950affc",
        signature_verified=True,
        reviewer_user_id="redagent-r105-independent-review",
        protocol="http",
        method="GET",
        paths=("/nuclei/missing-header",),
        severity="low",
        tags=("redagent", "synthetic"),
        expected_matcher_names=("missing-security-header",),
        file_inventory=("templates/redagent-r105-missing-header.yaml",),
        promoted_at=datetime.fromisoformat("2026-08-24T17:03:42+08:00"),
        expires_at=datetime.fromisoformat("2026-09-23T17:03:42+08:00"),
    )
    projected = build_projection_catalog((zap, nuclei))
    semantics = build_first_slice_semantics(
        zap_capability=zap,
        nuclei_capability=nuclei,
        nuclei_bundle=bundle,
        zap_projection=projected[0],
        nuclei_projection=projected[1],
        promoted_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(days=7),
    )
    return semantics, projected


def authority(mapping_sha256: str, *, tenant: str = "tenant-a") -> AuthorityContextV1:
    return AuthorityContextV1(
        schema_version="redagent.r119-authority-context/v1",
        tenant_id=tenant,
        engagement_id="engagement-a",
        principal_id="principal-a",
        target=ref("target", "target-a"),
        target_mapping_sha256=mapping_sha256,
        target_class="owned-http-application",
        application_class="synthetic-security-header-fixture",
        environment_class="owned-loopback-lab",
        url_class="owned-loopback-gateway",
        roe_version_id="roe-v1",
        roe_sha256=SHA_A,
        roe_status="approved",
        policy_decision_id="policy-decision-1",
        policy_revision="policy-v1",
        policy_sha256=SHA_B,
        policy_status="allowed",
        issued_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(minutes=30),
    )


def empty_snapshot():
    semantics, projected = source_values()
    mapping = build_first_slice_target_mapping(semantics)
    current_authority = authority(mapping.mapping_sha256)
    snapshot = build_decision_context_snapshot(
        semantics=semantics,
        target_mapping=mapping,
        authority=current_authority,
        collection_state=CollectionState.COMPLETE,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        prior_complete_snapshot=None,
        snapshot_at=NOW,
    )
    return snapshot, current_authority, projected


def objective(kind: StrategyObjectiveKind, *, corroboration: bool = False) -> StrategyObjectiveV1:
    return StrategyObjectiveV1(
        schema_version="redagent.r121-objective/v1",
        objective_id="objective-1",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        target=ref("target", "target-a"),
        kind=kind,
        header_code=(
            "x-content-type-options"
            if kind is StrategyObjectiveKind.SECURITY_HEADER_ASSERTION
            else None
        ),
        require_corroboration=corroboration,
    )


def budget(*, depth: int = 2, operations: int = 2) -> StrategyBudgetV1:
    return StrategyBudgetV1(
        max_elapsed_seconds=60,
        max_operations=operations,
        max_targets=1,
        max_evidence_bytes=8192,
        max_depth=depth,
    )


def decide(kind: StrategyObjectiveKind, **overrides):
    snapshot, current_authority, projected = empty_snapshot()
    values = {
        "objective": objective(kind),
        "snapshot": snapshot,
        "authority": current_authority,
        "projections": projected,
        "budget": budget(),
        "signals": StrategySignalsV1(),
        "model_proposal": None,
        "now": NOW + timedelta(minutes=1),
    }
    values.update(overrides)
    return decide_strategy(**values)


def outcome_snapshot(
    capability_id: str,
    *,
    value_code: str = "inconclusive",
    observed_at: datetime = NOW - timedelta(minutes=5),
    evidence_expires_at: datetime = NOW + timedelta(hours=2),
):
    snapshot, current_authority, projected = empty_snapshot()
    sidecar = next(
        item for item in snapshot.semantics
        if item.binding_key.capability_id == capability_id
    )
    binding_sha256 = canonical_sha256(sidecar.binding_key)
    label = "zap" if capability_id == "zap-controlled-runtime" else "nuclei"
    evidence_ref = ref("evidence", f"evidence-{label}", SHA_B)
    capability_ref = ref("capability", capability_id, binding_sha256)
    if capability_id == "zap-controlled-runtime":
        adapter, revision, schema, path = (
            "zap-service", "2.17.0-r104.2", "zap-progress-v1", "/passive/missing-header"
        )
    else:
        adapter, revision, schema, path = (
            "nuclei-service", "3.11.1-r105.2", "nuclei-cleanup-v1", "/nuclei/missing-header"
        )
    evidence = EvidenceFactV1(
        schema_version="redagent.r119-evidence-fact/v1",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        binding_key_sha256=binding_sha256,
        target=current_authority.target,
        resource=capability_ref,
        evidence=evidence_ref,
        job=ref("job", f"job-{label}", SHA_C),
        producer_adapter_id=adapter,
        producer_revision=revision,
        producer_schema_id=schema,
        observation_kind=ObservationKind.CAPABILITY_OUTCOME,
        source_definition_id="capability-outcome",
        source_matcher_id="terminal-status",
        source_path=path,
        verified=True,
        redaction_state="approved",
        finalized_at=NOW - timedelta(minutes=4),
        expires_at=evidence_expires_at,
        invalidation_state=InvalidationState.CURRENT,
    )
    observation = ObservationFactV1(
        schema_version="redagent.r119-observation/v1",
        fact_id=f"observation-{label}",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        binding_key_sha256=binding_sha256,
        subject=current_authority.target,
        object=capability_ref,
        kind=ObservationKind.CAPABILITY_OUTCOME,
        truth=TruthValue.TRUE,
        value_code=value_code,
        source_adapter_id=adapter,
        producer_revision=revision,
        producer_schema_id=schema,
        trust=TrustLevel.VERIFIED,
        confidence=Confidence.HIGH,
        evidence=evidence_ref,
        provenance_sha256=SHA_C,
        observed_at=observed_at,
        valid_from=observed_at,
        ingested_at=NOW - timedelta(minutes=4),
        expires_at=NOW + timedelta(hours=1),
        completeness=Completeness.COMPLETE,
        invalidation_state=InvalidationState.CURRENT,
    )
    mapping = build_first_slice_target_mapping(snapshot.semantics)
    return (
        build_decision_context_snapshot(
            semantics=snapshot.semantics,
            target_mapping=mapping,
            authority=current_authority,
            collection_state=CollectionState.COMPLETE,
            current_observations=(observation,),
            current_evidence_facts=(evidence,),
            current_finding_facts=(),
            prior_complete_snapshot=None,
            snapshot_at=NOW,
        ),
        current_authority,
        projected,
    )


def test_closed_table_selects_zap_for_posture_and_nuclei_for_header() -> None:
    posture_receipt, posture_plan = decide(StrategyObjectiveKind.HTTP_POSTURE)
    header_receipt, header_plan = decide(StrategyObjectiveKind.SECURITY_HEADER_ASSERTION)

    assert DECISION_TABLE_REVISION == 1
    assert posture_receipt.outcome is StrategyOutcome.SELECT
    assert posture_plan is not None
    assert posture_receipt.receipt_sha256 == "f4a6b14804fcb1b299eac753c06b5838cc6f6221ac5e567fba4b1a00c08e5a48"
    assert posture_plan.plan_sha256 == "f034e1c823fe517aba82bda64d2f8feefe2f3af43b7360c17dd1604b15ef978b"
    assert posture_plan.primary.capability_id == "zap-controlled-runtime"
    assert posture_plan.successor is not None
    assert posture_plan.successor.condition == "fresh_inconclusive_or_insufficient_observation"
    assert posture_plan.successor.action.capability_id == "nuclei-trusted-runtime"
    assert header_plan is not None
    assert header_plan.primary.capability_id == "nuclei-trusted-runtime"
    assert header_plan.successor is not None
    assert header_plan.successor.action.capability_id == "zap-controlled-runtime"
    assert len(posture_receipt.candidates) == len(header_receipt.candidates) == 2
    assert posture_receipt.objective == objective(StrategyObjectiveKind.HTTP_POSTURE)
    assert posture_receipt.objective_sha256 == canonical_sha256(posture_receipt.objective)
    assert posture_receipt.snapshot.snapshot_sha256 == posture_receipt.snapshot_sha256
    assert posture_receipt.snapshot.capability_section_sha256 == posture_receipt.capability_section_sha256
    assert not hasattr(posture_receipt, "score")


def test_explicit_corroboration_has_its_own_closed_successor_condition() -> None:
    _, plan = decide(
        StrategyObjectiveKind.HTTP_POSTURE,
        objective=objective(StrategyObjectiveKind.HTTP_POSTURE, corroboration=True),
    )
    assert plan is not None and plan.successor is not None
    assert plan.successor.condition == "explicit_corroboration"


@pytest.mark.parametrize(
    ("kind", "inconclusive_capability", "expected_primary"),
    (
        (
            StrategyObjectiveKind.HTTP_POSTURE,
            "zap-controlled-runtime",
            "nuclei-trusted-runtime",
        ),
        (
            StrategyObjectiveKind.SECURITY_HEADER_ASSERTION,
            "nuclei-trusted-runtime",
            "zap-controlled-runtime",
        ),
    ),
)
def test_inconclusive_preferred_candidate_switches_to_other_exact_binding(
    kind: StrategyObjectiveKind,
    inconclusive_capability: str,
    expected_primary: str,
) -> None:
    snapshot, current_authority, projected = outcome_snapshot(inconclusive_capability)
    receipt, plan = decide_strategy(
        objective=objective(kind),
        snapshot=snapshot,
        authority=current_authority,
        projections=projected,
        budget=budget(),
        signals=StrategySignalsV1(),
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )
    assert receipt.outcome is StrategyOutcome.SELECT
    assert receipt.snapshot == snapshot
    assert plan is not None and plan.primary.capability_id == expected_primary
    assert plan.successor is None
    assert {item.reason for item in receipt.candidates if not item.eligible} == {
        "existing_inconclusive"
    }


@pytest.mark.parametrize(
    ("kind", "non_preferred"),
    (
        (StrategyObjectiveKind.HTTP_POSTURE, "nuclei-trusted-runtime"),
        (StrategyObjectiveKind.SECURITY_HEADER_ASSERTION, "zap-controlled-runtime"),
    ),
)
def test_inconclusive_non_preferred_candidate_is_never_emitted_as_successor(
    kind: StrategyObjectiveKind, non_preferred: str
) -> None:
    snapshot, current_authority, projected = outcome_snapshot(non_preferred)
    receipt, plan = decide_strategy(
        objective=objective(kind),
        snapshot=snapshot,
        authority=current_authority,
        projections=projected,
        budget=budget(),
        signals=StrategySignalsV1(),
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )
    expected = (
        "zap-controlled-runtime"
        if kind is StrategyObjectiveKind.HTTP_POSTURE
        else "nuclei-trusted-runtime"
    )
    assert receipt.outcome is StrategyOutcome.SELECT
    assert plan is not None and plan.primary.capability_id == expected
    assert plan.successor is None
    assert {item.reason for item in receipt.candidates if not item.eligible} == {
        "existing_inconclusive"
    }


def test_both_inconclusive_candidates_stop_without_action() -> None:
    zap, current_authority, projected = outcome_snapshot("zap-controlled-runtime")
    nuclei, _, _ = outcome_snapshot("nuclei-trusted-runtime")
    mapping = build_first_slice_target_mapping(zap.semantics)
    both = build_decision_context_snapshot(
        semantics=zap.semantics,
        target_mapping=mapping,
        authority=current_authority,
        collection_state=CollectionState.COMPLETE,
        current_observations=zap.observations + nuclei.observations,
        current_evidence_facts=zap.evidence_facts + nuclei.evidence_facts,
        current_finding_facts=(),
        prior_complete_snapshot=None,
        snapshot_at=NOW,
    )
    receipt, plan = decide_strategy(
        objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
        snapshot=both,
        authority=current_authority,
        projections=projected,
        budget=budget(),
        signals=StrategySignalsV1(),
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )
    assert receipt.outcome is StrategyOutcome.STOP
    assert receipt.reason == "all_candidates_inconclusive" and plan is None
    assert not any(item.eligible for item in receipt.candidates)


@pytest.mark.parametrize(
    ("value_code", "expected_reason"),
    (("failed", "capability_failed"), ("cancelled", "capability_cancelled")),
)
def test_failed_and_cancelled_capability_outcomes_stop_without_action(
    value_code: str, expected_reason: str
) -> None:
    snapshot, current_authority, projected = outcome_snapshot(
        "zap-controlled-runtime", value_code=value_code
    )
    receipt, plan = decide_strategy(
        objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
        snapshot=snapshot,
        authority=current_authority,
        projections=projected,
        budget=budget(),
        signals=StrategySignalsV1(),
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )
    assert receipt.outcome is StrategyOutcome.STOP
    assert receipt.reason == expected_reason and plan is None
    assert not any(item.eligible for item in receipt.candidates)


def test_decision_time_stale_observation_or_linked_evidence_fails_closed() -> None:
    stale_fact, current_authority, projected = outcome_snapshot(
        "zap-controlled-runtime",
        observed_at=NOW - timedelta(minutes=59),
    )
    with pytest.raises(ValueError, match="r121_observation_or_evidence_not_current"):
        decide_strategy(
            objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
            snapshot=stale_fact,
            authority=current_authority,
            projections=projected,
            budget=budget(),
            signals=StrategySignalsV1(),
            model_proposal=None,
            now=NOW + timedelta(minutes=2),
        )

    stale_evidence, current_authority, projected = outcome_snapshot(
        "zap-controlled-runtime",
        evidence_expires_at=NOW + timedelta(seconds=30),
    )
    with pytest.raises(ValueError, match="r121_observation_or_evidence_not_current"):
        decide_strategy(
            objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
            snapshot=stale_evidence,
            authority=current_authority,
            projections=projected,
            budget=budget(),
            signals=StrategySignalsV1(),
            model_proposal=None,
            now=NOW + timedelta(minutes=1),
        )


def test_depth_one_and_exhausted_budget_never_create_extra_action() -> None:
    _, depth_one = decide(
        StrategyObjectiveKind.HTTP_POSTURE,
        budget=budget(depth=1, operations=1),
    )
    assert depth_one is not None and depth_one.successor is None and depth_one.depth == 1

    depth_receipt, _ = decide(
        StrategyObjectiveKind.HTTP_POSTURE,
        budget=budget(depth=1, operations=1),
    )
    assert [item.eligible for item in depth_receipt.candidates].count(True) == 1
    assert {item.reason for item in depth_receipt.candidates if not item.eligible} == {
        "successor_budget_unavailable"
    }

    receipt, plan = decide(
        StrategyObjectiveKind.HTTP_POSTURE,
        budget=budget(depth=0, operations=0),
    )
    assert receipt.outcome is StrategyOutcome.STOP
    assert receipt.reason == "budget_exhausted"
    assert not any(item.eligible for item in receipt.candidates)
    assert plan is None


def test_incomplete_collection_skips_without_action() -> None:
    snapshot, current_authority, projected = empty_snapshot()
    mapping = build_first_slice_target_mapping(snapshot.semantics)
    incomplete = build_decision_context_snapshot(
        semantics=snapshot.semantics,
        target_mapping=mapping,
        authority=current_authority,
        collection_state=CollectionState.FAILED,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        prior_complete_snapshot=None,
        snapshot_at=NOW,
    )
    receipt, plan = decide_strategy(
        objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
        snapshot=incomplete,
        authority=current_authority,
        projections=projected,
        budget=budget(),
        signals=StrategySignalsV1(),
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )
    assert receipt.outcome is StrategyOutcome.SKIP
    assert receipt.reason == "insufficient_observation" and plan is None
    assert not any(item.eligible for item in receipt.candidates)


@pytest.mark.parametrize(
    "signal",
    (
        "policy_denied",
        "evidence_failure",
        "cleanup_failure",
        "infrastructure_failure",
        "attention_required",
    ),
)
def test_operational_denials_stop_with_zero_action(signal: str) -> None:
    receipt, plan = decide(
        StrategyObjectiveKind.HTTP_POSTURE,
        signals=StrategySignalsV1(stop_reason=signal),
    )
    assert receipt.outcome is StrategyOutcome.STOP and receipt.reason == signal
    assert receipt.selected_binding_sha256 is None and plan is None
    assert not any(item.eligible for item in receipt.candidates)


def test_trusted_header_fact_satisfies_objective_without_action() -> None:
    snapshot, current_authority, projected = empty_snapshot()
    zap_binding = next(
        item.binding_key for item in snapshot.semantics
        if item.binding_key.capability_id == "zap-controlled-runtime"
    )
    evidence_ref = ref("evidence", "evidence-1", SHA_B)
    resource = ref("security-header", "x-content-type-options", SHA_C)
    evidence = EvidenceFactV1(
        schema_version="redagent.r119-evidence-fact/v1",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        binding_key_sha256=canonical_sha256(zap_binding),
        target=current_authority.target,
        resource=resource,
        evidence=evidence_ref,
        job=ref("job", "job-1", SHA_C),
        producer_adapter_id="zap-service",
        producer_revision="2.17.0-r104.2",
        producer_schema_id="zap-alert-v1",
        observation_kind=ObservationKind.SECURITY_HEADER_MISSING,
        source_definition_id="10021",
        source_matcher_id="10021",
        source_path="/passive/missing-header",
        verified=True,
        redaction_state="approved",
        finalized_at=NOW - timedelta(minutes=4),
        expires_at=NOW + timedelta(hours=2),
        invalidation_state=InvalidationState.CURRENT,
    )
    observation = ObservationFactV1(
        schema_version="redagent.r119-observation/v1",
        fact_id="observation-1",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        binding_key_sha256=canonical_sha256(zap_binding),
        subject=current_authority.target,
        object=resource,
        kind=ObservationKind.SECURITY_HEADER_MISSING,
        truth=TruthValue.TRUE,
        value_code="x-content-type-options",
        source_adapter_id="zap-service",
        producer_revision="2.17.0-r104.2",
        producer_schema_id="zap-alert-v1",
        trust=TrustLevel.VERIFIED,
        confidence=Confidence.HIGH,
        evidence=evidence_ref,
        provenance_sha256=SHA_C,
        observed_at=NOW - timedelta(minutes=5),
        valid_from=NOW - timedelta(minutes=5),
        ingested_at=NOW - timedelta(minutes=4),
        expires_at=NOW + timedelta(hours=1),
        completeness=Completeness.COMPLETE,
        invalidation_state=InvalidationState.CURRENT,
    )
    mapping = build_first_slice_target_mapping(snapshot.semantics)
    satisfied = build_decision_context_snapshot(
        semantics=snapshot.semantics,
        target_mapping=mapping,
        authority=current_authority,
        collection_state=CollectionState.COMPLETE,
        current_observations=(observation,),
        current_evidence_facts=(evidence,),
        current_finding_facts=(),
        prior_complete_snapshot=None,
        snapshot_at=NOW,
    )
    receipt, plan = decide_strategy(
        objective=objective(StrategyObjectiveKind.SECURITY_HEADER_ASSERTION),
        snapshot=satisfied,
        authority=current_authority,
        projections=projected,
        budget=budget(),
        signals=StrategySignalsV1(),
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )
    assert receipt.outcome is StrategyOutcome.STOP
    assert receipt.reason == "objective_satisfied" and plan is None


def test_scope_time_projection_and_candidate_drift_fail_closed() -> None:
    snapshot, current_authority, projected = empty_snapshot()
    for scoped_objective in (
        replace(objective(StrategyObjectiveKind.HTTP_POSTURE), tenant_id="tenant-b"),
        replace(objective(StrategyObjectiveKind.HTTP_POSTURE), engagement_id="engagement-b"),
        replace(
            objective(StrategyObjectiveKind.HTTP_POSTURE),
            target=ref("target", "target-b", SHA_B),
        ),
    ):
        with pytest.raises(ValueError, match="r121_objective_scope_mismatch"):
            decide_strategy(
                objective=scoped_objective,
                snapshot=snapshot, authority=current_authority, projections=projected,
                budget=budget(), signals=StrategySignalsV1(), model_proposal=None,
                now=NOW + timedelta(minutes=1),
            )
    long_authority = replace(current_authority, expires_at=NOW + timedelta(hours=3))
    mapping = build_first_slice_target_mapping(snapshot.semantics)
    stale_snapshot = build_decision_context_snapshot(
        semantics=snapshot.semantics,
        target_mapping=mapping,
        authority=long_authority,
        collection_state=CollectionState.COMPLETE,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        prior_complete_snapshot=None,
        snapshot_at=NOW,
    )
    with pytest.raises(ValueError, match="r121_snapshot_stale"):
        decide_strategy(
            objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
            snapshot=stale_snapshot, authority=long_authority, projections=projected,
            budget=budget(), signals=StrategySignalsV1(), model_proposal=None,
            now=NOW + timedelta(hours=2),
        )
    with pytest.raises(ValueError, match="r121_projection_set_mismatch"):
        decide_strategy(
            objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
            snapshot=snapshot, authority=current_authority, projections=projected[:1],
            budget=budget(), signals=StrategySignalsV1(), model_proposal=None,
            now=NOW + timedelta(minutes=1),
        )


def test_model_proposal_cannot_add_or_change_candidate() -> None:
    snapshot, current_authority, projected = empty_snapshot()
    proposal = ModelStrategyProposalV1(
        schema_version="redagent.r121-model-proposal/v1",
        outcome=StrategyOutcome.SELECT,
        selected_binding_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="r121_model_proposal_mismatch"):
        decide_strategy(
            objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
            snapshot=snapshot, authority=current_authority, projections=projected,
            budget=budget(), signals=StrategySignalsV1(), model_proposal=proposal,
            now=NOW + timedelta(minutes=1),
        )


def test_matching_model_proposal_is_only_a_non_authoritative_consistency_check() -> None:
    baseline_receipt, _ = decide(StrategyObjectiveKind.HTTP_POSTURE)
    proposal = ModelStrategyProposalV1(
        schema_version="redagent.r121-model-proposal/v1",
        outcome=baseline_receipt.outcome,
        selected_binding_sha256=baseline_receipt.selected_binding_sha256,
    )
    proposed = decide(StrategyObjectiveKind.HTTP_POSTURE, model_proposal=proposal)
    assert proposed[0] == baseline_receipt


def test_projection_tamper_boolean_budget_and_direct_output_construction_fail_closed() -> None:
    snapshot, current_authority, projected = empty_snapshot()
    with pytest.raises(ValueError, match="r121_projection_binding_mismatch"):
        decide_strategy(
            objective=objective(StrategyObjectiveKind.HTTP_POSTURE),
            snapshot=snapshot,
            authority=current_authority,
            projections=(replace(projected[0], approval_tier="low"), projected[1]),
            budget=budget(),
            signals=StrategySignalsV1(),
            model_proposal=None,
            now=NOW + timedelta(minutes=1),
        )
    with pytest.raises(ValueError, match="r121_budget_operations_invalid"):
        StrategyBudgetV1(
            max_elapsed_seconds=60,
            max_operations=True,
            max_targets=1,
            max_evidence_bytes=8192,
            max_depth=2,
        )
    receipt, plan = decide(StrategyObjectiveKind.HTTP_POSTURE)
    with pytest.raises(ValueError, match="r121_receipt_factory_required"):
        replace(receipt, reason="tampered")
    assert plan is not None
    with pytest.raises(ValueError, match="r121_plan_factory_required"):
        replace(plan, width=2)


def test_replay_is_order_invariant_and_validator_rechecks_result() -> None:
    snapshot, current_authority, projected = empty_snapshot()
    args = dict(
        objective=objective(StrategyObjectiveKind.HTTP_POSTURE, corroboration=True),
        snapshot=snapshot,
        authority=current_authority,
        budget=budget(),
        signals=StrategySignalsV1(),
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )
    first = decide_strategy(projections=projected, **args)
    repeated = decide_strategy(projections=tuple(reversed(projected)), **args)
    assert first == repeated
    assert first[0].receipt_sha256 == repeated[0].receipt_sha256
    assert first[1] is not None and first[1].plan_sha256 == repeated[1].plan_sha256
    validate_strategy_result(
        objective=args["objective"],
        current_snapshot=snapshot,
        authority=current_authority,
        projections=projected,
        budget=args["budget"],
        signals=args["signals"],
        now=args["now"],
        receipt=first[0],
        plan=first[1],
    )


def test_current_input_validator_rejects_forged_action_expiry_and_budget_drift() -> None:
    snapshot, current_authority, projected = empty_snapshot()
    current_objective = objective(StrategyObjectiveKind.HTTP_POSTURE)
    current_budget = budget()
    current_signals = StrategySignalsV1()
    receipt, plan = decide_strategy(
        objective=current_objective,
        snapshot=snapshot,
        authority=current_authority,
        projections=projected,
        budget=current_budget,
        signals=current_signals,
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )
    assert plan is not None
    forged_values = plan.canonical_body()
    forged_values["primary"] = replace(plan.primary, profile_id="forged-profile")
    forged_plan = _validated_plan_revision(
        **forged_values,
        plan_sha256=canonical_sha256(forged_values),
    )
    validator_values = {
        "objective": current_objective,
        "current_snapshot": snapshot,
        "authority": current_authority,
        "projections": projected,
        "budget": current_budget,
        "signals": current_signals,
        "now": NOW + timedelta(minutes=1),
        "receipt": receipt,
    }
    with pytest.raises(ValueError, match="r121_result_not_current"):
        validate_strategy_result(**validator_values, plan=forged_plan)
    with pytest.raises(ValueError, match="r121_result_not_current"):
        validate_strategy_result(
            **(validator_values | {"now": NOW + timedelta(minutes=31)}),
            plan=plan,
        )
    with pytest.raises(ValueError, match="r121_result_not_current"):
        validate_strategy_result(
            **(validator_values | {"budget": budget(depth=1, operations=1)}),
            plan=plan,
        )


def test_r121_is_pure_and_r122_has_no_surface() -> None:
    strategy_source = (ROOT / "redagent_platform/campaign_service/strategy.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "requests", "httpx", "socket", "subprocess", "sqlalchemy", "psycopg",
        "temporalio", "open(", "write_text", "write_bytes",
    ):
        assert forbidden not in strategy_source
    assert not (ROOT / "redagent_platform/campaign_service/path_planner.py").exists()
    assert not any("compat_121" in path.name.lower() or "compat_122" in path.name.lower()
                   for path in (ROOT / "migrations/versions").glob("*.py"))
