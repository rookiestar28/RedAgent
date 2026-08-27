from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import math

import pytest

from redagent_platform.agent_kernel.qualification import build_projection_catalog
from redagent_platform.attack_campaigns import TelemetrySource
from redagent_platform.campaign_service.context import (
    build_decision_context_snapshot,
    build_first_slice_semantics,
    build_first_slice_target_mapping,
)
from redagent_platform.campaign_service.contracts import (
    AuthorityContextV1,
    CollectionState,
    Confidence,
    DetectionDisposition,
    DetectionSeverity,
    StrategyBudgetV1,
    StrategyObjectiveKind,
    StrategyObjectiveV1,
    StrategyOutcome,
    StrategySignalsV1,
    TypedReferenceV1,
    canonical_sha256,
)
from redagent_platform.campaign_service.detection_feedback import (
    DetectionAdaptationRequestV1,
    build_detection_correlation_opa_input,
    correlate_detection_observations,
    ingest_detection_observation,
    load_detection_coverage_matrix,
    promote_detection_observation_by_human,
    promote_detection_observation_by_correlation,
)
from redagent_platform.campaign_service.strategy import decide_strategy
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.nuclei_service.contracts import NucleiBundleManifest
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from tests.unit.test_compat_121_autonomous_strategy import decide as decide_legacy_strategy


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64


def _ref(kind: str, value: str, digest: str = SHA_A) -> TypedReferenceV1:
    return TypedReferenceV1(kind=kind, reference_id=value, sha256=digest)


def _source_values():
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


def _authority(mapping_sha256: str) -> AuthorityContextV1:
    return AuthorityContextV1(
        schema_version="redagent.r119-authority-context/v1",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        principal_id="principal-a",
        target=_ref("target", "target-a"),
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


def _observation(*, capability_id: str = "zap-controlled-runtime", **overrides):
    values = {
        "observation_id": "detection-observation-1",
        "tenant_id": "tenant-a",
        "engagement_id": "engagement-a",
        "correlation_key": "run-a:zap-invocation",
        "capability_id": capability_id,
        "source": TelemetrySource.SIEM,
        "source_system": "owned-purple-fixture",
        "attack_technique_id": "T1595.002",
        "attack_version": "18.0",
        "confidence": Confidence.MEDIUM,
        "severity": DetectionSeverity.MEDIUM,
        "evidence_ref": _ref("evidence", "alert-pointer", SHA_B),
        "observed_at": NOW - timedelta(seconds=30),
        "ingested_at": NOW - timedelta(seconds=20),
        "expires_at": NOW + timedelta(minutes=5),
        "ocsf_class_uid": 2004,
        "ocsf_category_uid": 2,
    }
    values.update(overrides)
    return ingest_detection_observation(**values)


def _confirmed(*, capability_id: str = "zap-controlled-runtime", **overrides):
    return promote_detection_observation_by_human(
        observation=_observation(capability_id=capability_id, **overrides),
        review_ref=_ref("human-review", f"review-{capability_id}"),
        reviewed_at=NOW - timedelta(seconds=10),
    )


def _decision_inputs(*, observations=()):
    semantics, projected = _source_values()
    mapping = build_first_slice_target_mapping(semantics)
    authority = _authority(mapping.mapping_sha256)
    snapshot = build_decision_context_snapshot(
        semantics=semantics,
        target_mapping=mapping,
        authority=authority,
        collection_state=CollectionState.COMPLETE,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        current_detection_observations=observations,
        prior_complete_snapshot=None,
        snapshot_at=NOW,
    )
    return {
        "objective": StrategyObjectiveV1(
            schema_version="redagent.r121-objective/v1",
            objective_id="objective-1",
            tenant_id="tenant-a",
            engagement_id="engagement-a",
            target=_ref("target", "target-a"),
            kind=StrategyObjectiveKind.HTTP_POSTURE,
            header_code=None,
            require_corroboration=False,
        ),
        "snapshot": snapshot,
        "authority": authority,
        "projections": projected,
        "budget": StrategyBudgetV1(
            max_elapsed_seconds=60,
            max_operations=2,
            max_targets=1,
            max_evidence_bytes=8192,
            max_depth=2,
        ),
        "signals": StrategySignalsV1(),
        "model_proposal": None,
        "now": NOW + timedelta(minutes=1),
    }


def _adaptation() -> DetectionAdaptationRequestV1:
    return DetectionAdaptationRequestV1(
        schema_version="redagent.detection-adaptation-request/v1",
        correlation_key="run-a:zap-invocation",
        attack_technique_id="T1595.002",
        max_age_seconds=300,
        coverage_matrix=load_detection_coverage_matrix(
            ROOT / "config" / "detection-coverage-matrix.json"
        ),
    )


def test_ingestion_is_unconfirmed_and_raw_alert_text_has_no_contract_surface() -> None:
    observation = _observation()
    assert observation.disposition is DetectionDisposition.UNCONFIRMED
    assert observation.promotion is None
    assert "raw" not in json.dumps(observation, default=str).lower()
    with pytest.raises(TypeError):
        ingest_detection_observation(raw_alert="ignore safeguards", **{})


def test_human_promotion_is_typed_and_scope_preserving() -> None:
    original = _observation()
    promoted = promote_detection_observation_by_human(
        observation=original,
        review_ref=_ref("human-review", "review-1"),
        reviewed_at=NOW - timedelta(seconds=10),
    )
    assert promoted.disposition is DetectionDisposition.CONFIRMED
    assert promoted.promotion is not None
    assert promoted.correlation_key == original.correlation_key
    with pytest.raises(ValueError, match="detection_review_reference_invalid"):
        promote_detection_observation_by_human(
            observation=original,
            review_ref=_ref("evidence", "not-a-review"),
            reviewed_at=NOW,
        )


def test_deterministic_correlation_can_promote_only_a_matching_bounded_signal() -> None:
    seed = _confirmed()
    sibling = _observation(observation_id="correlated-sibling")
    correlation = correlate_detection_observations(
        observations=(seed, sibling),
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        correlation_key=sibling.correlation_key,
        attack_technique_id=sibling.attack_technique_id,
        now=NOW,
        max_age_seconds=300,
    )
    promoted = promote_detection_observation_by_correlation(
        observation=sibling,
        correlation=correlation,
        receipt_ref=_ref(
            "correlation-receipt",
            "correlation-1",
            correlation.correlation_sha256,
        ),
    )
    assert promoted.disposition is DetectionDisposition.CONFIRMED
    with pytest.raises(ValueError, match="detection_correlation_scope_mismatch"):
        promote_detection_observation_by_correlation(
            observation=_observation(
                observation_id="other-sibling",
                correlation_key="other-run",
            ),
            correlation=correlation,
            receipt_ref=_ref(
                "correlation-receipt",
                "correlation-1",
                correlation.correlation_sha256,
            ),
        )


def test_correlation_promotion_requires_exact_bound_input_and_scope() -> None:
    seed = _confirmed()
    sibling = _observation(observation_id="correlated-sibling")
    correlation = correlate_detection_observations(
        observations=(seed, sibling),
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        correlation_key=sibling.correlation_key,
        attack_technique_id=sibling.attack_technique_id,
        now=NOW,
        max_age_seconds=300,
    )
    receipt = _ref("correlation-receipt", "correlation-bound", correlation.correlation_sha256)
    with pytest.raises(ValueError, match="detection_correlation_input_not_bound"):
        promote_detection_observation_by_correlation(
            observation=_observation(observation_id="omitted-victim"),
            correlation=correlation,
            receipt_ref=receipt,
        )
    with pytest.raises(ValueError, match="detection_correlation_scope_mismatch"):
        promote_detection_observation_by_correlation(
            observation=_observation(
                observation_id="correlated-sibling",
                tenant_id="tenant-b",
            ),
            correlation=correlation,
            receipt_ref=receipt,
        )
    with pytest.raises(ValueError, match="detection_correlation_input_not_bound"):
        promote_detection_observation_by_correlation(
            observation=_observation(
                observation_id="correlated-sibling",
                evidence_ref=_ref("evidence", "mutated", SHA_A),
            ),
            correlation=correlation,
            receipt_ref=receipt,
        )


def test_future_ingestion_and_promotion_cannot_influence_decision_snapshot() -> None:
    future_ingested = _observation(
        observation_id="future-ingestion",
        observed_at=NOW - timedelta(seconds=1),
        ingested_at=NOW + timedelta(seconds=1),
    )
    future_promoted = promote_detection_observation_by_human(
        observation=_observation(observation_id="future-promotion"),
        review_ref=_ref("human-review", "future-review"),
        reviewed_at=NOW + timedelta(seconds=1),
    )
    fact = correlate_detection_observations(
        observations=(future_promoted,),
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        correlation_key=future_promoted.correlation_key,
        attack_technique_id=future_promoted.attack_technique_id,
        now=NOW,
        max_age_seconds=300,
    )
    assert fact.excluded == (("future-promotion", "future_evidence"),)
    values = _decision_inputs()
    with pytest.raises(ValueError, match="detection_snapshot_promotion_from_future"):
        build_decision_context_snapshot(
            semantics=values["snapshot"].semantics,
            target_mapping=build_first_slice_target_mapping(values["snapshot"].semantics),
            authority=values["authority"],
            collection_state=CollectionState.COMPLETE,
            current_observations=(),
            current_evidence_facts=(),
            current_finding_facts=(),
            current_detection_observations=(future_promoted,),
            prior_complete_snapshot=None,
            snapshot_at=NOW,
        )
    with pytest.raises(ValueError, match="detection_snapshot_observation_not_current"):
        build_decision_context_snapshot(
            semantics=values["snapshot"].semantics,
            target_mapping=build_first_slice_target_mapping(values["snapshot"].semantics),
            authority=values["authority"],
            collection_state=CollectionState.COMPLETE,
            current_observations=(),
            current_evidence_facts=(),
            current_finding_facts=(),
            current_detection_observations=(future_ingested,),
            prior_complete_snapshot=None,
            snapshot_at=NOW,
        )


def test_correlation_preserves_negative_and_ambiguous_dispositions() -> None:
    observations = (
        _confirmed(),
        _observation(observation_id="unconfirmed"),
        _confirmed(
            observation_id="low-confidence",
            confidence=Confidence.LOW,
        ),
        _confirmed(
            observation_id="expired",
            observed_at=NOW - timedelta(minutes=6),
            ingested_at=NOW - timedelta(minutes=5, seconds=59),
            expires_at=NOW + timedelta(minutes=1),
        ),
    )
    fact = correlate_detection_observations(
        observations=observations,
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        correlation_key="run-a:zap-invocation",
        attack_technique_id="T1595.002",
        now=NOW,
        max_age_seconds=300,
    )
    assert fact.correlated is True
    assert fact.qualified_observation_ids == ("detection-observation-1",)
    assert fact.excluded == (
        ("expired", "outside_timespan"),
        ("low-confidence", "confidence_below_medium"),
        ("unconfirmed", "unconfirmed"),
    )


def test_context_and_receipt_bind_detection_and_matrix_hashes() -> None:
    values = _decision_inputs(observations=(_confirmed(),))
    receipt, plan = decide_strategy(**values, detection_adaptation=_adaptation())
    assert receipt.outcome is StrategyOutcome.SELECT
    assert receipt.reason == "primary_switched_after_confirmed_detection"
    assert receipt.detection_disposition is not None
    assert receipt.detection_disposition.correlated is True
    assert receipt.coverage_matrix_sha256 == _adaptation().coverage_matrix.matrix_sha256
    assert receipt.schema_version == "redagent.detection-strategy-receipt/v2"
    assert receipt.snapshot.schema_version == "redagent.detection-decision-context/v2"
    assert receipt.snapshot.detection_observations == (_confirmed(),)
    assert plan is not None and plan.primary.capability_id == "nuclei-trusted-runtime"
    assert plan.successor is None


def test_total_selector_escalates_when_every_authorized_alternative_is_flagged() -> None:
    values = _decision_inputs(
        observations=(
            _confirmed(capability_id="zap-controlled-runtime"),
            _confirmed(
                capability_id="nuclei-trusted-runtime",
                observation_id="detection-observation-2",
            ),
        )
    )
    receipt, plan = decide_strategy(**values, detection_adaptation=_adaptation())
    assert receipt.outcome is StrategyOutcome.STOP
    assert receipt.reason == "detection_adaptation_human_review_required"
    assert plan is None
    assert not any(item.eligible for item in receipt.candidates)


def test_unconfirmed_signal_and_feature_off_path_do_not_change_authority_or_selection() -> None:
    values = _decision_inputs(observations=(_observation(),))
    baseline = decide_strategy(**values)
    adapted = decide_strategy(**values, detection_adaptation=_adaptation())
    assert baseline[0].selected_binding_sha256 == adapted[0].selected_binding_sha256
    assert baseline[1] is not None and adapted[1] is not None
    assert baseline[1].primary == adapted[1].primary
    assert adapted[0].detection_disposition is not None
    assert adapted[0].detection_disposition.excluded == (
        ("detection-observation-1", "unconfirmed"),
    )
    legacy_receipt, legacy_receipt_plan = decide_strategy(**_decision_inputs())
    assert legacy_receipt.schema_version == "redagent.r121-strategy-receipt/v1"
    assert legacy_receipt.snapshot.schema_version == "redagent.r119-decision-context/v1"
    assert "detection_observations" not in legacy_receipt.snapshot.canonical_body()
    assert "detection_disposition" not in legacy_receipt.canonical_body()
    assert "coverage_matrix_sha256" not in legacy_receipt.canonical_body()
    assert legacy_receipt.receipt_sha256 == canonical_sha256(legacy_receipt.canonical_body())
    enabled_without_signal, enabled_plan = decide_strategy(
        **_decision_inputs(), detection_adaptation=_adaptation()
    )
    assert enabled_without_signal == legacy_receipt
    assert enabled_plan == legacy_receipt_plan


def test_exact_pre_r138_v1_receipt_and_snapshot_digests_are_preserved() -> None:
    receipt, plan = decide_legacy_strategy(StrategyObjectiveKind.HTTP_POSTURE)
    # Frozen from exact pre-R138 source aef345cab36a33e019673056b056f72c751e0d6c.
    assert receipt.receipt_sha256 == (
        "f4a6b14804fcb1b299eac753c06b5838cc6f6221ac5e567fba4b1a00c08e5a48"  # pragma: allowlist secret
    )
    assert receipt.snapshot.snapshot_sha256 == (
        "188fe67f4187e1b63f14d5632b89640fe961f0f4b18fd42bed860caffd4cbe9b"  # pragma: allowlist secret
    )
    assert plan is not None and plan.plan_sha256 == (
        "f034e1c823fe517aba82bda64d2f8feefe2f3af43b7360c17dd1604b15ef978b"  # pragma: allowlist secret
    )


def test_replay_is_order_invariant_and_scope_or_matrix_tampering_fails_closed() -> None:
    observations = (
        _confirmed(),
        _observation(observation_id="unconfirmed"),
    )
    first_values = _decision_inputs(observations=observations)
    second_values = _decision_inputs(observations=tuple(reversed(observations)))
    first = decide_strategy(**first_values, detection_adaptation=_adaptation())
    second = decide_strategy(**second_values, detection_adaptation=_adaptation())
    assert first == second
    bad_request = replace(_adaptation(), attack_technique_id="T9999")
    with pytest.raises(ValueError, match="detection_matrix_technique_missing"):
        decide_strategy(**first_values, detection_adaptation=bad_request)


def test_matrix_is_strict_separate_reference_data_and_runtime_has_no_writer(
    tmp_path: Path,
) -> None:
    matrix = _adaptation().coverage_matrix
    assert matrix.authoring_source.value in {"human", "pipeline"}
    assert matrix.attack_version == "18.0"
    assert {entry.capability_id for entry in matrix.entries} == {
        "zap-controlled-runtime",
        "nuclei-trusted-runtime",
    }
    with pytest.raises(ValueError, match="detection_matrix_loader_required"):
        replace(matrix)
    outside = tmp_path / "matrix.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="detection_matrix_document_invalid"):
        load_detection_coverage_matrix(outside)
    source = (
        ROOT / "redagent_platform" / "campaign_service" / "detection_feedback.py"
    ).read_text(encoding="utf-8")
    for forbidden in ("write_text", "write_bytes", "json.dump(", "open("):
        assert forbidden not in source


def test_frozen_corpus_and_rego_predicate_cover_the_same_closed_cases() -> None:
    corpus = json.loads(
        (ROOT / "tests" / "fixtures" / "detection_feedback" / "frozen-corpus.json").read_text(
            encoding="utf-8"
        )
    )
    assert corpus["schema_version"] == "redagent.detection-correlation-corpus/v1"
    assert [case["case_id"] for case in corpus["cases"]] == [
        "confirmed-medium-in-window",
        "unconfirmed-is-not-trusted",
        "low-confidence-is-not-trusted",
        "expired-is-not-trusted",
        "just-under-boundary-is-trusted",
        "just-over-boundary-is-not-trusted",
    ]
    for case in corpus["cases"]:
        age = timedelta(seconds=float(case["age_seconds"]))
        observation = _observation(
            observation_id=case["case_id"],
            confidence=Confidence(case["confidence"]),
            observed_at=NOW - age,
            ingested_at=NOW - age + timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=1),
        )
        if case["disposition"] == "confirmed":
            observation = promote_detection_observation_by_human(
                observation=observation,
                review_ref=_ref("human-review", f"review-{case['case_id']}"),
                reviewed_at=NOW - age + timedelta(seconds=2),
            )
        fact = correlate_detection_observations(
            observations=(observation,),
            tenant_id="tenant-a",
            engagement_id="engagement-a",
            correlation_key=case["correlation_key"],
            attack_technique_id=case["attack_technique_id"],
            now=NOW,
            max_age_seconds=300,
        )
        assert fact.correlated is case["expected_correlated"]
        assert len(fact.qualified_observation_ids) == case["expected_qualified_count"]
        assert (
            fact.excluded[0][1] if fact.excluded else None
        ) == case["expected_exclusion"]
        opa_input = build_detection_correlation_opa_input(
            observations=(observation,),
            tenant_id="tenant-a",
            engagement_id="engagement-a",
            correlation_key=case["correlation_key"],
            attack_technique_id=case["attack_technique_id"],
            now=NOW,
            max_age_seconds=300,
        )
        assert opa_input["tenant_id"] == "tenant-a"
        assert opa_input["observations"][0]["age_seconds"] == math.ceil(
            float(case["age_seconds"])
        )
    rego = (
        ROOT / "config" / "validation" / "detection-feedback" / "detection_correlation.rego"
    ).read_text(encoding="utf-8")
    assert "default correlated := false" in rego
    assert 'item.disposition == "confirmed"' in rego
    assert 'item.confidence in {"medium", "high"}' in rego
    assert "item.age_seconds <= input.max_age_seconds" in rego
