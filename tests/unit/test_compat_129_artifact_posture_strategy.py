from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from redagent_platform.agent_kernel.qualification import build_projection_catalog
from redagent_platform.artifact_pipeline.capability import build_artifact_capability
from redagent_platform.artifact_pipeline.profiles import certified_profiles
from redagent_platform.artifact_pipeline.promotion import verify_current_artifact_promotion
from redagent_platform.campaign_service import context as campaign_context
from redagent_platform.campaign_service import strategy as campaign_strategy
from redagent_platform.campaign_service.contracts import (
    AuthorityContextV1,
    CollectionState,
    StrategyBudgetV1,
    StrategyObjectiveKind,
    StrategyObjectiveV1,
    StrategyOutcome,
    StrategySignalsV1,
    TypedReferenceV1,
    canonical_sha256,
)
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.nuclei_service.contracts import NucleiBundleManifest
from redagent_platform.runner_service.contracts import canonical_capability_sha256
from redagent_platform.zap_service.capability import build_zap_capability_manifest


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64


def _facts():
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
    artifact_promotion = verify_current_artifact_promotion(ROOT, now=NOW)
    artifact = build_artifact_capability(
        artifact_receipt_id=artifact_promotion.receipt.receipt_id,
        source_digest=artifact_promotion.receipt.image_digest,
    )
    projections = build_projection_catalog((zap, nuclei, artifact))
    first_slice = campaign_context.build_first_slice_semantics(
        zap_capability=zap,
        nuclei_capability=nuclei,
        nuclei_bundle=bundle,
        zap_projection=projections[0],
        nuclei_projection=projections[1],
        promoted_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(days=7),
    )
    semantics = campaign_context.promote_artifact_posture_semantics(
        first_slice_semantics=first_slice,
        artifact_capability=artifact,
        artifact_projection=projections[2],
        profile=certified_profiles()["r110-repository-snapshot-v1"],
        promoted_at=artifact_promotion.receipt.verified_at,
        expires_at=artifact_promotion.receipt.expires_at,
    )
    mapping = campaign_context.build_artifact_posture_target_mapping(semantics)
    authority = AuthorityContextV1(
        schema_version="redagent.r119-authority-context/v1",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        principal_id="principal-a",
        target=TypedReferenceV1(kind="target", reference_id="target-a", sha256=SHA_A),
        target_mapping_sha256=mapping.mapping_sha256,
        target_class="repository-snapshot",
        application_class="canonical-artifact-binding",
        environment_class="data-only-sandbox",
        url_class="no-url",
        roe_version_id="roe-v1",
        roe_sha256=SHA_A,
        roe_status="approved",
        policy_decision_id="policy-decision-1",
        policy_revision="artifact-posture-policy-v2",
        policy_sha256=SHA_B,
        policy_status="allowed",
        issued_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(minutes=30),
    )
    snapshot = campaign_context.build_decision_context_snapshot(
        semantics=semantics,
        target_mapping=mapping,
        authority=authority,
        collection_state=CollectionState.COMPLETE,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        prior_complete_snapshot=None,
        snapshot_at=NOW,
    )
    receipt_ref = TypedReferenceV1(
        kind="artifact-receipt",
        reference_id=artifact_promotion.receipt.receipt_id,
        sha256=canonical_capability_sha256(artifact),
    )
    return snapshot, authority, projections, receipt_ref


def _objective(
    kind: StrategyObjectiveKind,
    *,
    receipt: TypedReferenceV1 | None,
) -> StrategyObjectiveV1:
    return StrategyObjectiveV1(
        schema_version=(
            "redagent.artifact-posture-objective/v2"
            if kind is StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE
            else "redagent.r121-objective/v1"
        ),
        objective_id="objective-1",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        target=TypedReferenceV1(kind="target", reference_id="target-a", sha256=SHA_A),
        kind=kind,
        header_code=(
            "x-content-type-options"
            if kind is StrategyObjectiveKind.SECURITY_HEADER_ASSERTION
            else None
        ),
        require_corroboration=False,
        artifact_receipt=receipt,
    )


def _decide(objective: StrategyObjectiveV1):
    snapshot, authority, projections, _ = _facts()
    return campaign_strategy.decide_strategy(
        objective=objective,
        snapshot=snapshot,
        authority=authority,
        projections=projections,
        budget=StrategyBudgetV1(
            max_elapsed_seconds=60,
            max_operations=1,
            max_targets=1,
            max_evidence_bytes=8192,
            max_depth=1,
        ),
        signals=StrategySignalsV1(),
        model_proposal=None,
        now=NOW + timedelta(minutes=1),
    )


def test_exact_registry_and_current_receipt_select_only_zero_execution_artifact_posture() -> None:
    snapshot, _, projections, receipt_ref = _facts()
    receipt, plan = _decide(
        _objective(StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE, receipt=receipt_ref)
    )

    registry = closed_execution_registry()
    artifact = registry["artifact-posture@1"]
    projected = next(item for item in projections if item.source_capability_id == "artifact-posture")
    assert tuple(registry) == (
        "artifact-posture@1",
        "nuclei-trusted-runtime@2",
        "zap-controlled-runtime@2",
    )
    assert (artifact.profile_id, artifact.approval_tier, artifact.requires_secret) == (
        "r110-repository-snapshot-v1",
        1,
        False,
    )
    assert projected.network_mode == "none" and projected.credential_class == "none"
    assert snapshot.schema_version == "redagent.artifact-posture-decision-context/v2"
    assert receipt.schema_version == "redagent.artifact-posture-strategy-receipt/v2"
    assert receipt.decision_table_revision == campaign_strategy.ARTIFACT_DECISION_TABLE_REVISION == 2
    assert receipt.outcome is StrategyOutcome.SELECT
    assert len(receipt.candidates) == 3
    assert plan is not None
    assert plan.schema_version == "redagent.artifact-posture-plan-revision/v2"
    assert plan.primary.capability_id == "artifact-posture"
    assert plan.successor is None and plan.depth == 1
    dispositions = {item.capability_id: item for item in receipt.candidates}
    assert dispositions["artifact-posture"].eligible is True
    assert dispositions["zap-controlled-runtime"].reason == "objective_incompatible"
    assert dispositions["nuclei-trusted-runtime"].reason == "objective_incompatible"


@pytest.mark.parametrize(
    ("kind", "receipt_kind", "expected", "expected_outcome"),
    [
        ("repository_snapshot_posture", "artifact-receipt-inconclusive", "artifact_receipt_inconclusive", StrategyOutcome.SKIP),
        ("repository_snapshot_posture", "artifact-receipt-stale", "artifact_receipt_stale", StrategyOutcome.STOP),
        ("repository_snapshot_posture", "artifact-receipt-denied", "artifact_receipt_denied", StrategyOutcome.STOP),
        ("repository_snapshot_posture", "artifact-receipt", "artifact_receipt_mismatch", StrategyOutcome.STOP),
    ],
)
def test_repository_objective_fails_closed_for_inconclusive_or_mismatched_receipt(
    kind: str, receipt_kind: str, expected: str, expected_outcome: StrategyOutcome
) -> None:
    _, _, _, current = _facts()
    invalid = replace(
        current,
        kind=receipt_kind,
        sha256=(current.sha256 if "inconclusive" in receipt_kind else "c" * 64),
    )
    receipt, plan = _decide(_objective(StrategyObjectiveKind(kind), receipt=invalid))
    assert receipt.outcome is expected_outcome
    assert receipt.reason == expected
    assert plan is None
    assert all(not item.eligible for item in receipt.candidates)


def test_objective_schema_requires_current_receipt_shape_and_policy_corpus_is_frozen() -> None:
    missing, plan = _decide(
        _objective(StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE, receipt=None)
    )
    assert missing.outcome is StrategyOutcome.STOP
    assert missing.reason == "artifact_receipt_missing" and plan is None
    with pytest.raises(ValueError, match="r119_authority_denied"):
        replace(_facts()[1], policy_status="denied")

    corpus = json.loads(
        (ROOT / "config" / "artifact-posture-policy-v2.json").read_text(encoding="utf-8")
    )
    assert corpus["schema"] == "redagent.artifact-posture-policy-corpus/v2"
    assert corpus["decision_table_revision"] == 2
    assert tuple(item["case_id"] for item in corpus["cases"]) == (
        "authorized-repository-select",
        "missing-receipt-deny",
        "stale-receipt-deny",
        "denied-receipt-deny",
        "inconclusive-receipt-skip",
        "http-artifact-ineligible",
        "header-artifact-ineligible",
    )
    corpus_body = dict(corpus)
    asserted_sha256 = corpus_body.pop("corpus_sha256")
    assert canonical_sha256(corpus_body) == asserted_sha256
