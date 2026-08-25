from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redagent_platform.agent_kernel.qualification import build_projection_catalog
from redagent_platform.agent_kernel.registry import canonical_projected_tool_sha256
from redagent_platform.campaign_service.context import (
    build_decision_context_snapshot,
    build_first_slice_semantics,
    build_first_slice_target_mapping,
    canonical_sha256,
)
from redagent_platform.campaign_service.contracts import (
    AuthorityContextV1,
    CollectionState,
    Completeness,
    Confidence,
    EvidenceFactV1,
    FindingFactV1,
    InvalidationState,
    ObservationFactV1,
    ObservationKind,
    TargetMappingStatus,
    TrustLevel,
    TruthValue,
    TypedReferenceV1,
)
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.nuclei_service.contracts import (
    NucleiBundleManifest,
    NucleiProfileId,
    canonical_profile_sha256 as canonical_nuclei_profile_sha256,
    certified_profiles as nuclei_profiles,
)
from redagent_platform.nuclei_service.repository import profile_values as nuclei_profile_values
from redagent_platform.runner_service.contracts import canonical_capability_sha256
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from redagent_platform.zap_service.contracts import (
    CertifiedProfileId,
    canonical_profile_sha256 as canonical_zap_profile_sha256,
    certified_profiles as zap_profiles,
)
from redagent_platform.zap_service.repository import profile_values as zap_profile_values


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 24, 10, 30, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def source_contracts():
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
    return zap, nuclei, bundle


def sidecars():
    zap, nuclei, bundle = source_contracts()
    zap_projection, nuclei_projection = build_projection_catalog((zap, nuclei))
    return build_first_slice_semantics(
        zap_capability=zap,
        nuclei_capability=nuclei,
        nuclei_bundle=bundle,
        zap_projection=zap_projection,
        nuclei_projection=nuclei_projection,
        promoted_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(days=7),
    )


def ref(kind: str, value: str, digest: str = SHA_A) -> TypedReferenceV1:
    return TypedReferenceV1(kind=kind, reference_id=value, sha256=digest)


def evidence(
    *,
    tenant: str = "tenant-a",
    engagement: str = "engagement-a",
    evidence_id: str = "evidence-1",
    evidence_sha256: str = SHA_B,
    binding_key_sha256: str | None = None,
    target: TypedReferenceV1 | None = None,
    resource: TypedReferenceV1 | None = None,
    finalized_at: datetime | None = None,
    observation_kind: ObservationKind = ObservationKind.SECURITY_HEADER_MISSING,
) -> EvidenceFactV1:
    zap = sidecars()[0]
    return EvidenceFactV1(
        schema_version="redagent.r119-evidence-fact/v1",
        tenant_id=tenant,
        engagement_id=engagement,
        binding_key_sha256=binding_key_sha256 or canonical_sha256(zap.binding_key),
        target=target or ref("target", "target-a", SHA_A),
        resource=resource or ref("security-header", "x-content-type-options", SHA_C),
        evidence=ref("evidence", evidence_id, evidence_sha256),
        job=ref("job", "job-1", SHA_C),
        producer_adapter_id="zap-service",
        producer_revision="2.17.0-r104.2",
        producer_schema_id="zap-alert-v1",
        observation_kind=observation_kind,
        source_definition_id="10021",
        source_matcher_id="10021",
        source_path="/passive/missing-header",
        verified=True,
        redaction_state="approved",
        finalized_at=finalized_at or NOW - timedelta(minutes=4),
        expires_at=NOW + timedelta(hours=2),
        invalidation_state=InvalidationState.CURRENT,
    )


def observation(
    *,
    fact_id: str = "observation-1",
    tenant: str = "tenant-a",
    engagement: str = "engagement-a",
    truth: TruthValue = TruthValue.TRUE,
    observed_at: datetime | None = None,
    expires_at: datetime | None = None,
    invalidation: InvalidationState = InvalidationState.CURRENT,
    completeness: Completeness = Completeness.COMPLETE,
    kind: ObservationKind = ObservationKind.SECURITY_HEADER_MISSING,
    object_ref: TypedReferenceV1 | None = None,
    evidence_ref: TypedReferenceV1 | None = None,
    binding_key_sha256: str | None = None,
    ingested_at: datetime | None = None,
) -> ObservationFactV1:
    zap = sidecars()[0]
    observed = observed_at or NOW - timedelta(minutes=5)
    return ObservationFactV1(
        schema_version="redagent.r119-observation/v1",
        fact_id=fact_id,
        tenant_id=tenant,
        engagement_id=engagement,
        binding_key_sha256=binding_key_sha256 or canonical_sha256(zap.binding_key),
        subject=ref("target", "target-a", SHA_A),
        object=object_ref or ref("security-header", "x-content-type-options", SHA_C),
        kind=kind,
        truth=truth,
        value_code=(
            "x-content-type-options"
            if kind in {ObservationKind.SECURITY_HEADER_PRESENT, ObservationKind.SECURITY_HEADER_MISSING}
            and truth in {TruthValue.TRUE, TruthValue.FALSE}
            else None
        ),
        source_adapter_id="zap-service",
        producer_revision="2.17.0-r104.2",
        producer_schema_id="zap-alert-v1",
        trust=TrustLevel.VERIFIED,
        confidence=Confidence.HIGH,
        evidence=evidence_ref or ref("evidence", "evidence-1", SHA_B),
        provenance_sha256=SHA_C,
        observed_at=observed,
        valid_from=observed,
        ingested_at=ingested_at or NOW - timedelta(minutes=4),
        expires_at=expires_at or NOW + timedelta(hours=1),
        completeness=completeness,
        invalidation_state=invalidation,
    )


def finding(
    *,
    tenant: str = "tenant-a",
    engagement: str = "engagement-a",
    fact_id: str = "finding-1",
    binding_key_sha256: str | None = None,
    target: TypedReferenceV1 | None = None,
    resource: TypedReferenceV1 | None = None,
    evidence_ref: TypedReferenceV1 | None = None,
    observed_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> FindingFactV1:
    zap = sidecars()[0]
    return FindingFactV1(
        schema_version="redagent.r119-finding-fact/v1",
        fact_id=fact_id,
        tenant_id=tenant,
        engagement_id=engagement,
        binding_key_sha256=binding_key_sha256 or canonical_sha256(zap.binding_key),
        target=target or ref("target", "target-a", SHA_A),
        resource=resource or ref("security-header", "x-content-type-options", SHA_C),
        import_session=ref("finding-import", "import-1", SHA_A),
        occurrence=ref("finding-occurrence", "occurrence-1", SHA_B),
        issue=ref("managed-issue", "issue-1", SHA_C),
        evidence=evidence_ref or ref("evidence", "evidence-1", SHA_B),
        source_adapter_id="zap-service",
        producer_revision="2.17.0-r104.2",
        source_schema_id="zap-alert-v1",
        observation_kind=ObservationKind.SECURITY_HEADER_MISSING,
        source_definition_id="10021",
        source_matcher_id="10021",
        source_path="/passive/missing-header",
        import_state="accepted",
        occurrence_state="observed",
        disposition="needs_review",
        disposition_revision=1,
        retest_state="not_requested",
        observed_at=observed_at or NOW - timedelta(minutes=5),
        updated_at=updated_at or NOW - timedelta(minutes=4),
        expires_at=NOW + timedelta(hours=2),
        invalidation_state=InvalidationState.CURRENT,
    )


def nuclei_fact_set(
    *,
    resource_id: str = "x-content-type-options",
    source_path: str = "/nuclei/missing-header",
    source_definition_id: str = "redagent-r105-missing-header",
    source_matcher_id: str = "missing-security-header",
) -> tuple[EvidenceFactV1, ObservationFactV1, FindingFactV1]:
    binding_key_sha256 = canonical_sha256(sidecars()[1].binding_key)
    resource = ref("security-header", resource_id, SHA_C)
    evidence_fact = replace(
        evidence(binding_key_sha256=binding_key_sha256, resource=resource),
        producer_adapter_id="nuclei-service",
        producer_revision="3.11.1-r105.2",
        producer_schema_id="nuclei-result-v1",
        source_definition_id=source_definition_id,
        source_matcher_id=source_matcher_id,
        source_path=source_path,
    )
    observation_fact = replace(
        observation(),
        binding_key_sha256=binding_key_sha256,
        object=resource,
        evidence=evidence_fact.evidence,
        source_adapter_id="nuclei-service",
        producer_revision="3.11.1-r105.2",
        producer_schema_id="nuclei-result-v1",
        value_code=resource_id,
    )
    finding_fact = replace(
        finding(
            binding_key_sha256=binding_key_sha256,
            resource=resource,
            evidence_ref=evidence_fact.evidence,
        ),
        source_adapter_id="nuclei-service",
        producer_revision="3.11.1-r105.2",
        source_schema_id="nuclei-result-v1",
        source_definition_id=source_definition_id,
        source_matcher_id=source_matcher_id,
        source_path=source_path,
    )
    return evidence_fact, observation_fact, finding_fact


def observation_fact_set(
    capability_id: str, kind: ObservationKind
) -> tuple[EvidenceFactV1, ObservationFactV1]:
    promoted = {item.binding_key.capability_id: item for item in sidecars()}[capability_id]
    binding_sha256 = canonical_sha256(promoted.binding_key)
    target = ref("target", "target-a", SHA_A)
    evidence_ref = ref("evidence", "evidence-1", SHA_B)
    if kind is ObservationKind.TARGET_REACHABILITY:
        resource, value_code = target, None
        source_definition_id, source_matcher_id = "target-reachability", "reachable"
    elif kind is ObservationKind.HTTP_RESPONSE_STATUS:
        resource, value_code = ref("http-response", "response-status", SHA_C), "200"
        source_definition_id, source_matcher_id = "http-response-status", "status"
    elif kind is ObservationKind.SECURITY_HEADER_PRESENT:
        resource, value_code = ref("security-header", "x-content-type-options", SHA_C), "x-content-type-options"
        source_definition_id, source_matcher_id = "security-header-presence", "10021"
    elif kind is ObservationKind.SECURITY_HEADER_MISSING:
        resource, value_code = ref("security-header", "x-content-type-options", SHA_C), "x-content-type-options"
        source_definition_id = "10021" if capability_id == "zap-controlled-runtime" else "redagent-r105-missing-header"
        source_matcher_id = "10021" if capability_id == "zap-controlled-runtime" else "missing-security-header"
    elif kind is ObservationKind.CAPABILITY_OUTCOME:
        resource, value_code = ref("capability", capability_id, binding_sha256), "succeeded"
        source_definition_id, source_matcher_id = "capability-outcome", "terminal-status"
    else:
        resource, value_code = evidence_ref, None
        source_definition_id, source_matcher_id = "evidence-identity", "finalized-evidence"

    if capability_id == "zap-controlled-runtime":
        adapter_id, producer_revision, source_path = (
            "zap-service",
            "2.17.0-r104.2",
            "/passive/missing-header",
        )
        schema_id = (
            "zap-alert-v1"
            if kind is ObservationKind.SECURITY_HEADER_MISSING
            else "zap-cleanup-v1"
            if kind is ObservationKind.EVIDENCE_IDENTITY
            else "zap-progress-v1"
        )
    else:
        adapter_id, producer_revision, source_path = (
            "nuclei-service",
            "3.11.1-r105.2",
            "/nuclei/missing-header",
        )
        schema_id = (
            "nuclei-result-v1"
            if kind is ObservationKind.SECURITY_HEADER_MISSING
            else "nuclei-cleanup-v1"
            if kind in {ObservationKind.CAPABILITY_OUTCOME, ObservationKind.EVIDENCE_IDENTITY}
            else "nuclei-gateway-v1"
        )
        if kind is ObservationKind.SECURITY_HEADER_PRESENT:
            source_matcher_id = "missing-security-header"

    evidence_fact = replace(
        evidence(),
        binding_key_sha256=binding_sha256,
        resource=resource,
        producer_adapter_id=adapter_id,
        producer_revision=producer_revision,
        producer_schema_id=schema_id,
        observation_kind=kind,
        source_definition_id=source_definition_id,
        source_matcher_id=source_matcher_id,
        source_path=source_path,
    )
    observation_fact = replace(
        observation(),
        binding_key_sha256=binding_sha256,
        object=resource,
        kind=kind,
        value_code=value_code,
        source_adapter_id=adapter_id,
        producer_revision=producer_revision,
        producer_schema_id=schema_id,
        evidence=evidence_ref,
    )
    return evidence_fact, observation_fact


def authority(target_mapping_sha256: str, *, tenant: str = "tenant-a", engagement: str = "engagement-a") -> AuthorityContextV1:
    return AuthorityContextV1(
        schema_version="redagent.r119-authority-context/v1",
        tenant_id=tenant,
        engagement_id=engagement,
        principal_id="principal-a",
        target=ref("target", "target-a", SHA_A),
        target_mapping_sha256=target_mapping_sha256,
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


def build_snapshot(**overrides):
    semantics = sidecars()
    mapping = build_first_slice_target_mapping(semantics)
    values = {
        "semantics": semantics,
        "target_mapping": mapping,
        "authority": authority(mapping.mapping_sha256),
        "collection_state": CollectionState.COMPLETE,
        "current_observations": (observation(),),
        "current_evidence_facts": (evidence(),),
        "current_finding_facts": (finding(),),
        "prior_complete_snapshot": None,
        "snapshot_at": NOW,
    }
    values.update(overrides)
    return build_decision_context_snapshot(**values)


def test_existing_owner_hashes_remain_stable_and_projection_is_canonical() -> None:
    zap, nuclei, _ = source_contracts()
    assert canonical_capability_sha256(zap) == "24c1c1a0f18a3bbf473f34107f1636c911e0711b6873988ceaaa4601b0f8c6c3"
    assert canonical_capability_sha256(nuclei) == "f4a1d955aa81f19b9afe0bf6d55daa6cc78d0533c994875214f859e97b34cd82"
    assert canonical_zap_profile_sha256(zap_profiles()[CertifiedProfileId.PASSIVE]) == "0efb350685643918582cf5905413ed867ace8e994867b764778e7f6e21dce4f2"
    assert canonical_nuclei_profile_sha256(nuclei_profiles()[NucleiProfileId.HTTP_HEADER]) == "e3650cd3d57b7a73092fb7845ed1aa8aaafc50e46061c7a2d65952890a1016f0"
    tools = build_projection_catalog((zap, nuclei))
    projection_hashes = {tool.source_capability_id: canonical_projected_tool_sha256(tool) for tool in tools}
    assert projection_hashes == {
        "zap-controlled-runtime": "bafa1c3b2bfe105407a0452408d3cf6e0dce343d331f50f6011ea087aac3eb6d",  # pragma: allowlist secret
        "nuclei-trusted-runtime": "08ff0dc9305bd11903104c09e4c18a5d7589c951a8e6c424bf4c73047b1a81b2",  # pragma: allowlist secret
    }
    assert zap_profile_values(zap_profiles()[CertifiedProfileId.PASSIVE])["profile_sha256"] == "0efb350685643918582cf5905413ed867ace8e994867b764778e7f6e21dce4f2"
    assert nuclei_profile_values(nuclei_profiles()[NucleiProfileId.HTTP_HEADER])["profile_sha256"] == "e3650cd3d57b7a73092fb7845ed1aa8aaafc50e46061c7a2d65952890a1016f0"


def test_exact_two_non_interchangeable_semantics_are_promoted() -> None:
    zap, nuclei = sidecars()
    assert (zap.binding_key.capability_id, nuclei.binding_key.capability_id) == (
        "zap-controlled-runtime",
        "nuclei-trusted-runtime",
    )
    assert zap.binding_key.profile_id == "zap-passive-v1"
    assert zap.binding_key.bundle_id is None
    assert nuclei.binding_key.profile_id == "nuclei-http-header-v1"
    assert nuclei.binding_key.bundle_id == "r105-http-header-bundle"
    assert zap.definition.observation_kinds != nuclei.definition.observation_kinds
    assert zap.definition.effects != nuclei.definition.effects
    assert zap.definition.semantics_sha256 == canonical_sha256(zap.definition.canonical_body())
    assert nuclei.definition.semantics_sha256 == canonical_sha256(nuclei.definition.canonical_body())
    assert len(zap.binding_key.normalized_output_sha256) == 64
    assert len(nuclei.binding_key.normalized_output_sha256) == 64


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("capability_id", "nuclei-trusted-runtime", "r119_zap_capability_identity_mismatch"),
        ("adapter_version", "2.17.0-r104.1", "r119_zap_capability_identity_mismatch"),
        ("supported_modes", ("zap-auth-crawl-v1",), "r119_zap_capability_digest_mismatch"),
        ("status", "revoked", "capability_status_invalid"),
    ],
)
def test_manifest_substitution_or_revocation_fails_closed(field: str, value: object, reason: str) -> None:
    zap, nuclei, bundle = source_contracts()
    zap_projection, nuclei_projection = build_projection_catalog((zap, nuclei))
    with pytest.raises(ValueError, match=reason):
        build_first_slice_semantics(
            zap_capability=replace(zap, **{field: value}),
            nuclei_capability=nuclei,
            nuclei_bundle=bundle,
            zap_projection=zap_projection,
            nuclei_projection=nuclei_projection,
            promoted_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(days=7),
        )


def test_bundle_expiry_and_substitution_fail_closed() -> None:
    zap, nuclei, bundle = source_contracts()
    zap_projection, nuclei_projection = build_projection_catalog((zap, nuclei))
    with pytest.raises(ValueError, match="r119_nuclei_bundle_not_current"):
        build_first_slice_semantics(
            zap_capability=zap,
            nuclei_capability=nuclei,
            nuclei_bundle=bundle,
            zap_projection=zap_projection,
            nuclei_projection=nuclei_projection,
            promoted_at=NOW,
            expires_at=bundle.expires_at + timedelta(seconds=1),
        )
    with pytest.raises(ValueError, match="r119_nuclei_bundle_identity_mismatch"):
        build_first_slice_semantics(
            zap_capability=zap,
            nuclei_capability=nuclei,
            nuclei_bundle=replace(bundle, bundle_sha256=SHA_A),
            zap_projection=zap_projection,
            nuclei_projection=nuclei_projection,
            promoted_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(days=7),
        )


def test_projection_drift_fails_closed_before_model_exposure() -> None:
    zap, nuclei, bundle = source_contracts()
    zap_projection, nuclei_projection = build_projection_catalog((zap, nuclei))
    with pytest.raises(ValueError, match="r119_zap_projection_digest_mismatch"):
        build_first_slice_semantics(
            zap_capability=zap,
            nuclei_capability=nuclei,
            nuclei_bundle=bundle,
            zap_projection=replace(zap_projection, description="Unreviewed projection text."),
            nuclei_projection=nuclei_projection,
            promoted_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(days=7),
        )


def test_target_mapping_is_closed_to_exact_owned_loopback_classes() -> None:
    mapping = build_first_slice_target_mapping(sidecars())
    assert mapping.status is TargetMappingStatus.PROMOTED
    assert {route.path_class for route in mapping.routes} == {
        "zap-passive-missing-header",
        "nuclei-missing-header",
    }
    assert all(route.environment_class == "owned-loopback-lab" for route in mapping.routes)
    assert mapping.mapping_sha256 == canonical_sha256(mapping.canonical_body())
    with pytest.raises(ValueError, match="r119_target_mapping_semantics_required"):
        build_first_slice_target_mapping(sidecars()[:1])


def test_snapshot_digest_is_order_independent_and_sections_are_distinct() -> None:
    first = build_snapshot()
    second = build_snapshot(
        semantics=tuple(reversed(sidecars())),
        current_evidence_facts=tuple(reversed((evidence(),))),
        current_finding_facts=tuple(reversed((finding(),))),
    )
    assert first.snapshot_sha256 == second.snapshot_sha256
    assert first.capability_section_sha256 == second.capability_section_sha256
    assert first.trusted_section_sha256 == second.trusted_section_sha256
    assert first.capability_section_sha256 != first.trusted_section_sha256


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"authority": authority(SHA_A, tenant="tenant-b")}, "r119_authority_target_mapping_mismatch"),
        ({"current_evidence_facts": (evidence(tenant="tenant-b"),)}, "r119_evidence_scope_mismatch"),
        ({"current_finding_facts": (finding(engagement="engagement-b"),)}, "r119_finding_scope_mismatch"),
        ({"current_observations": (observation(tenant="tenant-b"),)}, "r119_observation_scope_mismatch"),
    ],
)
def test_cross_scope_or_authority_drift_denies_complete_snapshot(override: dict[str, object], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        build_snapshot(**override)


def test_observation_target_drift_and_noncomplete_prior_are_denied() -> None:
    wrong_target = replace(observation(), subject=ref("target", "target-b", SHA_C))
    with pytest.raises(ValueError, match="r119_observation_target_mismatch"):
        build_snapshot(current_observations=(wrong_target,))
    partial_prior = replace(observation(fact_id="prior-partial"), completeness=Completeness.PARTIAL)
    partial_snapshot = build_snapshot(
        collection_state=CollectionState.PARTIAL,
        current_observations=(partial_prior,),
    )
    with pytest.raises(ValueError, match="r119_prior_snapshot_not_complete"):
        build_snapshot(
            collection_state=CollectionState.PARTIAL,
            prior_complete_snapshot=partial_snapshot,
        )


def test_broad_or_production_target_class_is_denied() -> None:
    mapping = build_first_slice_target_mapping(sidecars())
    with pytest.raises(ValueError, match="r119_authority_target_class_denied"):
        build_snapshot(
            authority=replace(
                authority(mapping.mapping_sha256),
                application_class="production-web-application",
            )
        )


def test_unverified_or_unlinked_output_never_enters_trusted_section() -> None:
    unverified = replace(observation(), trust=TrustLevel.UNVERIFIED)
    with pytest.raises(ValueError, match="r119_observation_untrusted"):
        build_snapshot(current_observations=(unverified,))
    with pytest.raises(ValueError, match="r119_observation_evidence_missing"):
        build_snapshot(current_evidence_facts=(), current_finding_facts=())
    with pytest.raises(ValueError, match="r119_observation_schema_denied"):
        build_snapshot(current_observations=(replace(observation(), producer_schema_id="raw-stdout"),))


def test_true_false_unknown_and_not_observed_are_distinct() -> None:
    values = tuple(
        observation(fact_id=f"observation-{truth.value}", truth=truth)
        for truth in TruthValue
    )
    snapshots = tuple(build_snapshot(current_observations=(value,)) for value in values)
    assert {snapshot.observations[0].truth for snapshot in snapshots} == set(TruthValue)
    assert len({snapshot.trusted_section_sha256 for snapshot in snapshots}) == 4


def test_partial_collection_preserves_current_prior_complete_truth() -> None:
    prior = observation(fact_id="prior-complete", observed_at=NOW - timedelta(minutes=20))
    prior_snapshot = build_snapshot(current_observations=(prior,))
    current = observation(
        fact_id="current-partial",
        truth=TruthValue.UNKNOWN,
        completeness=Completeness.PARTIAL,
    )
    snapshot = build_snapshot(
        collection_state=CollectionState.PARTIAL,
        current_observations=(current,),
        prior_complete_snapshot=prior_snapshot,
        snapshot_at=NOW + timedelta(minutes=1),
    )
    assert {fact.fact_id for fact in snapshot.observations} == {"prior-complete", "current-partial"}
    assert "preserved_prior_complete" in {item.reason for item in snapshot.dispositions}


def test_failed_collection_excludes_stale_prior_truth_auditably() -> None:
    stale = observation(fact_id="stale", expires_at=NOW + timedelta(minutes=1))
    prior_snapshot = build_snapshot(current_observations=(stale,))
    snapshot = build_snapshot(
        collection_state=CollectionState.FAILED,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        prior_complete_snapshot=prior_snapshot,
        snapshot_at=NOW + timedelta(minutes=2),
    )
    assert snapshot.observations == ()
    assert {item.reason for item in snapshot.dispositions} == {
        "excluded_stale",
        "preserved_prior_complete",
    }


def test_conflicting_assertions_are_explicit_and_not_trusted() -> None:
    true_fact = observation(fact_id="true-current", truth=TruthValue.TRUE)
    false_fact = observation(fact_id="false-current", truth=TruthValue.FALSE)
    snapshot = build_snapshot(current_observations=(true_fact, false_fact))
    assert snapshot.observations == ()
    assert len(snapshot.conflicts) == 1
    assert set(snapshot.conflicts[0].fact_sha256s) == {
        canonical_sha256(true_fact),
        canonical_sha256(false_fact),
    }


@pytest.mark.parametrize(
    ("kind", "second_value"),
    (
        (ObservationKind.HTTP_RESPONSE_STATUS, "500"),
        (ObservationKind.CAPABILITY_OUTCOME, "failed"),
    ),
)
def test_same_truth_distinct_definitive_values_are_explicit_conflicts(
    kind: ObservationKind, second_value: str
) -> None:
    evidence_fact, first = observation_fact_set("zap-controlled-runtime", kind)
    second = replace(first, fact_id="observation-2", value_code=second_value)

    snapshot = build_snapshot(
        current_observations=(first, second),
        current_evidence_facts=(evidence_fact,),
        current_finding_facts=(),
    )

    assert snapshot.observations == ()
    assert len(snapshot.conflicts) == 1
    assert set(snapshot.conflicts[0].fact_sha256s) == {
        canonical_sha256(first),
        canonical_sha256(second),
    }
    assert {
        item.reason
        for item in snapshot.dispositions
        if item.fact_sha256 in snapshot.conflicts[0].fact_sha256s
    } == {"excluded_conflict"}


def test_duplicate_fact_identity_fails_closed() -> None:
    duplicate = observation()
    with pytest.raises(ValueError, match="r119_observation_duplicate"):
        build_snapshot(current_observations=(duplicate, duplicate))
    with pytest.raises(ValueError, match="r119_observation_duplicate_assertion"):
        build_snapshot(
            current_observations=(duplicate, replace(duplicate, fact_id="observation-duplicate-2"))
        )


def test_typed_observation_object_and_finding_occurrence_cannot_be_substituted() -> None:
    with pytest.raises(ValueError, match="r119_observation_object_mismatch"):
        replace(observation(), object=ref("security-header", "content-security-policy", SHA_C))
    duplicate_finding = finding()
    with pytest.raises(ValueError, match="r119_finding_duplicate"):
        build_snapshot(
            current_finding_facts=(duplicate_finding, replace(duplicate_finding, fact_id="finding-2"))
        )


def test_authority_expiry_and_semantics_revocation_fail_closed() -> None:
    mapping = build_first_slice_target_mapping(sidecars())
    with pytest.raises(ValueError, match="r119_authority_not_current"):
        build_snapshot(authority=replace(authority(mapping.mapping_sha256), expires_at=NOW))
    revoked = replace(sidecars()[0], revoked_at=NOW - timedelta(seconds=1))
    with pytest.raises(ValueError, match="r119_semantics_revoked"):
        build_snapshot(semantics=(revoked, sidecars()[1]))


def test_bounds_reject_boolean_revision_and_excess_observations() -> None:
    with pytest.raises(ValueError, match="r119_finding_disposition_revision_invalid"):
        replace(finding(), disposition_revision=True)
    too_many = tuple(
        observation(fact_id=f"fact-{index}", truth=TruthValue.UNKNOWN)
        for index in range(257)
    )
    with pytest.raises(ValueError, match="r119_observation_count_exceeded"):
        build_snapshot(current_observations=too_many)


def test_snapshot_contract_rejects_digest_tampering() -> None:
    with pytest.raises(ValueError, match="r119_snapshot_factory_required"):
        replace(build_snapshot(), snapshot_sha256=SHA_A)


def test_direct_sidecar_or_binding_substitution_fails_at_every_boundary() -> None:
    zap, nuclei = sidecars()
    forged_definition = replace(zap.definition, effects=("unreviewed-effect",))
    forged = replace(
        zap,
        binding_key=replace(
            zap.binding_key,
            semantics_sha256=forged_definition.semantics_sha256,
            profile_sha256=SHA_A,
        ),
        definition=forged_definition,
    )
    with pytest.raises(ValueError, match="r119_zap_semantics_digest_mismatch"):
        build_first_slice_target_mapping((forged, nuclei))
    with pytest.raises(ValueError, match="r119_zap_semantics_digest_mismatch"):
        build_snapshot(semantics=(forged, nuclei))


def test_direct_snapshot_reconstruction_cannot_bypass_validated_factory() -> None:
    snapshot = build_snapshot()
    zap, nuclei = sidecars()
    forged_definition = replace(zap.definition, effects=("unreviewed-effect",))
    forged_zap = replace(
        zap,
        binding_key=replace(zap.binding_key, semantics_sha256=forged_definition.semantics_sha256),
        definition=forged_definition,
    )
    forged_semantics = (forged_zap, nuclei)
    capability_sha256 = canonical_sha256(forged_semantics)
    forged_snapshot_sha256 = canonical_sha256(
        {
            "schema_version": snapshot.schema_version,
            "snapshot_at": snapshot.snapshot_at,
            "authority_sha256": snapshot.authority_sha256,
            "target_mapping_sha256": snapshot.target_mapping_sha256,
            "capability_section_sha256": capability_sha256,
            "trusted_section_sha256": snapshot.trusted_section_sha256,
        }
    )
    with pytest.raises(ValueError, match="r119_snapshot_factory_required"):
        replace(
            snapshot,
            semantics=forged_semantics,
            capability_section_sha256=capability_sha256,
            snapshot_sha256=forged_snapshot_sha256,
        )


def test_profile_and_each_signed_bundle_field_substitution_fail_closed(monkeypatch) -> None:
    import redagent_platform.campaign_service.context as context_module

    zap, nuclei, bundle = source_contracts()
    zap_projection, nuclei_projection = build_projection_catalog((zap, nuclei))
    passive = zap_profiles()[CertifiedProfileId.PASSIVE]
    monkeypatch.setattr(
        context_module,
        "zap_profiles",
        lambda: {CertifiedProfileId.PASSIVE: replace(passive, request_limit=passive.request_limit + 1)},
    )
    with pytest.raises(ValueError, match="r119_zap_profile_digest_mismatch"):
        build_first_slice_semantics(
            zap_capability=zap,
            nuclei_capability=nuclei,
            nuclei_bundle=bundle,
            zap_projection=zap_projection,
            nuclei_projection=nuclei_projection,
            promoted_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(days=7),
        )
    monkeypatch.undo()

    substitutions = (
        {"bundle_id": "substituted-bundle"},
        {"revision": 1},
        {"template_id": "substituted-template"},
        {"template_relative_path": "templates/substituted.yaml"},
        {"template_sha256": SHA_A},
        {"bundle_sha256": SHA_A},
        {"signature_verified": False},
        {"reviewer_user_id": "substituted-reviewer"},
        {"protocol": "https"},
        {"method": "HEAD"},
        {"paths": ("/nuclei/other",)},
        {"severity": "medium"},
        {"tags": ("synthetic", "redagent")},
        {"expected_matcher_names": ("other-matcher",)},
        {"file_inventory": ("templates/other.yaml",)},
        {"promoted_at": bundle.promoted_at + timedelta(seconds=1)},
        {"expires_at": bundle.expires_at - timedelta(seconds=1)},
    )
    for changes in substitutions:
        with pytest.raises(ValueError, match="r119_nuclei_bundle_identity_mismatch|nuclei_bundle_"):
            build_first_slice_semantics(
                zap_capability=zap,
                nuclei_capability=nuclei,
                nuclei_bundle=replace(bundle, **changes),
                zap_projection=zap_projection,
                nuclei_projection=nuclei_projection,
                promoted_at=NOW - timedelta(hours=1),
                expires_at=NOW + timedelta(days=7),
            )


def test_evidence_linkage_rejects_cross_binding_target_and_resource() -> None:
    zap, nuclei = sidecars()
    nuclei_binding = canonical_sha256(nuclei.binding_key)
    nuclei_evidence = nuclei_fact_set()[0]
    with pytest.raises(ValueError, match="r119_observation_evidence_binding_mismatch"):
        build_snapshot(current_evidence_facts=(nuclei_evidence,), current_finding_facts=())
    with pytest.raises(ValueError, match="r119_evidence_target_mismatch"):
        build_snapshot(current_evidence_facts=(evidence(target=ref("target", "target-b", SHA_A)),))
    with pytest.raises(ValueError, match="r119_zap_normalized_output_mismatch"):
        build_snapshot(
            current_evidence_facts=(evidence(resource=ref("security-header", "content-security-policy", SHA_C)),),
            current_finding_facts=(),
        )
    assert canonical_sha256(zap.binding_key) != nuclei_binding


def test_exact_nuclei_normalized_output_contract_rejects_cross_header_and_path() -> None:
    valid_evidence, valid_observation, valid_finding = nuclei_fact_set()
    snapshot = build_snapshot(
        current_evidence_facts=(valid_evidence,),
        current_observations=(valid_observation,),
        current_finding_facts=(valid_finding,),
    )
    assert snapshot.observations[0].value_code == "x-content-type-options"

    for overrides in (
        {"resource_id": "content-security-policy"},
        {"source_path": "/nuclei/other"},
        {"source_definition_id": "other-template"},
        {"source_matcher_id": "other-matcher"},
    ):
        candidate_evidence, candidate_observation, candidate_finding = nuclei_fact_set(**overrides)
        with pytest.raises(ValueError, match="r119_nuclei_normalized_output_mismatch"):
            build_snapshot(
                current_evidence_facts=(candidate_evidence,),
                current_observations=(candidate_observation,),
                current_finding_facts=(candidate_finding,),
            )


def test_finding_linkage_rejects_cross_target_or_evidence_producer() -> None:
    with pytest.raises(ValueError, match="r119_finding_target_mismatch"):
        build_snapshot(
            current_finding_facts=(finding(target=ref("target", "target-b", SHA_A)),)
        )
    cross_schema = replace(evidence(), producer_schema_id="zap-progress-v1")
    with pytest.raises(ValueError, match="r119_evidence_schema_denied"):
        build_snapshot(current_evidence_facts=(cross_schema,))


def test_future_and_semantically_stale_facts_never_enter_snapshot() -> None:
    future_observation = observation(
        observed_at=NOW + timedelta(minutes=1),
        ingested_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(hours=2),
    )
    with pytest.raises(ValueError, match="r119_observation_from_future"):
        build_snapshot(current_observations=(future_observation,))
    with pytest.raises(ValueError, match="r119_evidence_from_future"):
        build_snapshot(current_evidence_facts=(evidence(finalized_at=NOW + timedelta(minutes=1)),))
    future_finding = finding(
        observed_at=NOW + timedelta(minutes=1), updated_at=NOW + timedelta(minutes=2)
    )
    with pytest.raises(ValueError, match="r119_finding_from_future"):
        build_snapshot(current_finding_facts=(future_finding,))

    stale_observation = observation(
        observed_at=NOW - timedelta(hours=2), ingested_at=NOW - timedelta(hours=2) + timedelta(minutes=1)
    )
    with pytest.raises(ValueError, match="r119_observation_semantically_stale"):
        build_snapshot(current_observations=(stale_observation,))
    with pytest.raises(ValueError, match="r119_evidence_semantically_stale"):
        build_snapshot(current_evidence_facts=(evidence(finalized_at=NOW - timedelta(hours=2)),))
    stale_finding = finding(
        observed_at=NOW - timedelta(hours=2), updated_at=NOW - timedelta(hours=2) + timedelta(minutes=1)
    )
    with pytest.raises(ValueError, match="r119_finding_semantically_stale"):
        build_snapshot(current_finding_facts=(stale_finding,))


def test_failed_collection_preserves_prior_complete_evidence_and_findings() -> None:
    prior_snapshot = build_snapshot(
        current_observations=(observation(fact_id="prior-observation"),),
        current_finding_facts=(finding(fact_id="prior-finding"),),
    )
    snapshot = build_snapshot(
        collection_state=CollectionState.FAILED,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        prior_complete_snapshot=prior_snapshot,
        snapshot_at=NOW + timedelta(minutes=1),
    )
    assert [item.evidence.reference_id for item in snapshot.evidence_facts] == ["evidence-1"]
    assert [item.fact_id for item in snapshot.finding_facts] == ["prior-finding"]
    assert "preserved_prior_complete" in {item.reason for item in snapshot.dispositions}


def test_failed_collection_propagates_expired_prior_evidence_exclusion_to_exact_dependents() -> None:
    prior_evidence = replace(evidence(), expires_at=NOW + timedelta(minutes=1))
    prior_observation = observation(fact_id="prior-observation", evidence_ref=prior_evidence.evidence)
    prior_finding = finding(fact_id="prior-finding", evidence_ref=prior_evidence.evidence)
    prior_snapshot = build_snapshot(
        current_observations=(prior_observation,),
        current_evidence_facts=(prior_evidence,),
        current_finding_facts=(prior_finding,),
    )

    snapshot = build_snapshot(
        collection_state=CollectionState.FAILED,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        prior_complete_snapshot=prior_snapshot,
        snapshot_at=NOW + timedelta(minutes=2),
    )

    assert snapshot.evidence_facts == ()
    assert snapshot.finding_facts == ()
    assert snapshot.observations == ()
    assert {
        (item.fact_sha256, item.reason) for item in snapshot.dispositions
    } == {
        (canonical_sha256(prior_evidence), "excluded_stale"),
        (canonical_sha256(prior_finding), "excluded_stale"),
        (canonical_sha256(prior_observation), "excluded_stale"),
    }


def test_current_fact_cannot_consume_excluded_prior_evidence() -> None:
    prior_evidence = replace(evidence(), expires_at=NOW + timedelta(minutes=1))
    prior_snapshot = build_snapshot(
        current_observations=(),
        current_evidence_facts=(prior_evidence,),
        current_finding_facts=(),
    )

    with pytest.raises(ValueError, match="r119_observation_evidence_missing"):
        build_snapshot(
            collection_state=CollectionState.PARTIAL,
            current_observations=(observation(fact_id="current-observation"),),
            current_evidence_facts=(),
            current_finding_facts=(),
            prior_complete_snapshot=prior_snapshot,
            snapshot_at=NOW + timedelta(minutes=2),
        )


def test_complete_collection_rejects_prior_snapshot() -> None:
    with pytest.raises(ValueError, match="r119_complete_collection_has_prior_snapshot"):
        build_snapshot(prior_complete_snapshot=build_snapshot())


def test_prior_snapshot_must_precede_and_match_current_authority() -> None:
    prior = build_snapshot()
    with pytest.raises(ValueError, match="r119_prior_snapshot_not_earlier"):
        build_snapshot(
            collection_state=CollectionState.PARTIAL,
            prior_complete_snapshot=prior,
        )
    with pytest.raises(ValueError, match="r119_prior_snapshot_authority_mismatch"):
        build_snapshot(
            collection_state=CollectionState.PARTIAL,
            prior_complete_snapshot=prior,
            snapshot_at=NOW + timedelta(minutes=1),
            authority=authority(prior.target_mapping_sha256, tenant="tenant-b"),
            current_observations=(observation(tenant="tenant-b"),),
            current_evidence_facts=(evidence(tenant="tenant-b"),),
            current_finding_facts=(finding(tenant="tenant-b"),),
        )


def test_failed_collection_rejects_every_current_lane() -> None:
    with pytest.raises(ValueError, match="r119_failed_collection_has_current_facts"):
        build_snapshot(collection_state=CollectionState.FAILED, current_observations=())


@pytest.mark.parametrize(
    ("kind", "object_ref"),
    [
        (ObservationKind.TARGET_REACHABILITY, ref("raw-object", "raw", SHA_C)),
        (ObservationKind.HTTP_RESPONSE_STATUS, ref("raw-object", "raw", SHA_C)),
        (ObservationKind.CAPABILITY_OUTCOME, ref("raw-object", "raw", SHA_C)),
        (ObservationKind.EVIDENCE_IDENTITY, ref("raw-object", "raw", SHA_C)),
    ],
)
def test_every_non_header_observation_kind_has_closed_object_contract(
    kind: ObservationKind, object_ref: TypedReferenceV1
) -> None:
    with pytest.raises(ValueError, match="r119_observation_object_mismatch"):
        observation(kind=kind, truth=TruthValue.UNKNOWN, object_ref=object_ref)


@pytest.mark.parametrize(
    ("capability_id", "kind"),
    [
        ("zap-controlled-runtime", ObservationKind.TARGET_REACHABILITY),
        ("zap-controlled-runtime", ObservationKind.HTTP_RESPONSE_STATUS),
        ("zap-controlled-runtime", ObservationKind.SECURITY_HEADER_PRESENT),
        ("zap-controlled-runtime", ObservationKind.SECURITY_HEADER_MISSING),
        ("zap-controlled-runtime", ObservationKind.CAPABILITY_OUTCOME),
        ("zap-controlled-runtime", ObservationKind.EVIDENCE_IDENTITY),
        ("nuclei-trusted-runtime", ObservationKind.TARGET_REACHABILITY),
        ("nuclei-trusted-runtime", ObservationKind.SECURITY_HEADER_PRESENT),
        ("nuclei-trusted-runtime", ObservationKind.SECURITY_HEADER_MISSING),
        ("nuclei-trusted-runtime", ObservationKind.CAPABILITY_OUTCOME),
        ("nuclei-trusted-runtime", ObservationKind.EVIDENCE_IDENTITY),
    ],
)
def test_every_declared_binding_observation_kind_is_reachable(
    capability_id: str, kind: ObservationKind
) -> None:
    evidence_fact, observation_fact = observation_fact_set(capability_id, kind)
    snapshot = build_snapshot(
        current_evidence_facts=(evidence_fact,),
        current_observations=(observation_fact,),
        current_finding_facts=(),
    )
    assert snapshot.observations == (observation_fact,)


def test_prior_explicit_conflict_and_same_identity_new_fact_remain_non_trusted() -> None:
    true_fact = observation(fact_id="prior-true", truth=TruthValue.TRUE)
    false_fact = observation(fact_id="prior-false", truth=TruthValue.FALSE)
    prior = build_snapshot(current_observations=(true_fact, false_fact))
    assert len(prior.conflicts) == 1

    failed = build_snapshot(
        collection_state=CollectionState.FAILED,
        current_observations=(),
        current_evidence_facts=(),
        current_finding_facts=(),
        prior_complete_snapshot=prior,
        snapshot_at=NOW + timedelta(minutes=1),
    )
    assert failed.observations == ()
    assert failed.conflicts == prior.conflicts
    assert "excluded_conflict" in {item.reason for item in failed.dispositions}

    new_fact = observation(fact_id="current-same-identity", truth=TruthValue.UNKNOWN)
    partial = build_snapshot(
        collection_state=CollectionState.PARTIAL,
        current_observations=(new_fact,),
        prior_complete_snapshot=prior,
        snapshot_at=NOW + timedelta(minutes=1),
    )
    assert partial.observations == ()
    assert len(partial.conflicts[0].fact_sha256s) == 3
    assert canonical_sha256(new_fact) in partial.conflicts[0].fact_sha256s


def test_same_evidence_id_with_different_digest_is_a_conflict() -> None:
    first = evidence()
    second = evidence(evidence_sha256=SHA_C)
    with pytest.raises(ValueError, match="r119_evidence_identity_conflict"):
        build_snapshot(current_evidence_facts=(first, second))


def test_r119_package_has_no_io_writer_migration_or_r120_surface() -> None:
    package = ROOT / "redagent_platform" / "campaign_service"
    # compat_123 adds separately named persistence/relay modules; keep the compat_119 owners themselves pure.
    source = "\n".join(
        (package / name).read_text(encoding="utf-8")
        for name in ("__init__.py", "contracts.py", "context.py", "strategy.py")
    )
    forbidden = (
        "sqlalchemy",
        "temporalio",
        "subprocess",
        "socket",
        "requests",
        "httpx",
        "EvidenceRepository",
        "FindingOperationsRepository",
        "RunnerDispatcher",
        "import_batch(",
    )
    assert all(token not in source for token in forbidden)
    assert not any("compat_119" in path.name.lower() for path in (ROOT / "migrations" / "versions").glob("*.py"))
    assert not (ROOT / "redagent_platform" / "compat_120").exists()
    assert not (package / "r120.py").exists()
