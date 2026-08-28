"""Pure construction of the compat_119 capability and trusted-fact snapshot sections."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from redagent_platform.agent_kernel.contracts import ProjectedTool, ToolKind
from redagent_platform.agent_kernel.registry import canonical_projected_tool_sha256
from redagent_platform.artifact_pipeline.contracts import ArtifactKind, ArtifactProfile
from redagent_platform.artifact_pipeline.profiles import canonical_profile_sha256 as canonical_artifact_profile_sha256
from redagent_platform.campaign_service.contracts import (
    AuthorityContextV1,
    CapabilityBindingKeyV1,
    CapabilitySemanticsDefinitionV1,
    CollectionState,
    Completeness,
    DecisionContextSnapshotV1,
    DetectionObservationV1,
    EvidenceFactV1,
    FactConflictV1,
    FactDispositionV1,
    FindingFactV1,
    InvalidationState,
    ObservationFactV1,
    ObservationKind,
    PromotedCapabilitySemanticsV1,
    TargetMappingStatus,
    TargetMappingV1,
    TargetRouteV1,
    TrustLevel,
    TruthValue,
    _validated_decision_context_snapshot,
    canonical_sha256,
)
from redagent_platform.campaign_service.detection_feedback import (
    validate_detection_snapshot_inputs,
)
from redagent_platform.nuclei_service.contracts import (
    CURRENT_R105_HTTP_HEADER_BUNDLE_SHA256,
    NucleiBundleManifest,
    NucleiProfileId,
    canonical_profile_sha256 as canonical_nuclei_profile_sha256,
    certified_profiles as nuclei_profiles,
)
from redagent_platform.runner_service.contracts import (
    ExecutionCapabilityManifest,
    canonical_capability_sha256,
)
from redagent_platform.zap_service.contracts import (
    CertifiedProfileId,
    canonical_profile_sha256 as canonical_zap_profile_sha256,
    certified_profiles as zap_profiles,
)


_ZAP_IDENTITY = (
    "zap-controlled-runtime",
    2,
    "zap-service",
    "2.17.0-r104.2",
    "zap-certified-profile-v1",
)
_NUCLEI_IDENTITY = (
    "nuclei-trusted-runtime",
    2,
    "nuclei-service",
    "3.11.1-r105.2",
    "nuclei-certified-profile-v1",
)
_NUCLEI_BUNDLE_SHA256 = CURRENT_R105_HTTP_HEADER_BUNDLE_SHA256
_ARTIFACT_IDENTITY = (
    "artifact-posture",
    1,
    "redagent-canonical-artifact",
    "1.0.0-r110.1",
    "artifact-certified-plan-v1",
)
_EXPECTED_PROFILE_SHA256 = {
    "zap-controlled-runtime": "0efb350685643918582cf5905413ed867ace8e994867b764778e7f6e21dce4f2",  # pragma: allowlist secret
    "nuclei-trusted-runtime": "e3650cd3d57b7a73092fb7845ed1aa8aaafc50e46061c7a2d65952890a1016f0",  # pragma: allowlist secret
    "artifact-posture": "1e0e70f9c6b63eb40606e1081cede810c748369b760d642e2b3f87a7effaa3e8",  # pragma: allowlist secret
}
_EXPECTED_MANIFEST_SHA256 = {
    "zap-controlled-runtime": "24c1c1a0f18a3bbf473f34107f1636c911e0711b6873988ceaaa4601b0f8c6c3",  # pragma: allowlist secret
    "nuclei-trusted-runtime": "f4a1d955aa81f19b9afe0bf6d55daa6cc78d0533c994875214f859e97b34cd82",  # pragma: allowlist secret
    "artifact-posture": "968c0367f5f61c6c341b452287881b64b93efda49da657798e33f2e4bece4f86",  # pragma: allowlist secret
}
_EXPECTED_PROJECTION_SHA256 = {
    "zap-controlled-runtime": "bafa1c3b2bfe105407a0452408d3cf6e0dce343d331f50f6011ea087aac3eb6d",  # pragma: allowlist secret
    "nuclei-trusted-runtime": "08ff0dc9305bd11903104c09e4c18a5d7589c951a8e6c424bf4c73047b1a81b2",  # pragma: allowlist secret
    "artifact-posture": "dbc5eef3b0cf3b46681a725d0f81d7d4c8932b9e9e1b30de665d9e63b272930f",  # pragma: allowlist secret
}
_EXPECTED_SEMANTICS_SHA256 = {
    "zap-controlled-runtime": "af1297769f1d9af7ca9cbec39dc08bf561d3a2dd322c6936c2c8eff6b862e2f9",  # pragma: allowlist secret
    "nuclei-trusted-runtime": "b4814f92bbe4b94537e70da43b0157f65562bcfd8e8e6f2b576d35417c3a833b",  # pragma: allowlist secret
}
_EXPECTED_BINDING_SHA256 = {
    "zap-controlled-runtime": "4021073fac5b11b645065410c19153d8ed997bd5ce0fc31863c296f6d9afb242",  # pragma: allowlist secret
    "nuclei-trusted-runtime": "fee05ae6b093cc53e633d6372553e2fc3c28af30c30c821813d5b636d822e81c",  # pragma: allowlist secret
}
_EXPECTED_NUCLEI_BUNDLE = (
    "r105-http-header-bundle",
    2,
    "redagent-r105-missing-header",
    "templates/redagent-r105-missing-header.yaml",
    "7f0689cdad1a2daf912de264a4c4894f7cd136f4936767bad06ea8d10d8965a8",  # pragma: allowlist secret
    _NUCLEI_BUNDLE_SHA256,
    True,
    "redagent-r105-independent-review",
    "http",
    "GET",
    ("/nuclei/missing-header",),
    "low",
    ("redagent", "synthetic"),
    ("missing-security-header",),
    ("templates/redagent-r105-missing-header.yaml",),
    "2026-08-24T17:03:42+08:00",
    "2026-09-23T17:03:42+08:00",
)
_FIRST_SLICE_BINDINGS = frozenset({_ZAP_IDENTITY[0], _NUCLEI_IDENTITY[0]})
_EXPECTED_BINDINGS = frozenset((*_FIRST_SLICE_BINDINGS, _ARTIFACT_IDENTITY[0]))
_NORMALIZED_OUTPUT_CONTRACTS = {
    "zap-controlled-runtime": {
        ObservationKind.TARGET_REACHABILITY.value: (
            "zap-service", "2.17.0-r104.2", "zap-progress-v1",
            "target-reachability", "reachable", "/passive/missing-header", "target", "$target",
        ),
        ObservationKind.HTTP_RESPONSE_STATUS.value: (
            "zap-service", "2.17.0-r104.2", "zap-progress-v1",
            "http-response-status", "status", "/passive/missing-header",
            "http-response", "response-status",
        ),
        ObservationKind.SECURITY_HEADER_PRESENT.value: (
            "zap-service", "2.17.0-r104.2", "zap-progress-v1",
            "security-header-presence", "10021", "/passive/missing-header",
            "security-header", "x-content-type-options",
        ),
        ObservationKind.SECURITY_HEADER_MISSING.value: (
            "zap-service", "2.17.0-r104.2", "zap-alert-v1",
            "10021", "10021", "/passive/missing-header",
            "security-header", "x-content-type-options",
        ),
        ObservationKind.CAPABILITY_OUTCOME.value: (
            "zap-service", "2.17.0-r104.2", "zap-progress-v1",
            "capability-outcome", "terminal-status", "/passive/missing-header",
            "capability", "$capability",
        ),
        ObservationKind.EVIDENCE_IDENTITY.value: (
            "zap-service", "2.17.0-r104.2", "zap-cleanup-v1",
            "evidence-identity", "finalized-evidence", "/passive/missing-header",
            "evidence", "$evidence",
        ),
    },
    "nuclei-trusted-runtime": {
        ObservationKind.TARGET_REACHABILITY.value: (
            "nuclei-service", "3.11.1-r105.2", "nuclei-gateway-v1",
            "target-reachability", "reachable", "/nuclei/missing-header", "target", "$target",
        ),
        ObservationKind.SECURITY_HEADER_PRESENT.value: (
            "nuclei-service", "3.11.1-r105.2", "nuclei-gateway-v1",
            "security-header-presence", "missing-security-header", "/nuclei/missing-header",
            "security-header", "x-content-type-options",
        ),
        ObservationKind.SECURITY_HEADER_MISSING.value: (
            "nuclei-service", "3.11.1-r105.2", "nuclei-result-v1",
            "redagent-r105-missing-header", "missing-security-header", "/nuclei/missing-header",
            "security-header", "x-content-type-options",
        ),
        ObservationKind.CAPABILITY_OUTCOME.value: (
            "nuclei-service", "3.11.1-r105.2", "nuclei-cleanup-v1",
            "capability-outcome", "terminal-status", "/nuclei/missing-header",
            "capability", "$capability",
        ),
        ObservationKind.EVIDENCE_IDENTITY.value: (
            "nuclei-service", "3.11.1-r105.2", "nuclei-cleanup-v1",
            "evidence-identity", "finalized-evidence", "/nuclei/missing-header",
            "evidence", "$evidence",
        ),
    },
    "artifact-posture": {
        ObservationKind.CAPABILITY_OUTCOME.value: (
            "redagent-canonical-artifact",
            "1.0.0-r110.1",
            "artifact-static-result-v1",
            "capability-outcome",
            "terminal-status",
            "/repository-snapshot/posture",
            "capability",
            "$capability",
        ),
        ObservationKind.EVIDENCE_IDENTITY.value: (
            "redagent-canonical-artifact",
            "1.0.0-r110.1",
            "artifact-cleanup-v1",
            "evidence-identity",
            "finalized-evidence",
            "/repository-snapshot/posture",
            "evidence",
            "$evidence",
        ),
    },
}
_MAX_FACTS = 256


def build_first_slice_semantics(
    *,
    zap_capability: ExecutionCapabilityManifest,
    nuclei_capability: ExecutionCapabilityManifest,
    nuclei_bundle: NucleiBundleManifest,
    zap_projection: ProjectedTool,
    nuclei_projection: ProjectedTool,
    promoted_at: datetime,
    expires_at: datetime,
) -> tuple[PromotedCapabilitySemanticsV1, ...]:
    """Promote only the exact compat_104 passive and compat_105 fixed-header bindings."""
    _validate_window(promoted_at, expires_at)
    if expires_at > promoted_at + timedelta(days=30):
        raise ValueError("r119_semantics_window_exceeded")
    _validate_capability(zap_capability, expected=_ZAP_IDENTITY, label="zap")
    _validate_capability(nuclei_capability, expected=_NUCLEI_IDENTITY, label="nuclei")
    observed_bundle = (
        nuclei_bundle.bundle_id,
        nuclei_bundle.revision,
        nuclei_bundle.template_id,
        nuclei_bundle.template_relative_path,
        nuclei_bundle.template_sha256,
        nuclei_bundle.bundle_sha256,
        nuclei_bundle.signature_verified,
        nuclei_bundle.reviewer_user_id,
        nuclei_bundle.protocol,
        nuclei_bundle.method,
        nuclei_bundle.paths,
        nuclei_bundle.severity,
        nuclei_bundle.tags,
        nuclei_bundle.expected_matcher_names,
        nuclei_bundle.file_inventory,
        nuclei_bundle.promoted_at.isoformat(),
        nuclei_bundle.expires_at.isoformat(),
    )
    if observed_bundle != _EXPECTED_NUCLEI_BUNDLE:
        raise ValueError("r119_nuclei_bundle_identity_mismatch")
    if nuclei_bundle.promoted_at > promoted_at or nuclei_bundle.expires_at < expires_at:
        raise ValueError("r119_nuclei_bundle_not_current")

    zap_profile = zap_profiles()[CertifiedProfileId.PASSIVE]
    nuclei_profile = nuclei_profiles()[NucleiProfileId.HTTP_HEADER]
    if canonical_zap_profile_sha256(zap_profile) != _EXPECTED_PROFILE_SHA256[_ZAP_IDENTITY[0]]:
        raise ValueError("r119_zap_profile_digest_mismatch")
    if canonical_nuclei_profile_sha256(nuclei_profile) != _EXPECTED_PROFILE_SHA256[_NUCLEI_IDENTITY[0]]:
        raise ValueError("r119_nuclei_profile_digest_mismatch")
    _validate_projection(zap_projection, capability=zap_capability, label="zap")
    _validate_projection(nuclei_projection, capability=nuclei_capability, label="nuclei")
    projections = {
        zap_projection.source_capability_id: zap_projection,
        nuclei_projection.source_capability_id: nuclei_projection,
    }
    if set(projections) != _FIRST_SLICE_BINDINGS:
        raise ValueError("r119_projection_identity_mismatch")

    zap_definition = CapabilitySemanticsDefinitionV1(
        schema_version="redagent.r119-capability-semantics/v1",
        semantics_id="zap-passive-http-posture-v1",
        revision=1,
        target_class="owned-http-application",
        environment_class="owned-loopback-lab",
        preconditions=(
            "target-attested",
            "roe-current",
            "policy-allowed",
            "passive-profile-current",
        ),
        observation_kinds=(
            ObservationKind.TARGET_REACHABILITY,
            ObservationKind.HTTP_RESPONSE_STATUS,
            ObservationKind.SECURITY_HEADER_PRESENT,
            ObservationKind.SECURITY_HEADER_MISSING,
            ObservationKind.CAPABILITY_OUTCOME,
            ObservationKind.EVIDENCE_IDENTITY,
        ),
        effects=("passive-http-observation",),
        risk_class="low-passive",
        noise_class="bounded-low",
        cost_class="bounded-small",
        duration_class="under-three-minutes",
        evidence_schemas=("zap-alert-v1", "zap-progress-v1", "zap-cleanup-v1"),
        cleanup="no-target-mutation",
        compensation="stop-and-discard-unverified",
        stop_conditions=("scope-drift", "authority-drift", "evidence-failure", "timeout"),
        freshness_seconds=3600,
        qualification="r104-owned-loopback-certified",
        deprecation="review-before-source-revision-change",
    )
    nuclei_definition = CapabilitySemanticsDefinitionV1(
        schema_version="redagent.r119-capability-semantics/v1",
        semantics_id="nuclei-fixed-header-assertion-v1",
        revision=1,
        target_class="owned-http-application",
        environment_class="owned-loopback-lab",
        preconditions=(
            "target-attested",
            "roe-current",
            "policy-allowed",
            "signed-bundle-current",
        ),
        observation_kinds=(
            ObservationKind.TARGET_REACHABILITY,
            ObservationKind.SECURITY_HEADER_PRESENT,
            ObservationKind.SECURITY_HEADER_MISSING,
            ObservationKind.CAPABILITY_OUTCOME,
            ObservationKind.EVIDENCE_IDENTITY,
        ),
        effects=("fixed-header-assertion",),
        risk_class="low-fixed-template",
        noise_class="single-request-low",
        cost_class="bounded-minimal",
        duration_class="under-one-minute",
        evidence_schemas=("nuclei-result-v1", "nuclei-gateway-v1", "nuclei-cleanup-v1"),
        cleanup="no-target-mutation",
        compensation="stop-and-discard-unverified",
        stop_conditions=("scope-drift", "authority-drift", "bundle-drift", "timeout"),
        freshness_seconds=3600,
        qualification="r105-owned-loopback-certified",
        deprecation="review-before-bundle-or-source-revision-change",
    )

    zap_binding = CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1",
        capability_id=zap_capability.capability_id,
        capability_revision=zap_capability.revision,
        execution_manifest_sha256=canonical_capability_sha256(zap_capability),
        adapter_id=zap_capability.adapter_id,
        adapter_version=zap_capability.adapter_version,
        profile_id=zap_profile.profile_id.value,
        profile_revision=1,
        profile_sha256=canonical_zap_profile_sha256(zap_profile),
        bundle_id=None,
        bundle_revision=None,
        bundle_sha256=None,
        semantics_revision=zap_definition.revision,
        semantics_sha256=zap_definition.semantics_sha256,
        normalized_output_sha256=canonical_sha256(
            _NORMALIZED_OUTPUT_CONTRACTS[zap_capability.capability_id]
        ),
        projection_revision=1,
        projection_sha256=canonical_projected_tool_sha256(projections[zap_capability.capability_id]),
    )
    nuclei_binding = CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1",
        capability_id=nuclei_capability.capability_id,
        capability_revision=nuclei_capability.revision,
        execution_manifest_sha256=canonical_capability_sha256(nuclei_capability),
        adapter_id=nuclei_capability.adapter_id,
        adapter_version=nuclei_capability.adapter_version,
        profile_id=nuclei_profile.profile_id.value,
        profile_revision=1,
        profile_sha256=canonical_nuclei_profile_sha256(nuclei_profile),
        bundle_id=nuclei_bundle.bundle_id,
        bundle_revision=nuclei_bundle.revision,
        bundle_sha256=nuclei_bundle.bundle_sha256,
        semantics_revision=nuclei_definition.revision,
        semantics_sha256=nuclei_definition.semantics_sha256,
        normalized_output_sha256=canonical_sha256(
            _NORMALIZED_OUTPUT_CONTRACTS[nuclei_capability.capability_id]
        ),
        projection_revision=1,
        projection_sha256=canonical_projected_tool_sha256(projections[nuclei_capability.capability_id]),
    )
    return (
        PromotedCapabilitySemanticsV1(
            schema_version="redagent.r119-promoted-semantics/v1",
            binding_key=zap_binding,
            definition=zap_definition,
            promotion_status="promoted",
            promoted_at=promoted_at,
            expires_at=expires_at,
        ),
        PromotedCapabilitySemanticsV1(
            schema_version="redagent.r119-promoted-semantics/v1",
            binding_key=nuclei_binding,
            definition=nuclei_definition,
            promotion_status="promoted",
            promoted_at=promoted_at,
            expires_at=expires_at,
        ),
    )


def promote_artifact_posture_semantics(
    *,
    first_slice_semantics: tuple[PromotedCapabilitySemanticsV1, ...],
    artifact_capability: ExecutionCapabilityManifest,
    artifact_projection: ProjectedTool,
    profile: ArtifactProfile,
    promoted_at: datetime,
    expires_at: datetime,
) -> tuple[PromotedCapabilitySemanticsV1, ...]:
    """Add only the exact current R110 repository-snapshot zero-execution binding."""
    indexed = _index_semantics(first_slice_semantics)
    if set(indexed) != _FIRST_SLICE_BINDINGS:
        raise ValueError("artifact_posture_first_slice_required")
    _validate_window(promoted_at, expires_at)
    if expires_at > promoted_at + timedelta(days=30):
        raise ValueError("artifact_posture_semantics_window_exceeded")
    _validate_capability(
        artifact_capability,
        expected=_ARTIFACT_IDENTITY,
        label="artifact",
    )
    if (
        profile.profile_id != "r110-repository-snapshot-v1"
        or profile.artifact_kind is not ArtifactKind.REPOSITORY_SNAPSHOT
        or canonical_artifact_profile_sha256(profile)
        != _EXPECTED_PROFILE_SHA256["artifact-posture"]
        or artifact_capability.network_mode.value != "none"
        or artifact_capability.credential_class.value != "none"
        or artifact_capability.network_mode.value == "host"
    ):
        raise ValueError("artifact_posture_profile_or_execution_boundary_invalid")
    _validate_projection(
        artifact_projection,
        capability=artifact_capability,
        label="artifact",
    )
    definition = _artifact_posture_definition()
    binding = CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1",
        capability_id=artifact_capability.capability_id,
        capability_revision=artifact_capability.revision,
        execution_manifest_sha256=canonical_capability_sha256(artifact_capability),
        adapter_id=artifact_capability.adapter_id,
        adapter_version=artifact_capability.adapter_version,
        profile_id=profile.profile_id,
        profile_revision=1,
        profile_sha256=canonical_artifact_profile_sha256(profile),
        bundle_id=None,
        bundle_revision=None,
        bundle_sha256=None,
        semantics_revision=definition.revision,
        semantics_sha256=definition.semantics_sha256,
        normalized_output_sha256=canonical_sha256(
            _NORMALIZED_OUTPUT_CONTRACTS["artifact-posture"]
        ),
        projection_revision=1,
        projection_sha256=canonical_projected_tool_sha256(artifact_projection),
    )
    sidecar = PromotedCapabilitySemanticsV1(
        schema_version="redagent.r119-promoted-semantics/v1",
        binding_key=binding,
        definition=definition,
        promotion_status="promoted",
        promoted_at=promoted_at,
        expires_at=expires_at,
    )
    return tuple((*first_slice_semantics, sidecar))


def _artifact_posture_definition() -> CapabilitySemanticsDefinitionV1:
    return CapabilitySemanticsDefinitionV1(
        schema_version="redagent.r119-capability-semantics/v1",
        semantics_id="artifact-repository-snapshot-posture-v1",
        revision=1,
        target_class="repository-snapshot",
        environment_class="data-only-sandbox",
        preconditions=(
            "artifact-receipt-current",
            "roe-current",
            "policy-allowed",
            "repository-snapshot-profile-current",
        ),
        observation_kinds=(
            ObservationKind.CAPABILITY_OUTCOME,
            ObservationKind.EVIDENCE_IDENTITY,
        ),
        effects=("repository-snapshot-posture",),
        risk_class="zero-execution",
        noise_class="none",
        cost_class="bounded-minimal",
        duration_class="under-one-minute",
        evidence_schemas=(
            "artifact-manifest-v1",
            "artifact-component-v1",
            "artifact-static-result-v1",
            "artifact-cleanup-v1",
        ),
        cleanup="artifact-zero-execution-cleanup",
        compensation="revoke-artifact-lease",
        stop_conditions=(
            "authority-drift",
            "artifact-receipt-stale",
            "evidence-failure",
            "cleanup-failure",
        ),
        freshness_seconds=3600,
        qualification="artifact-promotion-qualified",
        deprecation="review-before-source-revision-change",
    )


def build_first_slice_target_mapping(
    semantics: tuple[PromotedCapabilitySemanticsV1, ...],
) -> TargetMappingV1:
    indexed = _index_semantics(semantics)
    if set(indexed) != _FIRST_SLICE_BINDINGS:
        raise ValueError("r119_target_mapping_semantics_required")
    routes = (
        TargetRouteV1(
            binding_key_sha256=canonical_sha256(indexed["zap-controlled-runtime"].binding_key),
            target_class="owned-http-application",
            application_class="synthetic-security-header-fixture",
            environment_class="owned-loopback-lab",
            path_class="zap-passive-missing-header",
        ),
        TargetRouteV1(
            binding_key_sha256=canonical_sha256(indexed["nuclei-trusted-runtime"].binding_key),
            target_class="owned-http-application",
            application_class="synthetic-security-header-fixture",
            environment_class="owned-loopback-lab",
            path_class="nuclei-missing-header",
        ),
    )
    return TargetMappingV1(
        schema_version="redagent.r119-target-mapping/v1",
        mapping_id="owned-loopback-http-first-slice",
        revision=1,
        status=TargetMappingStatus.PROMOTED,
        routes=routes,
    )


def build_artifact_posture_target_mapping(
    semantics: tuple[PromotedCapabilitySemanticsV1, ...],
) -> TargetMappingV1:
    indexed = _index_semantics(semantics)
    if set(indexed) != _EXPECTED_BINDINGS:
        raise ValueError("artifact_posture_target_mapping_semantics_required")
    first_slice = build_first_slice_target_mapping(
        tuple(indexed[key] for key in sorted(_FIRST_SLICE_BINDINGS))
    )
    routes = (*first_slice.routes, TargetRouteV1(
        binding_key_sha256=canonical_sha256(indexed["artifact-posture"].binding_key),
        target_class="repository-snapshot",
        application_class="canonical-artifact-binding",
        environment_class="data-only-sandbox",
        path_class="artifact-posture-data-only",
    ))
    return TargetMappingV1(
        schema_version="redagent.artifact-posture-target-mapping/v2",
        mapping_id="artifact-posture-three-capability",
        revision=2,
        status=TargetMappingStatus.PROMOTED,
        routes=routes,
    )


def build_decision_context_snapshot(
    *,
    semantics: tuple[PromotedCapabilitySemanticsV1, ...],
    target_mapping: TargetMappingV1,
    authority: AuthorityContextV1,
    collection_state: CollectionState,
    current_observations: tuple[ObservationFactV1, ...],
    current_evidence_facts: tuple[EvidenceFactV1, ...],
    current_finding_facts: tuple[FindingFactV1, ...],
    current_detection_observations: tuple[DetectionObservationV1, ...] = (),
    prior_complete_snapshot: DecisionContextSnapshotV1 | None,
    snapshot_at: datetime,
) -> DecisionContextSnapshotV1:
    """Build one deterministic, authorization-filtered, non-authoritative snapshot."""
    _validate_window(snapshot_at, snapshot_at + timedelta(microseconds=1))
    if not isinstance(collection_state, CollectionState):
        raise ValueError("r119_collection_state_invalid")
    current_lanes = (
        current_observations,
        current_evidence_facts,
        current_finding_facts,
        current_detection_observations,
    )
    if collection_state is CollectionState.COMPLETE and prior_complete_snapshot is not None:
        raise ValueError("r119_complete_collection_has_prior_snapshot")
    if collection_state is CollectionState.FAILED and any(current_lanes):
        raise ValueError("r119_failed_collection_has_current_facts")
    indexed_semantics = _index_semantics(semantics)
    expected_bindings = (
        _EXPECTED_BINDINGS if len(indexed_semantics) == 3 else _FIRST_SLICE_BINDINGS
    )
    if set(indexed_semantics) != expected_bindings:
        raise ValueError("r119_semantics_exact_set_required")
    semantics_sorted = tuple(indexed_semantics[key] for key in sorted(indexed_semantics))
    for sidecar in semantics_sorted:
        if sidecar.revoked_at is not None and sidecar.revoked_at <= snapshot_at:
            raise ValueError("r119_semantics_revoked")
        if not sidecar.promoted_at <= snapshot_at < sidecar.expires_at:
            raise ValueError("r119_semantics_not_current")

    expected_mapping = (
        build_artifact_posture_target_mapping(semantics_sorted)
        if expected_bindings == _EXPECTED_BINDINGS
        else build_first_slice_target_mapping(semantics_sorted)
    )
    if (
        target_mapping.status is not TargetMappingStatus.PROMOTED
        or target_mapping.mapping_sha256 != expected_mapping.mapping_sha256
        or authority.target_mapping_sha256 != target_mapping.mapping_sha256
    ):
        raise ValueError("r119_authority_target_mapping_mismatch")
    if not authority.issued_at <= snapshot_at < authority.expires_at:
        raise ValueError("r119_authority_not_current")
    allowed_authority_classes = {
        (
            "owned-http-application",
            "synthetic-security-header-fixture",
            "owned-loopback-lab",
            "owned-loopback-gateway",
        )
    }
    if expected_bindings == _EXPECTED_BINDINGS:
        allowed_authority_classes.add(
            (
                "repository-snapshot",
                "canonical-artifact-binding",
                "data-only-sandbox",
                "no-url",
            )
        )
    if (
        authority.target_class,
        authority.application_class,
        authority.environment_class,
        authority.url_class,
    ) not in allowed_authority_classes:
        raise ValueError("r119_authority_target_class_denied")

    capability_section_sha256 = canonical_sha256(semantics_sorted)
    authority_sha256 = canonical_sha256(authority)
    prior_observations: tuple[ObservationFactV1, ...] = ()
    prior_evidence: tuple[EvidenceFactV1, ...] = ()
    prior_findings: tuple[FindingFactV1, ...] = ()
    prior_detection_observations: tuple[DetectionObservationV1, ...] = ()
    if prior_complete_snapshot is not None:
        if prior_complete_snapshot.collection_state is not CollectionState.COMPLETE:
            raise ValueError("r119_prior_snapshot_not_complete")
        if prior_complete_snapshot.snapshot_at >= snapshot_at:
            raise ValueError("r119_prior_snapshot_not_earlier")
        if prior_complete_snapshot.authority_sha256 != authority_sha256:
            raise ValueError("r119_prior_snapshot_authority_mismatch")
        if prior_complete_snapshot.target_mapping_sha256 != target_mapping.mapping_sha256:
            raise ValueError("r119_prior_snapshot_target_mapping_mismatch")
        if prior_complete_snapshot.capability_section_sha256 != capability_section_sha256:
            raise ValueError("r119_prior_snapshot_capability_mismatch")
        prior_observations = prior_complete_snapshot.observations
        prior_evidence = prior_complete_snapshot.evidence_facts
        prior_findings = prior_complete_snapshot.finding_facts
        prior_detection_observations = prior_complete_snapshot.detection_observations

    binding_by_sha = {
        canonical_sha256(item.binding_key): item for item in semantics_sorted
    }
    evidence_sorted, evidence_dispositions, excluded_prior_evidence_by_ref = _validate_evidence(
        current=current_evidence_facts,
        prior=prior_evidence,
        authority=authority,
        snapshot_at=snapshot_at,
        binding_by_sha=binding_by_sha,
    )
    evidence_by_ref = {item.evidence.reference_id: item for item in evidence_sorted}
    findings_sorted, finding_dispositions = _validate_findings(
        current=current_finding_facts,
        prior=prior_findings,
        authority=authority,
        snapshot_at=snapshot_at,
        binding_by_sha=binding_by_sha,
        evidence_by_ref=evidence_by_ref,
        excluded_prior_evidence_by_ref=excluded_prior_evidence_by_ref,
    )
    observations, observation_dispositions, conflicts = _validate_observations(
        collection_state=collection_state,
        current=current_observations,
        prior=prior_observations,
        authority=authority,
        snapshot_at=snapshot_at,
        binding_by_sha=binding_by_sha,
        evidence_by_ref=evidence_by_ref,
        excluded_prior_evidence_by_ref=excluded_prior_evidence_by_ref,
    )
    observations, observation_dispositions, conflicts = _merge_prior_conflicts(
        observations=observations,
        dispositions=observation_dispositions,
        current_conflicts=conflicts,
        prior_conflicts=(
            prior_complete_snapshot.conflicts if prior_complete_snapshot is not None else ()
        ),
    )
    if expected_bindings == _EXPECTED_BINDINGS and current_detection_observations:
        raise ValueError("artifact_posture_detection_observations_forbidden")
    detection_observations = validate_detection_snapshot_inputs(
        current=current_detection_observations,
        prior=prior_detection_observations,
        tenant_id=authority.tenant_id,
        engagement_id=authority.engagement_id,
        capability_ids=frozenset(indexed_semantics),
        snapshot_at=snapshot_at,
    )
    dispositions = tuple(
        sorted(
            (*evidence_dispositions, *finding_dispositions, *observation_dispositions),
            key=lambda item: (item.fact_sha256, item.reason),
        )
    )

    trusted_body: dict[str, object] = {
        "collection_state": collection_state,
        "observations": observations,
        "evidence_facts": evidence_sorted,
        "finding_facts": findings_sorted,
        "dispositions": dispositions,
        "conflicts": conflicts,
    }
    if detection_observations:
        trusted_body["detection_observations"] = detection_observations
    snapshot_schema_version = (
        "redagent.detection-decision-context/v2"
        if detection_observations
        else "redagent.artifact-posture-decision-context/v2"
        if expected_bindings == _EXPECTED_BINDINGS
        else "redagent.r119-decision-context/v1"
    )
    trusted_section_sha256 = canonical_sha256(trusted_body)
    snapshot_sha256 = canonical_sha256(
        {
            "schema_version": snapshot_schema_version,
            "snapshot_at": snapshot_at,
            "authority_sha256": authority_sha256,
            "target_mapping_sha256": target_mapping.mapping_sha256,
            "capability_section_sha256": capability_section_sha256,
            "trusted_section_sha256": trusted_section_sha256,
        }
    )
    return _validated_decision_context_snapshot(
        schema_version=snapshot_schema_version,
        snapshot_at=snapshot_at,
        authority_sha256=authority_sha256,
        target_mapping_sha256=target_mapping.mapping_sha256,
        collection_state=collection_state,
        semantics=semantics_sorted,
        observations=observations,
        evidence_facts=evidence_sorted,
        finding_facts=findings_sorted,
        dispositions=dispositions,
        conflicts=conflicts,
        detection_observations=detection_observations,
        capability_section_sha256=capability_section_sha256,
        trusted_section_sha256=trusted_section_sha256,
        snapshot_sha256=snapshot_sha256,
    )


def _validate_capability(
    capability: ExecutionCapabilityManifest,
    *,
    expected: tuple[str, int, str, str, str],
    label: str,
) -> None:
    observed = (
        capability.capability_id,
        capability.revision,
        capability.adapter_id,
        capability.adapter_version,
        capability.input_schema_id,
    )
    if observed != expected or capability.status != "certified":
        raise ValueError(f"r119_{label}_capability_identity_mismatch")
    if canonical_capability_sha256(capability) != _EXPECTED_MANIFEST_SHA256[capability.capability_id]:
        raise ValueError(f"r119_{label}_capability_digest_mismatch")


def _index_semantics(
    semantics: tuple[PromotedCapabilitySemanticsV1, ...],
) -> dict[str, PromotedCapabilitySemanticsV1]:
    if len(semantics) > 3:
        raise ValueError("r119_semantics_count_exceeded")
    output: dict[str, PromotedCapabilitySemanticsV1] = {}
    binding_hashes: set[str] = set()
    for item in semantics:
        capability_id = item.binding_key.capability_id
        binding_hash = canonical_sha256(item.binding_key)
        if capability_id not in _EXPECTED_BINDINGS:
            raise ValueError("r119_semantics_capability_denied")
        label = (
            "zap"
            if capability_id == _ZAP_IDENTITY[0]
            else "nuclei"
            if capability_id == _NUCLEI_IDENTITY[0]
            else "artifact"
        )
        # CRITICAL: direct dataclass construction must not bypass the promoted semantic lock.
        expected_definition_sha256 = (
            _artifact_posture_definition().semantics_sha256
            if capability_id == "artifact-posture"
            else _EXPECTED_SEMANTICS_SHA256[capability_id]
        )
        if item.definition.semantics_sha256 != expected_definition_sha256:
            raise ValueError(f"r119_{label}_semantics_digest_mismatch")
        if item.binding_key.normalized_output_sha256 != canonical_sha256(
            _NORMALIZED_OUTPUT_CONTRACTS[capability_id]
        ):
            raise ValueError(f"r119_{label}_normalized_output_digest_mismatch")
        if capability_id == "artifact-posture":
            binding = item.binding_key
            if (
                binding.capability_revision != 1
                or binding.execution_manifest_sha256
                != _EXPECTED_MANIFEST_SHA256[capability_id]
                or binding.adapter_id != _ARTIFACT_IDENTITY[2]
                or binding.adapter_version != _ARTIFACT_IDENTITY[3]
                or binding.profile_id != "r110-repository-snapshot-v1"
                or binding.profile_revision != 1
                or binding.profile_sha256 != _EXPECTED_PROFILE_SHA256[capability_id]
                or binding.bundle_id is not None
                or binding.projection_sha256 != _EXPECTED_PROJECTION_SHA256[capability_id]
            ):
                raise ValueError("r119_artifact_binding_digest_mismatch")
        elif binding_hash != _EXPECTED_BINDING_SHA256[capability_id]:
            raise ValueError(f"r119_{label}_binding_digest_mismatch")
        if item.expires_at > item.promoted_at + timedelta(days=30):
            raise ValueError("r119_semantics_window_exceeded")
        if capability_id in output or binding_hash in binding_hashes:
            raise ValueError("r119_semantics_duplicate")
        output[capability_id] = item
        binding_hashes.add(binding_hash)
    return output


def _validate_projection(
    projection: ProjectedTool,
    *,
    capability: ExecutionCapabilityManifest,
    label: str,
) -> None:
    if (
        projection.tool_kind is not ToolKind.PROPOSAL
        or projection.fully_qualified_name != f"redagent.{capability.capability_id}.propose.v1"
        or projection.source_capability_id != capability.capability_id
        or projection.source_capability_revision != capability.revision
        or projection.source_capability_sha256 != canonical_capability_sha256(capability)
        or projection.adapter_id != capability.adapter_id
        or projection.adapter_version != capability.adapter_version
        or projection.approval_tier != "high"
    ):
        raise ValueError(f"r119_{label}_projection_identity_mismatch")
    if canonical_projected_tool_sha256(projection) != _EXPECTED_PROJECTION_SHA256[capability.capability_id]:
        raise ValueError(f"r119_{label}_projection_digest_mismatch")


def _validate_evidence(
    *,
    current: tuple[EvidenceFactV1, ...],
    prior: tuple[EvidenceFactV1, ...],
    authority: AuthorityContextV1,
    snapshot_at: datetime,
    binding_by_sha: dict[str, PromotedCapabilitySemanticsV1],
) -> tuple[
    tuple[EvidenceFactV1, ...],
    tuple[FactDispositionV1, ...],
    dict[str, tuple[EvidenceFactV1, str]],
]:
    if len(current) > _MAX_FACTS or len(prior) > _MAX_FACTS:
        raise ValueError("r119_evidence_count_exceeded")
    seen: dict[str, EvidenceFactV1] = {}
    output: list[EvidenceFactV1] = []
    dispositions: list[FactDispositionV1] = []
    excluded_prior_by_ref: dict[str, tuple[EvidenceFactV1, str]] = {}

    def exclude_prior(item: EvidenceFactV1, *, digest: str, reason: str) -> None:
        # IMPORTANT: retain the exact validated prior fact so dependent exclusions cannot cross-link.
        excluded_prior_by_ref[item.evidence.reference_id] = (item, reason)
        dispositions.append(FactDispositionV1(fact_sha256=digest, reason=reason))

    def consider(item: EvidenceFactV1, *, previous: bool) -> None:
        if item.tenant_id != authority.tenant_id or item.engagement_id != authority.engagement_id:
            raise ValueError("r119_evidence_scope_mismatch")
        if item.target != authority.target:
            raise ValueError("r119_evidence_target_mismatch")
        sidecar = binding_by_sha.get(item.binding_key_sha256)
        if sidecar is None:
            raise ValueError("r119_evidence_binding_unknown")
        normalized = _normalized_contract(sidecar, item.observation_kind)
        if (item.producer_adapter_id, item.producer_revision) != normalized[:2]:
            raise ValueError("r119_evidence_producer_denied")
        if item.producer_schema_id != normalized[2]:
            raise ValueError("r119_evidence_schema_denied")
        if (
            item.producer_adapter_id,
            item.producer_revision,
            item.producer_schema_id,
            item.source_definition_id,
            item.source_matcher_id,
            item.source_path,
        ) != normalized[:6] or not _resource_matches(
            item.resource,
            normalized,
            authority=authority,
            evidence=item.evidence,
            binding_key_sha256=item.binding_key_sha256,
        ):
            label = "zap" if sidecar.binding_key.capability_id == _ZAP_IDENTITY[0] else "nuclei"
            raise ValueError(f"r119_{label}_normalized_output_mismatch")
        if item.verified is not True or item.redaction_state != "approved":
            raise ValueError("r119_evidence_untrusted")
        if item.finalized_at > snapshot_at:
            raise ValueError("r119_evidence_from_future")
        digest = canonical_sha256(item)
        existing = seen.get(item.evidence.reference_id)
        if existing is not None:
            if existing.evidence.sha256 != item.evidence.sha256:
                raise ValueError("r119_evidence_identity_conflict")
            if canonical_sha256(existing) != digest:
                raise ValueError("r119_evidence_duplicate")
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_superseded"))
            return
        seen[item.evidence.reference_id] = item
        if item.invalidation_state is not InvalidationState.CURRENT:
            if not previous:
                raise ValueError("r119_evidence_not_current")
            exclude_prior(item, digest=digest, reason="excluded_invalidated")
            return
        if not snapshot_at < item.expires_at:
            if not previous:
                raise ValueError("r119_evidence_not_current")
            exclude_prior(item, digest=digest, reason="excluded_stale")
            return
        freshness = timedelta(seconds=sidecar.definition.freshness_seconds)
        if snapshot_at - item.finalized_at >= freshness:
            if not previous:
                raise ValueError("r119_evidence_semantically_stale")
            exclude_prior(item, digest=digest, reason="excluded_stale")
            return
        dispositions.append(
            FactDispositionV1(
                fact_sha256=digest,
                reason="preserved_prior_complete" if previous else "included_current",
            )
        )
        output.append(item)

    for item in current:
        consider(item, previous=False)
    for item in prior:
        consider(item, previous=True)
    return (
        tuple(sorted(output, key=canonical_sha256)),
        tuple(dispositions),
        excluded_prior_by_ref,
    )


def _validate_findings(
    *,
    current: tuple[FindingFactV1, ...],
    prior: tuple[FindingFactV1, ...],
    authority: AuthorityContextV1,
    snapshot_at: datetime,
    binding_by_sha: dict[str, PromotedCapabilitySemanticsV1],
    evidence_by_ref: dict[str, EvidenceFactV1],
    excluded_prior_evidence_by_ref: dict[str, tuple[EvidenceFactV1, str]],
) -> tuple[tuple[FindingFactV1, ...], tuple[FactDispositionV1, ...]]:
    if len(current) > _MAX_FACTS or len(prior) > _MAX_FACTS:
        raise ValueError("r119_finding_count_exceeded")
    seen: dict[str, FindingFactV1] = {}
    seen_occurrences: set[tuple[str, str, str, str]] = set()
    output: list[FindingFactV1] = []
    dispositions: list[FactDispositionV1] = []

    def consider(item: FindingFactV1, *, previous: bool) -> None:
        if item.tenant_id != authority.tenant_id or item.engagement_id != authority.engagement_id:
            raise ValueError("r119_finding_scope_mismatch")
        if item.target != authority.target:
            raise ValueError("r119_finding_target_mismatch")
        digest = canonical_sha256(item)
        existing = seen.get(item.fact_id)
        if existing is not None:
            if canonical_sha256(existing) != digest:
                raise ValueError("r119_finding_identity_conflict")
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_superseded"))
            return
        seen[item.fact_id] = item
        occurrence_key = (
            item.import_session.reference_id,
            item.occurrence.reference_id,
            item.issue.reference_id,
            item.evidence.reference_id,
        )
        if occurrence_key in seen_occurrences:
            raise ValueError("r119_finding_duplicate")
        seen_occurrences.add(occurrence_key)
        sidecar = binding_by_sha.get(item.binding_key_sha256)
        if sidecar is None:
            raise ValueError("r119_finding_binding_unknown")
        normalized = _normalized_contract(sidecar, item.observation_kind)
        if (item.source_adapter_id, item.producer_revision, item.source_schema_id) != normalized[:3]:
            raise ValueError("r119_finding_schema_denied")
        if (
            item.source_adapter_id,
            item.producer_revision,
            item.source_schema_id,
            item.source_definition_id,
            item.source_matcher_id,
            item.source_path,
        ) != normalized[:6] or not _resource_matches(
            item.resource,
            normalized,
            authority=authority,
            evidence=item.evidence,
            binding_key_sha256=item.binding_key_sha256,
        ):
            label = "zap" if sidecar.binding_key.capability_id == _ZAP_IDENTITY[0] else "nuclei"
            raise ValueError(f"r119_{label}_normalized_output_mismatch")
        linked = evidence_by_ref.get(item.evidence.reference_id)
        linked_exclusion_reason: str | None = None
        if linked is None and previous:
            excluded_link = excluded_prior_evidence_by_ref.get(item.evidence.reference_id)
            if excluded_link is not None:
                linked, linked_exclusion_reason = excluded_link
        if linked is None or linked.evidence.sha256 != item.evidence.sha256:
            raise ValueError("r119_finding_evidence_missing")
        if linked.binding_key_sha256 != item.binding_key_sha256:
            raise ValueError("r119_finding_evidence_binding_mismatch")
        if linked.observation_kind is not item.observation_kind:
            raise ValueError("r119_finding_evidence_kind_mismatch")
        if (linked.producer_adapter_id, linked.producer_revision) != (
            item.source_adapter_id,
            item.producer_revision,
        ):
            raise ValueError("r119_finding_evidence_producer_mismatch")
        if linked.producer_schema_id != item.source_schema_id:
            raise ValueError("r119_finding_evidence_schema_mismatch")
        if linked.target != item.target:
            raise ValueError("r119_finding_evidence_target_mismatch")
        if linked.resource != item.resource:
            raise ValueError("r119_finding_evidence_resource_mismatch")
        if linked_exclusion_reason is not None:
            dispositions.append(
                FactDispositionV1(fact_sha256=digest, reason=linked_exclusion_reason)
            )
            return
        if item.observed_at > snapshot_at or item.updated_at > snapshot_at:
            raise ValueError("r119_finding_from_future")
        if (
            item.import_state != "accepted"
            or item.occurrence_state != "observed"
        ):
            raise ValueError("r119_finding_not_current")
        if item.invalidation_state is not InvalidationState.CURRENT:
            if not previous:
                raise ValueError("r119_finding_not_current")
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_invalidated"))
            return
        if not snapshot_at < item.expires_at:
            if not previous:
                raise ValueError("r119_finding_not_current")
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_stale"))
            return
        freshness = timedelta(seconds=sidecar.definition.freshness_seconds)
        if snapshot_at - item.updated_at >= freshness:
            if not previous:
                raise ValueError("r119_finding_semantically_stale")
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_stale"))
            return
        dispositions.append(
            FactDispositionV1(
                fact_sha256=digest,
                reason="preserved_prior_complete" if previous else "included_current",
            )
        )
        output.append(item)

    for item in current:
        consider(item, previous=False)
    for item in prior:
        consider(item, previous=True)
    return tuple(sorted(output, key=canonical_sha256)), tuple(dispositions)


def _validate_observations(
    *,
    collection_state: CollectionState,
    current: tuple[ObservationFactV1, ...],
    prior: tuple[ObservationFactV1, ...],
    authority: AuthorityContextV1,
    snapshot_at: datetime,
    binding_by_sha: dict[str, PromotedCapabilitySemanticsV1],
    evidence_by_ref: dict[str, EvidenceFactV1],
    excluded_prior_evidence_by_ref: dict[str, tuple[EvidenceFactV1, str]],
) -> tuple[tuple[ObservationFactV1, ...], tuple[FactDispositionV1, ...], tuple[FactConflictV1, ...]]:
    if len(current) > _MAX_FACTS or len(prior) > _MAX_FACTS:
        raise ValueError("r119_observation_count_exceeded")
    if collection_state is CollectionState.FAILED and current:
        raise ValueError("r119_failed_collection_has_current_facts")
    seen_ids: set[str] = set()
    candidates: list[ObservationFactV1] = []
    dispositions: list[FactDispositionV1] = []

    def consider(item: ObservationFactV1, *, previous: bool) -> None:
        if item.fact_id in seen_ids:
            raise ValueError("r119_observation_duplicate")
        seen_ids.add(item.fact_id)
        if item.tenant_id != authority.tenant_id or item.engagement_id != authority.engagement_id:
            raise ValueError("r119_observation_scope_mismatch")
        if item.subject != authority.target:
            raise ValueError("r119_observation_target_mismatch")
        if previous and item.completeness is not Completeness.COMPLETE:
            raise ValueError("r119_prior_observation_not_complete")
        sidecar = binding_by_sha.get(item.binding_key_sha256)
        if sidecar is None:
            raise ValueError("r119_observation_binding_unknown")
        if item.kind not in sidecar.definition.observation_kinds:
            raise ValueError("r119_observation_schema_denied")
        normalized = _normalized_contract(sidecar, item.kind)
        if (item.source_adapter_id, item.producer_revision) != normalized[:2]:
            raise ValueError("r119_observation_producer_denied")
        if item.producer_schema_id != normalized[2]:
            raise ValueError("r119_observation_schema_denied")
        if (
            (item.source_adapter_id, item.producer_revision, item.producer_schema_id)
            != normalized[:3]
            or not _resource_matches(
                item.object,
                normalized,
                authority=authority,
                evidence=item.evidence,
                binding_key_sha256=item.binding_key_sha256,
            )
        ):
            label = "zap" if sidecar.binding_key.capability_id == _ZAP_IDENTITY[0] else "nuclei"
            raise ValueError(f"r119_{label}_normalized_output_mismatch")
        if item.trust is not TrustLevel.VERIFIED:
            raise ValueError("r119_observation_untrusted")
        if collection_state is CollectionState.COMPLETE and item.completeness is not Completeness.COMPLETE:
            raise ValueError("r119_complete_collection_fact_incomplete")
        linked = evidence_by_ref.get(item.evidence.reference_id)
        linked_exclusion_reason: str | None = None
        if linked is None and previous:
            excluded_link = excluded_prior_evidence_by_ref.get(item.evidence.reference_id)
            if excluded_link is not None:
                linked, linked_exclusion_reason = excluded_link
        if linked is None or linked.evidence.sha256 != item.evidence.sha256:
            raise ValueError("r119_observation_evidence_missing")
        if linked.binding_key_sha256 != item.binding_key_sha256:
            raise ValueError("r119_observation_evidence_binding_mismatch")
        if linked.observation_kind is not item.kind:
            raise ValueError("r119_observation_evidence_kind_mismatch")
        if (linked.producer_adapter_id, linked.producer_revision) != (
            item.source_adapter_id,
            item.producer_revision,
        ):
            raise ValueError("r119_observation_evidence_producer_mismatch")
        if linked.producer_schema_id != item.producer_schema_id:
            raise ValueError("r119_observation_evidence_schema_mismatch")
        if linked.target != item.subject:
            raise ValueError("r119_observation_evidence_target_mismatch")
        if linked.resource != item.object:
            raise ValueError("r119_observation_evidence_resource_mismatch")
        if linked_exclusion_reason is not None:
            dispositions.append(
                FactDispositionV1(fact_sha256=canonical_sha256(item), reason=linked_exclusion_reason)
            )
            return
        if item.kind is ObservationKind.CAPABILITY_OUTCOME and (
            item.object.reference_id != sidecar.binding_key.capability_id
        ):
            raise ValueError("r119_observation_object_mismatch")
        if item.observed_at > snapshot_at or item.valid_from > snapshot_at or item.ingested_at > snapshot_at:
            raise ValueError("r119_observation_from_future")
        digest = canonical_sha256(item)
        if item.invalidation_state is not InvalidationState.CURRENT:
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_invalidated"))
            return
        if not snapshot_at < item.expires_at:
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_stale"))
            return
        freshness = timedelta(seconds=sidecar.definition.freshness_seconds)
        if snapshot_at - item.observed_at >= freshness:
            if not previous:
                raise ValueError("r119_observation_semantically_stale")
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_stale"))
            return
        if previous and collection_state is CollectionState.COMPLETE:
            dispositions.append(FactDispositionV1(fact_sha256=digest, reason="excluded_superseded"))
            return
        reason = "preserved_prior_complete" if previous else "included_current"
        dispositions.append(FactDispositionV1(fact_sha256=digest, reason=reason))
        candidates.append(item)

    for item in current:
        consider(item, previous=False)
    for item in prior:
        consider(item, previous=True)

    by_identity: dict[str, list[ObservationFactV1]] = defaultdict(list)
    assertions: set[tuple[str, TruthValue, str | None]] = set()
    for item in candidates:
        identity_sha256 = canonical_sha256(item.identity_body())
        assertion_key = (identity_sha256, item.truth, item.value_code)
        if assertion_key in assertions:
            raise ValueError("r119_observation_duplicate_assertion")
        assertions.add(assertion_key)
        by_identity[identity_sha256].append(item)
    conflicts: list[FactConflictV1] = []
    conflicted: set[str] = set()
    for identity_sha256, items in by_identity.items():
        definitive = {
            (item.truth, item.value_code)
            for item in items
            if item.truth in {TruthValue.TRUE, TruthValue.FALSE}
        }
        if len(definitive) > 1:
            digests = tuple(sorted(canonical_sha256(item) for item in items))
            conflicts.append(
                FactConflictV1(identity_sha256=identity_sha256, fact_sha256s=digests)
            )
            conflicted.update(digests)
    if conflicted:
        dispositions = [item for item in dispositions if item.fact_sha256 not in conflicted]
        dispositions.extend(
            FactDispositionV1(fact_sha256=digest, reason="excluded_conflict")
            for digest in sorted(conflicted)
        )
    trusted = tuple(
        sorted((item for item in candidates if canonical_sha256(item) not in conflicted), key=canonical_sha256)
    )
    return (
        trusted,
        tuple(sorted(dispositions, key=lambda item: (item.fact_sha256, item.reason))),
        tuple(sorted(conflicts, key=lambda item: item.identity_sha256)),
    )


def _merge_prior_conflicts(
    *,
    observations: tuple[ObservationFactV1, ...],
    dispositions: tuple[FactDispositionV1, ...],
    current_conflicts: tuple[FactConflictV1, ...],
    prior_conflicts: tuple[FactConflictV1, ...],
) -> tuple[tuple[ObservationFactV1, ...], tuple[FactDispositionV1, ...], tuple[FactConflictV1, ...]]:
    if not prior_conflicts:
        return observations, dispositions, current_conflicts
    conflict_hashes: dict[str, set[str]] = {
        item.identity_sha256: set(item.fact_sha256s) for item in prior_conflicts
    }
    for item in current_conflicts:
        conflict_hashes.setdefault(item.identity_sha256, set()).update(item.fact_sha256s)
    retained: list[ObservationFactV1] = []
    for item in observations:
        identity_sha256 = canonical_sha256(item.identity_body())
        if identity_sha256 in conflict_hashes:
            conflict_hashes[identity_sha256].add(canonical_sha256(item))
        else:
            retained.append(item)
    conflicted_fact_hashes = {
        digest for values in conflict_hashes.values() for digest in values
    }
    merged_dispositions = [
        item for item in dispositions if item.fact_sha256 not in conflicted_fact_hashes
    ]
    merged_dispositions.extend(
        FactDispositionV1(fact_sha256=digest, reason="excluded_conflict")
        for digest in sorted(conflicted_fact_hashes)
    )
    merged_conflicts = tuple(
        FactConflictV1(
            identity_sha256=identity_sha256,
            fact_sha256s=tuple(sorted(fact_sha256s)),
        )
        for identity_sha256, fact_sha256s in sorted(conflict_hashes.items())
    )
    return (
        tuple(sorted(retained, key=canonical_sha256)),
        tuple(sorted(merged_dispositions, key=lambda item: (item.fact_sha256, item.reason))),
        merged_conflicts,
    )


def _capability_for_adapter(adapter_id: str) -> str:
    if adapter_id == "zap-service":
        return "zap-controlled-runtime"
    if adapter_id == "nuclei-service":
        return "nuclei-trusted-runtime"
    return ""


def _normalized_contract(
    sidecar: PromotedCapabilitySemanticsV1,
    kind: ObservationKind,
) -> tuple[str, str, str, str, str, str, str, str]:
    value = _NORMALIZED_OUTPUT_CONTRACTS[sidecar.binding_key.capability_id].get(kind.value)
    if value is None:
        raise ValueError("r119_observation_kind_not_promoted")
    return value


def _resource_matches(
    resource,
    contract: tuple[str, str, str, str, str, str, str, str],
    *,
    authority: AuthorityContextV1,
    evidence,
    binding_key_sha256: str,
) -> bool:
    expected_kind, expected_id = contract[6:]
    if resource.kind != expected_kind:
        return False
    if expected_id == "$target":
        return resource == authority.target
    if expected_id == "$evidence":
        return resource == evidence
    if expected_id == "$capability":
        capability_id = _capability_for_adapter(contract[0])
        return resource.reference_id == capability_id and resource.sha256 == binding_key_sha256
    return resource.reference_id == expected_id


def _validate_window(start: datetime, end: datetime) -> None:
    if (
        start.tzinfo is None
        or start.utcoffset() is None
        or end.tzinfo is None
        or end.utcoffset() is None
        or not start < end
    ):
        raise ValueError("r119_time_window_invalid")
