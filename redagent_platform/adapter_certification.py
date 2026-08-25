"""Adapter certification and safety conformance contracts.

This module validates adapter metadata only. It never invokes adapter binaries,
loads scanner templates, starts subprocesses, dispatches runners, or contacts
targets.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum

from redagent_platform.coverage_packs import CoveragePackRegistry
from redagent_platform.domain import EvidenceKind, PolicyDecisionOutcome, TestMode
from redagent_platform.evidence_chain import AuditAction, EvidenceChain


class AdapterFeature(str, Enum):
    PASSIVE_RESULT_IMPORT = "passive_result_import"
    ACTIVE_SCAN = "active_scan"
    CANCELLATION = "cancellation"
    CLEANUP = "cleanup"
    ARBITRARY_COMMAND_EXECUTION = "arbitrary_command_execution"
    CODE_TEMPLATE_EXECUTION = "code_template_execution"
    UNCONTROLLED_NETWORK_SCAN = "uncontrolled_network_scan"
    CREDENTIAL_ATTACK = "credential_attack"
    PAYLOAD_EXECUTION = "payload_execution"


class AdapterUseSurface(str, Enum):
    UI = "ui"
    API = "api"
    SKILL = "skill"
    RUNNER_JOB = "runner_job"


class AdapterCertificationStatus(str, Enum):
    DRAFT = "draft"
    CERTIFIED = "certified"
    FAILED = "failed"
    REVOKED = "revoked"


@dataclass(frozen=True, kw_only=True)
class AdapterProvenance:
    source_reference: str
    expected_artifact_digest: str
    observed_artifact_digest: str
    sbom_reference: str
    attestation_reference: str
    reviewed_by_user_id: str


@dataclass(frozen=True, kw_only=True)
class AdapterCoveragePackRef:
    pack_id: str
    version: str
    adapter_id: str
    profile_id: str


@dataclass(frozen=True, kw_only=True)
class AdapterManifest:
    adapter_id: str
    version: str
    display_name: str
    command_boundary: str
    supported_modes: tuple[TestMode, ...]
    forbidden_modes: tuple[TestMode, ...]
    evidence_schema: tuple[EvidenceKind, ...]
    cleanup_required: bool
    cleanup_evidence_schema: tuple[str, ...]
    timeout_seconds: int
    cancellation_supported: bool
    declared_features: tuple[AdapterFeature, ...]
    allowed_surfaces: tuple[AdapterUseSurface, ...]
    coverage_pack_refs: tuple[AdapterCoveragePackRef, ...]
    provenance: AdapterProvenance
    status: AdapterCertificationStatus = AdapterCertificationStatus.DRAFT
    certified_by_user_id: str | None = None
    certified_at: datetime | None = None
    certification_audit_event_hash: str | None = None


@dataclass(frozen=True, kw_only=True)
class CertificationFinding:
    finding_id: str
    reason: str
    release_blocking: bool


@dataclass(frozen=True, kw_only=True)
class AdapterCertificationResult:
    adapter_id: str
    version: str
    status: AdapterCertificationStatus
    findings: tuple[CertificationFinding, ...]
    release_blocking: bool
    result_hash: str
    audit_event_hash: str

    @property
    def certified(self) -> bool:
        return self.status is AdapterCertificationStatus.CERTIFIED


@dataclass(frozen=True, kw_only=True)
class AdapterUseDecision:
    outcome: PolicyDecisionOutcome
    reason: str
    adapter_id: str
    version: str
    surface: AdapterUseSurface
    mode: TestMode

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyDecisionOutcome.ALLOW


@dataclass(frozen=True, kw_only=True)
class ReleaseGateResult:
    allowed: bool
    reason: str
    release_blocking_results: tuple[AdapterCertificationResult, ...]


@dataclass(frozen=True)
class AdapterCertificationRegistry:
    certified_adapters: tuple[AdapterManifest, ...] = ()
    audit_chain: EvidenceChain = EvidenceChain()

    def certify(
        self,
        manifest: AdapterManifest,
        *,
        coverage_registry: CoveragePackRegistry,
        reviewer_user_id: str,
        certified_at: datetime,
        event_id: str,
    ) -> tuple["AdapterCertificationRegistry", AdapterCertificationResult]:
        _require_non_empty("reviewer_user_id", reviewer_user_id)
        _require_non_empty("event_id", event_id)
        _require_timezone(certified_at)
        findings = _certification_findings(manifest, coverage_registry)
        status = AdapterCertificationStatus.FAILED if findings else AdapterCertificationStatus.CERTIFIED
        next_chain = self.audit_chain.append_audit_event(
            event_id=event_id,
            organization_id="adapter-certification",
            actor_user_id=reviewer_user_id,
            action=AuditAction.TEST_DEFINITION_CHANGE,
            subject_type="adapter_certification",
            subject_id=f"{manifest.adapter_id}:{manifest.version}",
            occurred_at=certified_at,
            details={
                "status": status.value,
                "finding_count": len(findings),
                "release_blocking": bool(findings),
                "supported_modes": tuple(mode.value for mode in manifest.supported_modes),
                "allowed_surfaces": tuple(surface.value for surface in manifest.allowed_surfaces),
                "coverage_pack_count": len(manifest.coverage_pack_refs),
            },
        )
        audit_hash = next_chain.audit_events[-1].event_hash
        result = _result(manifest, status, findings, audit_hash)
        if findings:
            return AdapterCertificationRegistry(self.certified_adapters, next_chain), result
        certified = replace(
            manifest,
            status=AdapterCertificationStatus.CERTIFIED,
            certified_by_user_id=reviewer_user_id.strip(),
            certified_at=certified_at,
            certification_audit_event_hash=audit_hash,
        )
        return AdapterCertificationRegistry(self.certified_adapters + (certified,), next_chain), result

    def authorize_use(
        self,
        *,
        adapter_id: str,
        version: str,
        surface: AdapterUseSurface,
        mode: TestMode,
    ) -> AdapterUseDecision:
        try:
            manifest = _manifest_by_id(self.certified_adapters, adapter_id, version)
        except ValueError:
            return _use_denied(adapter_id, version, surface, mode, "adapter_not_certified")
        if manifest.status is not AdapterCertificationStatus.CERTIFIED:
            return _use_denied(adapter_id, version, surface, mode, "adapter_not_certified")
        if surface not in manifest.allowed_surfaces:
            return _use_denied(adapter_id, version, surface, mode, "adapter_surface_not_certified")
        if mode in manifest.forbidden_modes or mode not in manifest.supported_modes:
            return _use_denied(adapter_id, version, surface, mode, "adapter_mode_not_certified")
        return AdapterUseDecision(
            outcome=PolicyDecisionOutcome.ALLOW,
            reason="adapter_certified_for_surface",
            adapter_id=adapter_id,
            version=version,
            surface=surface,
            mode=mode,
        )


UNSAFE_FEATURES: frozenset[AdapterFeature] = frozenset(
    {
        AdapterFeature.ARBITRARY_COMMAND_EXECUTION,
        AdapterFeature.CODE_TEMPLATE_EXECUTION,
        AdapterFeature.UNCONTROLLED_NETWORK_SCAN,
        AdapterFeature.CREDENTIAL_ATTACK,
        AdapterFeature.PAYLOAD_EXECUTION,
    }
)


def evaluate_release_gate(results: tuple[AdapterCertificationResult, ...]) -> ReleaseGateResult:
    blockers = tuple(result for result in results if result.release_blocking)
    if blockers:
        return ReleaseGateResult(
            allowed=False,
            reason="adapter_certification_release_blocked",
            release_blocking_results=blockers,
        )
    return ReleaseGateResult(allowed=True, reason="adapter_certification_release_allowed", release_blocking_results=())


def _certification_findings(
    manifest: AdapterManifest,
    coverage_registry: CoveragePackRegistry,
) -> tuple[CertificationFinding, ...]:
    findings: list[CertificationFinding] = []
    try:
        _validate_manifest_basics(manifest)
    except ValueError as exc:
        findings.append(_finding("manifest", str(exc)))
        return tuple(findings)
    for feature in sorted(set(manifest.declared_features).intersection(UNSAFE_FEATURES), key=lambda item: item.value):
        findings.append(_finding(f"unsafe:{feature.value}", f"unsafe_feature_denied:{feature.value}"))
    if manifest.provenance.expected_artifact_digest != manifest.provenance.observed_artifact_digest:
        findings.append(_finding("provenance", "adapter_provenance_mismatch"))
    if manifest.cleanup_required and not manifest.cleanup_evidence_schema:
        findings.append(_finding("cleanup", "cleanup_evidence_schema_required"))
    if not manifest.cancellation_supported:
        findings.append(_finding("cancellation", "adapter_cancellation_required"))
    for ref in manifest.coverage_pack_refs:
        if ref.adapter_id != manifest.adapter_id:
            findings.append(_finding(f"coverage:{ref.pack_id}", "coverage_pack_adapter_mismatch"))
            continue
        decision = coverage_registry.select_for_live_job(
            pack_id=ref.pack_id,
            version=ref.version,
            adapter_id=ref.adapter_id,
            profile_id=ref.profile_id,
        )
        if not decision.allowed:
            findings.append(_finding(f"coverage:{ref.pack_id}", f"coverage_pack_not_selectable:{decision.reason}"))
    return tuple(findings)


def _validate_manifest_basics(manifest: AdapterManifest) -> None:
    for field_name, value in (
        ("adapter_id", manifest.adapter_id),
        ("version", manifest.version),
        ("display_name", manifest.display_name),
        ("command_boundary", manifest.command_boundary),
    ):
        _require_non_empty(field_name, value)
    _validate_provenance(manifest.provenance)
    if not manifest.supported_modes:
        raise ValueError("adapter_supported_modes_required")
    if set(manifest.supported_modes).intersection(manifest.forbidden_modes):
        raise ValueError("adapter_mode_cannot_be_supported_and_forbidden")
    if not manifest.evidence_schema:
        raise ValueError("adapter_evidence_schema_required")
    if manifest.timeout_seconds <= 0:
        raise ValueError("adapter_timeout_required")
    if not manifest.declared_features:
        raise ValueError("adapter_features_required")
    if not manifest.allowed_surfaces:
        raise ValueError("adapter_surfaces_required")
    if not manifest.coverage_pack_refs:
        raise ValueError("adapter_coverage_pack_required")
    for ref in manifest.coverage_pack_refs:
        _validate_coverage_ref(ref)


def _validate_provenance(provenance: AdapterProvenance) -> None:
    for field_name, value in (
        ("source_reference", provenance.source_reference),
        ("expected_artifact_digest", provenance.expected_artifact_digest),
        ("observed_artifact_digest", provenance.observed_artifact_digest),
        ("sbom_reference", provenance.sbom_reference),
        ("attestation_reference", provenance.attestation_reference),
        ("reviewed_by_user_id", provenance.reviewed_by_user_id),
    ):
        _require_non_empty(field_name, value)


def _validate_coverage_ref(ref: AdapterCoveragePackRef) -> None:
    for field_name, value in (
        ("pack_id", ref.pack_id),
        ("version", ref.version),
        ("adapter_id", ref.adapter_id),
        ("profile_id", ref.profile_id),
    ):
        _require_non_empty(field_name, value)


def _result(
    manifest: AdapterManifest,
    status: AdapterCertificationStatus,
    findings: tuple[CertificationFinding, ...],
    audit_event_hash: str,
) -> AdapterCertificationResult:
    payload = {
        "adapter_id": manifest.adapter_id,
        "version": manifest.version,
        "status": status.value,
        "findings": tuple(
            {
                "finding_id": finding.finding_id,
                "reason": finding.reason,
                "release_blocking": finding.release_blocking,
            }
            for finding in findings
        ),
        "audit_event_hash": audit_event_hash,
    }
    return AdapterCertificationResult(
        adapter_id=manifest.adapter_id,
        version=manifest.version,
        status=status,
        findings=findings,
        release_blocking=bool(findings),
        result_hash=_canonical_sha256(payload),
        audit_event_hash=audit_event_hash,
    )


def _finding(finding_id: str, reason: str) -> CertificationFinding:
    return CertificationFinding(finding_id=finding_id, reason=reason, release_blocking=True)


def _manifest_by_id(
    manifests: tuple[AdapterManifest, ...],
    adapter_id: str,
    version: str,
) -> AdapterManifest:
    _require_non_empty("adapter_id", adapter_id)
    _require_non_empty("version", version)
    for manifest in manifests:
        if manifest.adapter_id == adapter_id and manifest.version == version:
            return manifest
    raise ValueError("adapter_not_certified")


def _use_denied(
    adapter_id: str,
    version: str,
    surface: AdapterUseSurface,
    mode: TestMode,
    reason: str,
) -> AdapterUseDecision:
    return AdapterUseDecision(
        outcome=PolicyDecisionOutcome.DENY,
        reason=reason,
        adapter_id=adapter_id,
        version=version,
        surface=surface,
        mode=mode,
    )


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
