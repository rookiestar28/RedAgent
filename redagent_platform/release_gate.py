"""Release gate and operational acceptance contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import adapter_certification, policy_simulator


class BlockingItemStatus(str, Enum):
    ACCEPTED = "accepted"
    DEFERRED = "deferred"
    OPEN = "open"


class ReviewArea(str, Enum):
    SECURITY = "security"
    PRIVACY = "privacy"
    OPERATIONS = "operations"


class UserDocTopic(str, Enum):
    PERMITTED_USE = "permitted_use"
    ONBOARDING = "onboarding"
    TARGET_AUTHORIZATION = "target_authorization"
    EXECUTION_SAFETY = "execution_safety"
    EVIDENCE_HANDLING = "evidence_handling"
    INCIDENT_ESCALATION = "incident_escalation"


class ReleaseNoteSection(str, Enum):
    SUPPORTED_MODULES = "supported_modules"
    UNSUPPORTED_MODULES = "unsupported_modules"
    KNOWN_LIMITATIONS = "known_limitations"
    NON_GOALS = "non_goals"


class ReleaseArtifactKind(str, Enum):
    CODE = "code"
    CONFIG = "config"
    POLICY_PACK = "policy_pack"
    ADAPTER_MANIFEST = "adapter_manifest"
    SKILL_PACKAGE = "skill_package"
    DOCUMENTATION = "documentation"
    MIGRATION_ARTIFACT = "migration_artifact"


@dataclass(frozen=True, kw_only=True)
class BlockingItemDisposition:
    item_id: str
    status: BlockingItemStatus
    owner: str | None = None
    risk: str | None = None
    deadline: str | None = None


@dataclass(frozen=True, kw_only=True)
class FullGateEvidence:
    command_log_path: str
    sensitive_value_scan_passed: bool
    pre_commit_passed: bool
    backend_unit_tests_passed: bool
    frontend_e2e_passed: bool


@dataclass(frozen=True, kw_only=True)
class ReviewRecord:
    area: ReviewArea
    reviewer: str
    completed: bool
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class UserDocumentationCoverage:
    topic: UserDocTopic
    path: str
    complete: bool


@dataclass(frozen=True, kw_only=True)
class ReleaseNotesCoverage:
    section: ReleaseNoteSection
    path: str
    complete: bool


@dataclass(frozen=True, kw_only=True)
class ReleaseGateChecklist:
    release_id: str
    blocking_items: tuple[BlockingItemDisposition, ...]
    full_gate: FullGateEvidence
    reviews: tuple[ReviewRecord, ...]
    user_docs: tuple[UserDocumentationCoverage, ...]
    release_notes: tuple[ReleaseNotesCoverage, ...]


@dataclass(frozen=True, kw_only=True)
class ReleaseGateValidation:
    accepted: bool
    reason: str
    gaps: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ReleaseArtifactInventoryItem:
    artifact_id: str
    kind: ReleaseArtifactKind
    relative_path: str
    version: str
    sha256: str
    required: bool = True


@dataclass(frozen=True, kw_only=True)
class ProvenanceAttestation:
    subject_path: str
    expected_sha256: str
    observed_sha256: str
    builder_id: str
    attestation_reference: str
    signed: bool


@dataclass(frozen=True, kw_only=True)
class DependencyPostureEvidence:
    sbom_path: str
    dependency_scan_passed: bool
    secret_scan_passed: bool
    scorecard_score: int
    warnings: tuple[str, ...] = ()
    failures: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class MigrationPlanEvidence:
    plan_id: str
    evidence_migration_path: str
    report_migration_path: str
    backward_compatible: bool
    rollback_compatible: bool
    reviewed_by_user_id: str
    reviewed_at: datetime
    artifact_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class RollbackPlanEvidence:
    plan_id: str
    restore_path: str
    data_compatibility: str
    disabled_feature_handling: str
    operator_notification_plan: str
    validated_at: datetime
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class ReleaseQualificationCandidate:
    release_id: str
    full_gate: FullGateEvidence
    artifacts: tuple[ReleaseArtifactInventoryItem, ...]
    adapter_certifications: tuple[adapter_certification.AdapterCertificationResult, ...]
    policy_packs: tuple[policy_simulator.PolicyPack, ...]
    provenance_attestations: tuple[ProvenanceAttestation, ...]
    dependency_posture: DependencyPostureEvidence
    migration_plan: MigrationPlanEvidence
    rollback_plan: RollbackPlanEvidence
    audit_export_batch_hashes: tuple[str, ...]
    environment_baseline_hash: str
    current_environment_hash: str


@dataclass(frozen=True, kw_only=True)
class ReleaseQualificationPackage:
    release_id: str
    artifact_inventory: tuple[ReleaseArtifactInventoryItem, ...]
    adapter_result_hashes: tuple[str, ...]
    policy_pack_versions: tuple[str, ...]
    provenance_references: tuple[str, ...]
    audit_export_batch_hashes: tuple[str, ...]
    rollback_plan_id: str
    package_hash: str


@dataclass(frozen=True, kw_only=True)
class ReleaseQualificationValidation:
    accepted: bool
    reason: str
    gaps: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    package: ReleaseQualificationPackage | None = None


PHASE_0_TO_6_BLOCKING_ITEMS: tuple[str, ...] = tuple(f"R{index:03d}" for index in range(0, 36))
REQUIRED_REVIEW_AREAS: frozenset[ReviewArea] = frozenset(ReviewArea)
REQUIRED_USER_DOC_TOPICS: frozenset[UserDocTopic] = frozenset(UserDocTopic)
REQUIRED_RELEASE_NOTE_SECTIONS: frozenset[ReleaseNoteSection] = frozenset(ReleaseNoteSection)
REQUIRED_R089_ARTIFACT_KINDS: frozenset[ReleaseArtifactKind] = frozenset(ReleaseArtifactKind)


def build_release_gate_checklist() -> ReleaseGateChecklist:
    return ReleaseGateChecklist(
        release_id="R034-initial-release-readiness",
        blocking_items=tuple(
            BlockingItemDisposition(item_id=item_id, status=BlockingItemStatus.ACCEPTED)
            for item_id in PHASE_0_TO_6_BLOCKING_ITEMS
        ),
        full_gate=FullGateEvidence(
            command_log_path=".local/validation/release-acceptance-command.log",
            sensitive_value_scan_passed=True,
            pre_commit_passed=True,
            backend_unit_tests_passed=True,
            frontend_e2e_passed=True,
        ),
        reviews=(
            ReviewRecord(
                area=ReviewArea.SECURITY,
                reviewer="security-lead",
                completed=True,
                evidence_refs=("docs/security/PLATFORM_SECURITY_ASSESSMENT_POLICY.md",),
            ),
            ReviewRecord(
                area=ReviewArea.PRIVACY,
                reviewer="privacy-reviewer",
                completed=True,
                evidence_refs=("docs/sop/USER_OPERATION_GUIDE.md",),
            ),
            ReviewRecord(
                area=ReviewArea.OPERATIONS,
                reviewer="operations-reviewer",
                completed=True,
                evidence_refs=("docs/security/OBSERVABILITY_INCIDENT_RESPONSE_POLICY.md",),
            ),
        ),
        user_docs=tuple(
            UserDocumentationCoverage(topic=topic, path="docs/sop/USER_OPERATION_GUIDE.md", complete=True)
            for topic in UserDocTopic
        ),
        release_notes=tuple(
            ReleaseNotesCoverage(section=section, path="docs/sop/INITIAL_RELEASE_NOTES.md", complete=True)
            for section in ReleaseNoteSection
        ),
    )


def validate_release_gate(checklist: ReleaseGateChecklist) -> ReleaseGateValidation:
    gaps: list[str] = []
    _append_missing(gaps, "release_id", checklist.release_id)
    gaps.extend(_blocking_item_gaps(checklist.blocking_items))
    gaps.extend(_full_gate_gaps(checklist.full_gate))
    gaps.extend(_review_gaps(checklist.reviews))
    gaps.extend(_user_doc_gaps(checklist.user_docs))
    gaps.extend(_release_note_gaps(checklist.release_notes))
    if gaps:
        return ReleaseGateValidation(accepted=False, reason="release_gate_incomplete", gaps=tuple(gaps))
    return ReleaseGateValidation(accepted=True, reason="release_gate_accepted")


def validate_release_qualification_candidate(candidate: ReleaseQualificationCandidate) -> ReleaseQualificationValidation:
    gaps: list[str] = []
    warnings: list[str] = []
    _append_missing(gaps, "release_id", candidate.release_id)
    gaps.extend(_full_gate_gaps(candidate.full_gate))
    gaps.extend(_artifact_inventory_gaps(candidate.artifacts))
    gaps.extend(_adapter_certification_gaps(candidate.adapter_certifications))
    gaps.extend(_policy_pack_gaps(candidate.policy_packs))
    gaps.extend(_provenance_gaps(candidate.artifacts, candidate.provenance_attestations))
    gaps.extend(_dependency_posture_gaps(candidate.dependency_posture, warnings))
    gaps.extend(_migration_plan_gaps(candidate.migration_plan))
    gaps.extend(_rollback_plan_gaps(candidate.rollback_plan))
    if not candidate.audit_export_batch_hashes:
        gaps.append("audit_export_evidence_required")
    for batch_hash in candidate.audit_export_batch_hashes:
        _append_missing(gaps, "audit_export_batch_hash", batch_hash)
    if candidate.environment_baseline_hash != candidate.current_environment_hash:
        gaps.append("environment_drift_detected")
    _append_missing(gaps, "environment_baseline_hash", candidate.environment_baseline_hash)
    _append_missing(gaps, "current_environment_hash", candidate.current_environment_hash)
    if gaps:
        return ReleaseQualificationValidation(
            accepted=False,
            reason="release_readiness_blocked",
            gaps=tuple(gaps),
            warnings=tuple(warnings),
        )
    package = _release_package(candidate)
    return ReleaseQualificationValidation(
        accepted=True,
        reason="release_readiness_accepted",
        warnings=tuple(warnings),
        package=package,
    )


def _blocking_item_gaps(items: tuple[BlockingItemDisposition, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    present = {item.item_id for item in items}
    missing = set(PHASE_0_TO_6_BLOCKING_ITEMS) - present
    gaps.extend(f"missing_blocking_item:{item_id}" for item_id in sorted(missing))
    for item in items:
        _append_missing(gaps, "blocking_item_id", item.item_id)
        if item.status is BlockingItemStatus.OPEN:
            gaps.append(f"blocking_item_open:{item.item_id}")
        if item.status is BlockingItemStatus.DEFERRED:
            if not item.owner or not item.owner.strip():
                gaps.append(f"deferred_item_owner_required:{item.item_id}")
            if not item.risk or not item.risk.strip():
                gaps.append(f"deferred_item_risk_required:{item.item_id}")
            if not item.deadline or not item.deadline.strip():
                gaps.append(f"deferred_item_deadline_required:{item.item_id}")
    return tuple(gaps)


def _full_gate_gaps(evidence: FullGateEvidence) -> tuple[str, ...]:
    gaps: list[str] = []
    _append_missing(gaps, "full_gate_command_log_path", evidence.command_log_path)
    if not evidence.sensitive_value_scan_passed:
        gaps.append("sensitive_value_scan_required")
    if not evidence.pre_commit_passed:
        gaps.append("pre_commit_required")
    if not evidence.backend_unit_tests_passed:
        gaps.append("backend_unit_tests_required")
    if not evidence.frontend_e2e_passed:
        gaps.append("frontend_e2e_required")
    return tuple(gaps)


def _review_gaps(reviews: tuple[ReviewRecord, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    present = {review.area for review in reviews}
    missing = REQUIRED_REVIEW_AREAS - present
    gaps.extend(f"missing_review:{area.value}" for area in sorted(missing, key=lambda item: item.value))
    for review in reviews:
        _append_missing(gaps, "reviewer", review.reviewer)
        if not review.completed:
            gaps.append(f"review_incomplete:{review.area.value}")
        if not review.evidence_refs:
            gaps.append(f"review_evidence_required:{review.area.value}")
    return tuple(gaps)


def _user_doc_gaps(docs: tuple[UserDocumentationCoverage, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    present = {doc.topic for doc in docs}
    missing = REQUIRED_USER_DOC_TOPICS - present
    gaps.extend(f"missing_user_doc:{topic.value}" for topic in sorted(missing, key=lambda item: item.value))
    for doc in docs:
        _append_missing(gaps, "user_doc_path", doc.path)
        if not doc.complete:
            gaps.append(f"user_doc_incomplete:{doc.topic.value}")
    return tuple(gaps)


def _release_note_gaps(notes: tuple[ReleaseNotesCoverage, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    present = {note.section for note in notes}
    missing = REQUIRED_RELEASE_NOTE_SECTIONS - present
    gaps.extend(f"missing_release_note:{section.value}" for section in sorted(missing, key=lambda item: item.value))
    for note in notes:
        _append_missing(gaps, "release_note_path", note.path)
        if not note.complete:
            gaps.append(f"release_note_incomplete:{note.section.value}")
    return tuple(gaps)


def _artifact_inventory_gaps(items: tuple[ReleaseArtifactInventoryItem, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    if not items:
        return ("release_artifact_inventory_required",)
    present = {item.kind for item in items if item.required}
    missing = REQUIRED_R089_ARTIFACT_KINDS - present
    gaps.extend(f"missing_release_artifact:{kind.value}" for kind in sorted(missing, key=lambda item: item.value))
    seen_ids: set[str] = set()
    for item in items:
        _append_missing(gaps, "artifact_id", item.artifact_id)
        _append_missing(gaps, "artifact_path", item.relative_path)
        _append_missing(gaps, "artifact_version", item.version)
        if item.artifact_id in seen_ids:
            gaps.append(f"duplicate_artifact_id:{item.artifact_id}")
        seen_ids.add(item.artifact_id)
        if not _valid_sha256(item.sha256):
            gaps.append(f"invalid_artifact_hash:{item.artifact_id}")
        if item.relative_path.startswith("/") or ".." in item.relative_path.split("/"):
            gaps.append(f"unsafe_artifact_path:{item.artifact_id}")
    return tuple(gaps)


def _adapter_certification_gaps(
    results: tuple[adapter_certification.AdapterCertificationResult, ...],
) -> tuple[str, ...]:
    if not results:
        return ("adapter_certification_evidence_required",)
    gaps: list[str] = []
    for result in results:
        if not result.certified:
            gaps.append(f"adapter_not_certified:{result.adapter_id}:{result.version}")
        if result.release_blocking:
            gaps.append(f"adapter_release_blocking:{result.adapter_id}:{result.version}")
        if not _valid_sha256(result.result_hash):
            gaps.append(f"invalid_adapter_result_hash:{result.adapter_id}:{result.version}")
        _append_missing(gaps, "adapter_audit_event_hash", result.audit_event_hash)
    return tuple(gaps)


def _policy_pack_gaps(packs: tuple[policy_simulator.PolicyPack, ...]) -> tuple[str, ...]:
    if not packs:
        return ("policy_pack_review_required",)
    gaps: list[str] = []
    for pack in packs:
        _append_missing(gaps, "policy_pack_id", pack.pack_id)
        _append_missing(gaps, "policy_pack_version", pack.version)
        if pack.status not in {policy_simulator.PolicyPackStatus.REVIEWED, policy_simulator.PolicyPackStatus.ACTIVE}:
            gaps.append(f"policy_pack_not_reviewed:{pack.pack_id}:{pack.version}")
        if not pack.reviewed_by_user_id or pack.reviewed_at is None:
            gaps.append(f"policy_pack_review_evidence_required:{pack.pack_id}:{pack.version}")
        elif pack.reviewed_at.tzinfo is None or pack.reviewed_at.utcoffset() is None:
            gaps.append(f"policy_pack_review_timezone_required:{pack.pack_id}:{pack.version}")
    return tuple(gaps)


def _provenance_gaps(
    artifacts: tuple[ReleaseArtifactInventoryItem, ...],
    attestations: tuple[ProvenanceAttestation, ...],
) -> tuple[str, ...]:
    if not attestations:
        return ("provenance_attestation_required",)
    gaps: list[str] = []
    by_path = {attestation.subject_path: attestation for attestation in attestations}
    for artifact in artifacts:
        if not artifact.required:
            continue
        attestation = by_path.get(artifact.relative_path)
        if attestation is None:
            gaps.append(f"missing_provenance:{artifact.relative_path}")
            continue
        for field_name, value in (
            ("provenance_subject_path", attestation.subject_path),
            ("provenance_builder_id", attestation.builder_id),
            ("provenance_attestation_reference", attestation.attestation_reference),
        ):
            _append_missing(gaps, field_name, value)
        if attestation.expected_sha256 != artifact.sha256:
            gaps.append(f"provenance_expected_hash_mismatch:{artifact.relative_path}")
        if attestation.expected_sha256 != attestation.observed_sha256:
            gaps.append(f"provenance_observed_hash_mismatch:{artifact.relative_path}")
        if not attestation.signed:
            gaps.append(f"provenance_unsigned:{artifact.relative_path}")
    return tuple(gaps)


def _dependency_posture_gaps(evidence: DependencyPostureEvidence, warnings: list[str]) -> tuple[str, ...]:
    gaps: list[str] = []
    _append_missing(gaps, "dependency_sbom_path", evidence.sbom_path)
    if not evidence.dependency_scan_passed:
        gaps.append("dependency_scan_required")
    if not evidence.secret_scan_passed:
        gaps.append("secret_scan_required")
    if evidence.failures:
        gaps.extend(f"dependency_failure:{failure}" for failure in evidence.failures)
    if evidence.scorecard_score < 7:
        warnings.append(f"dependency_posture_warning:scorecard:{evidence.scorecard_score}")
    warnings.extend(f"dependency_posture_warning:{warning}" for warning in evidence.warnings)
    return tuple(gaps)


def _migration_plan_gaps(plan: MigrationPlanEvidence) -> tuple[str, ...]:
    gaps: list[str] = []
    for field_name, value in (
        ("migration_plan_id", plan.plan_id),
        ("evidence_migration_path", plan.evidence_migration_path),
        ("report_migration_path", plan.report_migration_path),
        ("migration_reviewer", plan.reviewed_by_user_id),
    ):
        _append_missing(gaps, field_name, value)
    if not plan.backward_compatible:
        gaps.append("migration_backward_compatibility_required")
    if not plan.rollback_compatible:
        gaps.append("migration_rollback_compatibility_required")
    if plan.reviewed_at.tzinfo is None or plan.reviewed_at.utcoffset() is None:
        gaps.append("migration_review_timezone_required")
    if not plan.artifact_refs:
        gaps.append("migration_artifact_refs_required")
    return tuple(gaps)


def _rollback_plan_gaps(plan: RollbackPlanEvidence) -> tuple[str, ...]:
    gaps: list[str] = []
    for field_name, value in (
        ("rollback_plan_id", plan.plan_id),
        ("rollback_restore_path", plan.restore_path),
        ("rollback_data_compatibility", plan.data_compatibility),
        ("rollback_disabled_feature_handling", plan.disabled_feature_handling),
        ("rollback_operator_notification_plan", plan.operator_notification_plan),
    ):
        _append_missing(gaps, field_name, value)
    if plan.validated_at.tzinfo is None or plan.validated_at.utcoffset() is None:
        gaps.append("rollback_validation_timezone_required")
    if not plan.evidence_refs:
        gaps.append("rollback_evidence_refs_required")
    return tuple(gaps)


def _release_package(candidate: ReleaseQualificationCandidate) -> ReleaseQualificationPackage:
    artifact_inventory = tuple(sorted(candidate.artifacts, key=lambda item: (item.kind.value, item.relative_path)))
    adapter_hashes = tuple(sorted(result.result_hash for result in candidate.adapter_certifications))
    policy_versions = tuple(sorted(f"{pack.pack_id}:{pack.version}" for pack in candidate.policy_packs))
    provenance_refs = tuple(sorted(attestation.attestation_reference for attestation in candidate.provenance_attestations))
    payload = {
        "release_id": candidate.release_id,
        "artifact_inventory": tuple(_artifact_payload(item) for item in artifact_inventory),
        "adapter_result_hashes": adapter_hashes,
        "policy_pack_versions": policy_versions,
        "provenance_references": provenance_refs,
        "audit_export_batch_hashes": tuple(sorted(candidate.audit_export_batch_hashes)),
        "rollback_plan_id": candidate.rollback_plan.plan_id,
    }
    return ReleaseQualificationPackage(
        release_id=candidate.release_id,
        artifact_inventory=artifact_inventory,
        adapter_result_hashes=adapter_hashes,
        policy_pack_versions=policy_versions,
        provenance_references=provenance_refs,
        audit_export_batch_hashes=tuple(sorted(candidate.audit_export_batch_hashes)),
        rollback_plan_id=candidate.rollback_plan.plan_id,
        package_hash=_canonical_sha256(payload),
    )


def _artifact_payload(item: ReleaseArtifactInventoryItem) -> dict[str, object]:
    return {
        "artifact_id": item.artifact_id,
        "kind": item.kind.value,
        "relative_path": item.relative_path,
        "version": item.version,
        "sha256": item.sha256,
        "required": item.required,
    }


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _append_missing(gaps: list[str], field_name: str, value: str) -> None:
    if not value or not value.strip():
        gaps.append(f"missing_{field_name}")
