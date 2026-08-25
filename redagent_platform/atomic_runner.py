"""Metadata-only atomic test import and lab-only runner contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform.attack_campaigns import AttackTechniqueSelection, TelemetrySource
from redagent_platform.domain import EvidenceKind, TargetType, TestMode, TestRiskClass
from redagent_platform.evidence_chain import AuditAction, EvidenceChain


class AtomicSafetyFlag(str, Enum):
    EXTERNAL_DOWNLOAD = "external_download"
    ELEVATED_PRIVILEGE = "elevated_privilege"
    DESTRUCTIVE = "destructive"
    MISSING_CLEANUP = "missing_cleanup"
    UNSUPPORTED_PLATFORM = "unsupported_platform"


class AtomicRunPhase(str, Enum):
    PREREQUISITE = "prerequisite"
    EXECUTION = "execution"
    CLEANUP = "cleanup"
    TELEMETRY = "telemetry"
    EVIDENCE = "evidence"


class AtomicPhaseStatus(str, Enum):
    CAPTURED = "captured"
    BLOCKED = "blocked"


@dataclass(frozen=True, kw_only=True)
class AtomicTestMetadata:
    test_id: str
    name: str
    attack_mapping: tuple[AttackTechniqueSelection, ...]
    supported_platforms: tuple[str, ...]
    executor_name: str
    prerequisite_summary: str
    execution_summary: str
    cleanup_summary: str | None
    expected_telemetry: tuple[TelemetrySource, ...]
    metadata_only: bool = True
    requires_external_download: bool = False
    requires_elevation: bool = False
    destructive_potential: bool = False


@dataclass(frozen=True, kw_only=True)
class LabTargetContext:
    target_id: str
    target_type: TargetType
    environment: str
    platform: str
    is_lab_target: bool
    approved_by_user_id: str | None


@dataclass(frozen=True, kw_only=True)
class AtomicReview:
    reviewed_by_user_id: str
    reviewed_at: datetime
    allowed_flags: tuple[AtomicSafetyFlag, ...]
    lab_environment_id: str


@dataclass(frozen=True, kw_only=True)
class AtomicPhaseCapture:
    phase: AtomicRunPhase
    status: AtomicPhaseStatus
    summary: str
    evidence_kind: EvidenceKind | None = None


@dataclass(frozen=True, kw_only=True)
class AtomicLabRunDecision:
    allowed: bool
    reason: str
    blocked_flags: tuple[AtomicSafetyFlag, ...]
    phases: tuple[AtomicPhaseCapture, ...]


@dataclass(frozen=True, kw_only=True)
class AtomicLabRunRequest:
    job_id: str
    organization_id: str
    engagement_id: str
    metadata: AtomicTestMetadata
    target: LabTargetContext
    requested_at: datetime
    review: AtomicReview | None = None


@dataclass(frozen=True, kw_only=True)
class AtomicLabRunRecord:
    job_id: str
    test_id: str
    mode: TestMode
    risk_class: TestRiskClass
    target_id: str
    phases: tuple[AtomicPhaseCapture, ...]
    execution_enabled: bool


@dataclass(frozen=True, kw_only=True)
class AtomicLabRunResult:
    decision: AtomicLabRunDecision
    record: AtomicLabRunRecord | None
    audit_chain: EvidenceChain


_ATOMIC_ID = re.compile(r"^[A-Za-z0-9_.:-]+$")


def import_atomic_metadata(raw: Mapping[str, object]) -> AtomicTestMetadata:
    """Import safe atomic metadata while dropping executable command bodies."""
    test_id = _string(raw, "test_id")
    name = _string(raw, "name")
    tactic_id = _string(raw, "tactic_id")
    tactic_name = _string(raw, "tactic_name")
    technique_id = _string(raw, "technique_id")
    technique_name = _string(raw, "technique_name")
    supported_platforms = tuple(_normalized_platform(platform) for platform in _string_sequence(raw, "supported_platforms"))
    expected_telemetry = tuple(TelemetrySource(item) for item in _string_sequence(raw, "expected_telemetry"))
    cleanup_summary = raw.get("cleanup_summary")
    if cleanup_summary is not None and not isinstance(cleanup_summary, str):
        raise ValueError("invalid_cleanup_summary")
    metadata = AtomicTestMetadata(
        test_id=test_id,
        name=name,
        attack_mapping=(
            AttackTechniqueSelection(
                tactic_id=tactic_id,
                tactic_name=tactic_name,
                technique_id=technique_id,
                technique_name=technique_name,
                subtechnique_id=_optional_string(raw, "subtechnique_id"),
            ),
        ),
        supported_platforms=supported_platforms,
        executor_name=_string(raw, "executor_name"),
        prerequisite_summary=_string(raw, "prerequisite_summary"),
        execution_summary=_string(raw, "execution_summary"),
        cleanup_summary=cleanup_summary.strip() if isinstance(cleanup_summary, str) and cleanup_summary.strip() else None,
        expected_telemetry=expected_telemetry,
        metadata_only=True,
        requires_external_download=bool(raw.get("requires_external_download", False)),
        requires_elevation=bool(raw.get("requires_elevation", False)),
        destructive_potential=bool(raw.get("destructive_potential", False)),
    )
    validate_atomic_metadata(metadata)
    return metadata


def prepare_lab_atomic_run(
    *,
    request: AtomicLabRunRequest,
    audit_chain: EvidenceChain,
    event_id: str,
) -> AtomicLabRunResult:
    _validate_request(request)
    _require_non_empty("event_id", event_id)
    decision = evaluate_lab_run(request)
    record = (
        AtomicLabRunRecord(
            job_id=request.job_id,
            test_id=request.metadata.test_id,
            mode=TestMode.LAB_ONLY_RUN,
            risk_class=TestRiskClass.LAB_ONLY,
            target_id=request.target.target_id,
            phases=decision.phases,
            execution_enabled=True,
        )
        if decision.allowed
        else None
    )
    next_chain = audit_chain.append_audit_event(
        event_id=event_id,
        organization_id=request.organization_id,
        actor_user_id=request.review.reviewed_by_user_id if request.review else None,
        action=AuditAction.JOB_LIFECYCLE,
        subject_type="atomic_lab_run",
        subject_id=request.job_id,
        occurred_at=request.requested_at,
        details={
            "outcome": "allow" if decision.allowed else "deny",
            "reason": decision.reason,
            "blocked_flags": tuple(flag.value for flag in decision.blocked_flags),
            "phase_count": len(decision.phases),
            "metadata_only": request.metadata.metadata_only,
        },
    )
    return AtomicLabRunResult(decision=decision, record=record, audit_chain=next_chain)


def evaluate_lab_run(request: AtomicLabRunRequest) -> AtomicLabRunDecision:
    _validate_request(request)
    base_phases = _phase_capture(request.metadata, AtomicPhaseStatus.CAPTURED)
    target_denial = _target_denial(request.target)
    if target_denial:
        return AtomicLabRunDecision(
            allowed=False,
            reason=target_denial,
            blocked_flags=(),
            phases=_phase_capture(request.metadata, AtomicPhaseStatus.BLOCKED),
        )
    blocked_flags = _blocked_flags(request.metadata, request.target.platform)
    unreviewed = _unreviewed_flags(blocked_flags, request.review)
    if unreviewed:
        return AtomicLabRunDecision(
            allowed=False,
            reason="atomic_review_required",
            blocked_flags=unreviewed,
            phases=_phase_capture(request.metadata, AtomicPhaseStatus.BLOCKED),
        )
    return AtomicLabRunDecision(
        allowed=True,
        reason="lab_atomic_run_prepared",
        blocked_flags=(),
        phases=base_phases,
    )


def validate_atomic_metadata(metadata: AtomicTestMetadata) -> None:
    for field_name, value in (
        ("test_id", metadata.test_id),
        ("name", metadata.name),
        ("executor_name", metadata.executor_name),
        ("prerequisite_summary", metadata.prerequisite_summary),
        ("execution_summary", metadata.execution_summary),
    ):
        _require_non_empty(field_name, value)
    if not _ATOMIC_ID.fullmatch(metadata.test_id):
        raise ValueError("invalid_atomic_test_id")
    if not metadata.metadata_only:
        raise ValueError("atomic_import_must_be_metadata_only")
    if not metadata.attack_mapping:
        raise ValueError("missing_attack_mapping")
    if not metadata.supported_platforms:
        raise ValueError("missing_supported_platforms")
    if not metadata.expected_telemetry:
        raise ValueError("missing_expected_telemetry")


def _blocked_flags(metadata: AtomicTestMetadata, target_platform: str) -> tuple[AtomicSafetyFlag, ...]:
    flags: list[AtomicSafetyFlag] = []
    if metadata.requires_external_download:
        flags.append(AtomicSafetyFlag.EXTERNAL_DOWNLOAD)
    if metadata.requires_elevation:
        flags.append(AtomicSafetyFlag.ELEVATED_PRIVILEGE)
    if metadata.destructive_potential:
        flags.append(AtomicSafetyFlag.DESTRUCTIVE)
    if metadata.destructive_potential and not metadata.cleanup_summary:
        flags.append(AtomicSafetyFlag.MISSING_CLEANUP)
    if _normalized_platform(target_platform) not in metadata.supported_platforms:
        flags.append(AtomicSafetyFlag.UNSUPPORTED_PLATFORM)
    return tuple(flags)


def _unreviewed_flags(
    flags: tuple[AtomicSafetyFlag, ...],
    review: AtomicReview | None,
) -> tuple[AtomicSafetyFlag, ...]:
    if not flags:
        return ()
    if review is None:
        return flags
    _require_non_empty("reviewed_by_user_id", review.reviewed_by_user_id)
    _require_non_empty("lab_environment_id", review.lab_environment_id)
    _require_timezone(review.reviewed_at)
    allowed = set(review.allowed_flags)
    return tuple(flag for flag in flags if flag not in allowed)


def _target_denial(target: LabTargetContext) -> str | None:
    _require_non_empty("target_id", target.target_id)
    _require_non_empty("environment", target.environment)
    _require_non_empty("platform", target.platform)
    if not target.is_lab_target:
        return "lab_target_required"
    if target.target_type is not TargetType.LAB_TARGET:
        return "lab_target_type_required"
    if not target.approved_by_user_id or not target.approved_by_user_id.strip():
        return "lab_target_approval_required"
    return None


def _phase_capture(metadata: AtomicTestMetadata, status: AtomicPhaseStatus) -> tuple[AtomicPhaseCapture, ...]:
    cleanup = metadata.cleanup_summary or "No cleanup summary supplied; cleanup gap requires review for destructive tests."
    return (
        AtomicPhaseCapture(
            phase=AtomicRunPhase.PREREQUISITE,
            status=status,
            summary=metadata.prerequisite_summary,
            evidence_kind=EvidenceKind.COMMAND_LOG,
        ),
        AtomicPhaseCapture(
            phase=AtomicRunPhase.EXECUTION,
            status=status,
            summary=metadata.execution_summary,
            evidence_kind=EvidenceKind.COMMAND_LOG,
        ),
        AtomicPhaseCapture(
            phase=AtomicRunPhase.CLEANUP,
            status=status,
            summary=cleanup,
            evidence_kind=EvidenceKind.COMMAND_LOG,
        ),
        AtomicPhaseCapture(
            phase=AtomicRunPhase.TELEMETRY,
            status=status,
            summary=", ".join(source.value for source in metadata.expected_telemetry),
            evidence_kind=EvidenceKind.TELEMETRY,
        ),
        AtomicPhaseCapture(
            phase=AtomicRunPhase.EVIDENCE,
            status=status,
            summary="Evidence capture is represented by immutable evidence ids and hashes.",
            evidence_kind=EvidenceKind.COMMAND_LOG,
        ),
    )


def _validate_request(request: AtomicLabRunRequest) -> None:
    for field_name, value in (
        ("job_id", request.job_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    validate_atomic_metadata(request.metadata)


def _string(raw: Mapping[str, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing_{key}")
    return value.strip()


def _optional_string(raw: Mapping[str, object], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"invalid_{key}")
    stripped = value.strip()
    return stripped or None


def _string_sequence(raw: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = raw.get(key)
    if not isinstance(value, (tuple, list)) or not value:
        raise ValueError(f"missing_{key}")
    result = tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
    if len(result) != len(value):
        raise ValueError(f"invalid_{key}")
    return result


def _normalized_platform(value: str) -> str:
    _require_non_empty("platform", value)
    return value.strip().lower()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
