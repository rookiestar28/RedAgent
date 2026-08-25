"""Immutable audit and evidence chain contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform.domain import EvidenceKind


class AuditAction(str, Enum):
    LOGIN = "login"
    POLICY_DECISION = "policy_decision"
    TARGET_CHANGE = "target_change"
    TEST_DEFINITION_CHANGE = "test_definition_change"
    CREDENTIAL_LEASE = "credential_lease"
    SCHEDULER_CONTROL = "scheduler_control"
    JOB_LIFECYCLE = "job_lifecycle"
    RUNNER_CALLBACK = "runner_callback"
    EVIDENCE_CREATION = "evidence_creation"
    FINDING_CHANGE = "finding_change"
    REPORT_GENERATION = "report_generation"
    EXPORT = "export"


class RedactionStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    REDACTED = "redacted"
    BLOCKED = "blocked"
    RAW_ALLOWED = "raw_allowed"


class RetentionClass(str, Enum):
    SHORT = "short"
    STANDARD = "standard"
    LEGAL_HOLD = "legal_hold"


class EvidenceAccessPolicy(str, Enum):
    ENGAGEMENT_MEMBERS = "engagement_members"
    REVIEWERS_ONLY = "reviewers_only"
    SECURITY_LEADS_ONLY = "security_leads_only"


class EvidenceOverwriteError(ValueError):
    """Raised when a duplicate evidence id would overwrite chain history."""


@dataclass(frozen=True, kw_only=True)
class ImmutableAuditEvent:
    id: str
    organization_id: str
    actor_user_id: str | None
    action: AuditAction
    subject_type: str
    subject_id: str
    occurred_at: datetime
    details_hash: str
    previous_hash: str | None
    event_hash: str


@dataclass(frozen=True, kw_only=True)
class EvidenceRecord:
    id: str
    organization_id: str
    source_job_id: str
    kind: EvidenceKind
    created_at: datetime
    redaction_status: RedactionStatus
    retention_class: RetentionClass
    access_policy: EvidenceAccessPolicy
    content_hash: str
    metadata_hash: str
    previous_hash: str | None
    integrity_hash: str


@dataclass(frozen=True)
class EvidenceChain:
    audit_events: tuple[ImmutableAuditEvent, ...] = ()
    evidence_records: tuple[EvidenceRecord, ...] = ()

    def append_audit_event(
        self,
        *,
        event_id: str,
        organization_id: str,
        actor_user_id: str | None,
        action: AuditAction,
        subject_type: str,
        subject_id: str,
        occurred_at: datetime,
        details: Mapping[str, object] | None = None,
    ) -> "EvidenceChain":
        event = build_audit_event(
            event_id=event_id,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            subject_type=subject_type,
            subject_id=subject_id,
            occurred_at=occurred_at,
            details=details or {},
            previous_hash=self.audit_events[-1].event_hash if self.audit_events else None,
        )
        return EvidenceChain(
            audit_events=self.audit_events + (event,),
            evidence_records=self.evidence_records,
        )

    def append_evidence_record(
        self,
        *,
        evidence_id: str,
        organization_id: str,
        source_job_id: str,
        kind: EvidenceKind,
        created_at: datetime,
        redaction_status: RedactionStatus,
        retention_class: RetentionClass,
        access_policy: EvidenceAccessPolicy,
        content: bytes | None,
        contains_sensitive_capture: bool,
        metadata: Mapping[str, object] | None = None,
    ) -> "EvidenceChain":
        if any(record.id == evidence_id for record in self.evidence_records):
            raise EvidenceOverwriteError("evidence_id_already_exists")
        record = build_evidence_record(
            evidence_id=evidence_id,
            organization_id=organization_id,
            source_job_id=source_job_id,
            kind=kind,
            created_at=created_at,
            redaction_status=redaction_status,
            retention_class=retention_class,
            access_policy=access_policy,
            content=content,
            contains_sensitive_capture=contains_sensitive_capture,
            metadata=metadata or {},
            previous_hash=self.evidence_records[-1].integrity_hash if self.evidence_records else None,
        )
        return EvidenceChain(
            audit_events=self.audit_events,
            evidence_records=self.evidence_records + (record,),
        )


REQUIRED_AUDIT_ACTIONS: frozenset[AuditAction] = frozenset(
    {
        AuditAction.LOGIN,
        AuditAction.POLICY_DECISION,
        AuditAction.TARGET_CHANGE,
        AuditAction.JOB_LIFECYCLE,
        AuditAction.RUNNER_CALLBACK,
        AuditAction.EVIDENCE_CREATION,
        AuditAction.FINDING_CHANGE,
        AuditAction.REPORT_GENERATION,
        AuditAction.EXPORT,
    }
)


def missing_required_audit_actions(actions: set[AuditAction]) -> tuple[AuditAction, ...]:
    return tuple(sorted(REQUIRED_AUDIT_ACTIONS - actions, key=lambda action: action.value))


def build_audit_event(
    *,
    event_id: str,
    organization_id: str,
    actor_user_id: str | None,
    action: AuditAction,
    subject_type: str,
    subject_id: str,
    occurred_at: datetime,
    details: Mapping[str, object],
    previous_hash: str | None,
) -> ImmutableAuditEvent:
    _require_non_empty("event_id", event_id)
    _require_non_empty("organization_id", organization_id)
    _require_non_empty("subject_type", subject_type)
    _require_non_empty("subject_id", subject_id)
    _require_timezone(occurred_at)

    details_hash = _canonical_sha256(details)
    event_payload = {
        "id": event_id.strip(),
        "organization_id": organization_id.strip(),
        "actor_user_id": actor_user_id,
        "action": action.value,
        "subject_type": subject_type.strip(),
        "subject_id": subject_id.strip(),
        "occurred_at": occurred_at.isoformat(),
        "details_hash": details_hash,
        "previous_hash": previous_hash,
    }
    return ImmutableAuditEvent(
        id=event_id.strip(),
        organization_id=organization_id.strip(),
        actor_user_id=actor_user_id,
        action=action,
        subject_type=subject_type.strip(),
        subject_id=subject_id.strip(),
        occurred_at=occurred_at,
        details_hash=details_hash,
        previous_hash=previous_hash,
        event_hash=_canonical_sha256(event_payload),
    )


def build_evidence_record(
    *,
    evidence_id: str,
    organization_id: str,
    source_job_id: str,
    kind: EvidenceKind,
    created_at: datetime,
    redaction_status: RedactionStatus,
    retention_class: RetentionClass,
    access_policy: EvidenceAccessPolicy,
    content: bytes | None,
    contains_sensitive_capture: bool,
    metadata: Mapping[str, object],
    previous_hash: str | None,
) -> EvidenceRecord:
    _require_non_empty("evidence_id", evidence_id)
    _require_non_empty("organization_id", organization_id)
    _require_non_empty("source_job_id", source_job_id)
    _require_timezone(created_at)
    _enforce_sensitive_capture_policy(redaction_status, content, contains_sensitive_capture)

    content_hash = _content_hash(content, redaction_status)
    metadata_hash = _canonical_sha256(metadata)
    record_payload = {
        "id": evidence_id.strip(),
        "organization_id": organization_id.strip(),
        "source_job_id": source_job_id.strip(),
        "kind": kind.value,
        "created_at": created_at.isoformat(),
        "redaction_status": redaction_status.value,
        "retention_class": retention_class.value,
        "access_policy": access_policy.value,
        "content_hash": content_hash,
        "metadata_hash": metadata_hash,
        "previous_hash": previous_hash,
    }
    return EvidenceRecord(
        id=evidence_id.strip(),
        organization_id=organization_id.strip(),
        source_job_id=source_job_id.strip(),
        kind=kind,
        created_at=created_at,
        redaction_status=redaction_status,
        retention_class=retention_class,
        access_policy=access_policy,
        content_hash=content_hash,
        metadata_hash=metadata_hash,
        previous_hash=previous_hash,
        integrity_hash=_canonical_sha256(record_payload),
    )


def verify_evidence_record(record: EvidenceRecord) -> bool:
    payload = {
        "id": record.id,
        "organization_id": record.organization_id,
        "source_job_id": record.source_job_id,
        "kind": record.kind.value,
        "created_at": record.created_at.isoformat(),
        "redaction_status": record.redaction_status.value,
        "retention_class": record.retention_class.value,
        "access_policy": record.access_policy.value,
        "content_hash": record.content_hash,
        "metadata_hash": record.metadata_hash,
        "previous_hash": record.previous_hash,
    }
    return _canonical_sha256(payload) == record.integrity_hash


def _enforce_sensitive_capture_policy(
    redaction_status: RedactionStatus,
    content: bytes | None,
    contains_sensitive_capture: bool,
) -> None:
    if contains_sensitive_capture and redaction_status not in {RedactionStatus.REDACTED, RedactionStatus.BLOCKED}:
        raise ValueError("sensitive_capture_requires_redacted_or_blocked_status")
    if redaction_status is RedactionStatus.BLOCKED and content:
        raise ValueError("blocked_capture_must_not_store_content")
    if redaction_status is not RedactionStatus.BLOCKED and content is None:
        raise ValueError("evidence_content_required_unless_blocked")


def _content_hash(content: bytes | None, redaction_status: RedactionStatus) -> str:
    if redaction_status is RedactionStatus.BLOCKED:
        return _canonical_sha256({"content": "blocked"})
    if content is None:
        raise ValueError("evidence_content_required_unless_blocked")
    return hashlib.sha256(content).hexdigest()


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
