"""Structured audit and security event export contracts.

The exporter is metadata-only. It never ships events to a SIEM endpoint and
never includes raw audit details or raw evidence bytes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.evidence_chain import (
    AuditAction,
    EvidenceAccessPolicy,
    EvidenceChain,
    EvidenceRecord,
    ImmutableAuditEvent,
    RedactionStatus,
    RetentionClass,
)
from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output


class SecurityEventType(str, Enum):
    AUTHORIZATION = "authorization"
    RUNNER = "runner"
    EVIDENCE = "evidence"
    KILL_SWITCH = "kill_switch"
    REDACTION = "redaction"
    REPORTING = "reporting"
    EXPORT = "export"
    AUDIT = "audit"


@dataclass(frozen=True, kw_only=True)
class SecurityEventExportProfile:
    profile_id: str
    schema_version: str
    destination_label: str
    include_retention_classes: tuple[RetentionClass, ...]
    retention_cutoff_at: datetime | None = None
    preserve_legal_hold: bool = True


@dataclass(frozen=True, kw_only=True)
class EvidenceEventReference:
    evidence_id: str
    source_job_id: str
    kind: str
    redaction_status: RedactionStatus
    retention_class: RetentionClass
    access_policy: EvidenceAccessPolicy
    content_hash: str
    metadata_hash: str
    integrity_hash: str


@dataclass(frozen=True, kw_only=True)
class EventIntegrityMetadata:
    source_event_hash: str
    previous_event_hash: str | None
    details_hash: str
    evidence_integrity_hashes: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class SecurityEventEnvelope:
    schema_version: str
    event_id: str
    event_type: SecurityEventType
    action: AuditAction
    organization_id: str
    actor_user_id: str | None
    subject_type: str
    subject_id: str
    occurred_at: datetime
    target_reference: str | None
    policy_decision_reference: str | None
    evidence_references: tuple[EvidenceEventReference, ...]
    redaction_status: RedactionStatus
    retention_class: RetentionClass | None
    access_policy: EvidenceAccessPolicy | None
    integrity: EventIntegrityMetadata
    export_hash: str


@dataclass(frozen=True, kw_only=True)
class SecurityEventExportRequest:
    export_id: str
    organization_id: str
    exported_by_user_id: str
    exported_at: datetime
    audit_chain: EvidenceChain
    evidence_records: tuple[EvidenceRecord, ...]
    profile: SecurityEventExportProfile


@dataclass(frozen=True, kw_only=True)
class SecurityEventExportBatch:
    export_id: str
    organization_id: str
    schema_version: str
    destination_label: str
    exported_by_user_id: str
    exported_at: datetime
    source_event_count: int
    exported_event_count: int
    events: tuple[SecurityEventEnvelope, ...]
    batch_hash: str


def build_security_event_export(request: SecurityEventExportRequest) -> SecurityEventExportBatch:
    _validate_request(request)
    retained_evidence = tuple(_retained_evidence(record, request.profile) for record in request.evidence_records)
    evidence_records = tuple(record for record in retained_evidence if record is not None)
    events = tuple(
        _build_envelope(
            event=event,
            evidence_records=evidence_records,
            profile=request.profile,
        )
        for event in request.audit_chain.audit_events
        if event.organization_id == request.organization_id
    )
    payload = {
        "export_id": request.export_id.strip(),
        "organization_id": request.organization_id.strip(),
        "schema_version": request.profile.schema_version.strip(),
        "destination_label": request.profile.destination_label.strip(),
        "exported_by_user_id": request.exported_by_user_id.strip(),
        "exported_at": request.exported_at.isoformat(),
        "source_event_count": len(request.audit_chain.audit_events),
        "exported_event_hashes": tuple(event.export_hash for event in events),
    }
    _ensure_export_payload_safe(payload)
    return SecurityEventExportBatch(
        export_id=request.export_id.strip(),
        organization_id=request.organization_id.strip(),
        schema_version=request.profile.schema_version.strip(),
        destination_label=request.profile.destination_label.strip(),
        exported_by_user_id=request.exported_by_user_id.strip(),
        exported_at=request.exported_at,
        source_event_count=len(request.audit_chain.audit_events),
        exported_event_count=len(events),
        events=events,
        batch_hash=_canonical_sha256(payload),
    )


def validate_security_event_envelope(envelope: SecurityEventEnvelope) -> None:
    _require_non_empty("schema_version", envelope.schema_version)
    _require_non_empty("event_id", envelope.event_id)
    _require_non_empty("organization_id", envelope.organization_id)
    _require_non_empty("subject_type", envelope.subject_type)
    _require_non_empty("subject_id", envelope.subject_id)
    _require_timezone(envelope.occurred_at)
    _require_non_empty("source_event_hash", envelope.integrity.source_event_hash)
    _require_non_empty("details_hash", envelope.integrity.details_hash)
    expected_hash = _envelope_hash(envelope, include_export_hash=False)
    if envelope.export_hash != expected_hash:
        raise ValueError("security_event_export_hash_mismatch")
    _ensure_export_payload_safe(_envelope_payload(envelope, include_export_hash=True))


def replay_batch_hash(batch: SecurityEventExportBatch) -> str:
    payload = {
        "export_id": batch.export_id,
        "organization_id": batch.organization_id,
        "schema_version": batch.schema_version,
        "destination_label": batch.destination_label,
        "exported_by_user_id": batch.exported_by_user_id,
        "exported_at": batch.exported_at.isoformat(),
        "source_event_count": batch.source_event_count,
        "exported_event_hashes": tuple(event.export_hash for event in batch.events),
    }
    return _canonical_sha256(payload)


def _build_envelope(
    *,
    event: ImmutableAuditEvent,
    evidence_records: tuple[EvidenceRecord, ...],
    profile: SecurityEventExportProfile,
) -> SecurityEventEnvelope:
    evidence_refs = _evidence_references_for_event(event, evidence_records)
    redaction_status = _aggregate_redaction_status(evidence_refs)
    retention_class = _aggregate_retention_class(evidence_refs)
    access_policy = _aggregate_access_policy(evidence_refs)
    integrity = EventIntegrityMetadata(
        source_event_hash=event.event_hash,
        previous_event_hash=event.previous_hash,
        details_hash=event.details_hash,
        evidence_integrity_hashes=tuple(ref.integrity_hash for ref in evidence_refs),
    )
    envelope = SecurityEventEnvelope(
        schema_version=profile.schema_version.strip(),
        event_id=event.id,
        event_type=_event_type(event),
        action=event.action,
        organization_id=event.organization_id,
        actor_user_id=event.actor_user_id,
        subject_type=event.subject_type,
        subject_id=event.subject_id,
        occurred_at=event.occurred_at,
        target_reference=_target_reference(event),
        policy_decision_reference=_policy_decision_reference(event),
        evidence_references=evidence_refs,
        redaction_status=redaction_status,
        retention_class=retention_class,
        access_policy=access_policy,
        integrity=integrity,
        export_hash="",
    )
    export_hash = _envelope_hash(envelope, include_export_hash=False)
    finalized = SecurityEventEnvelope(
        schema_version=envelope.schema_version,
        event_id=envelope.event_id,
        event_type=envelope.event_type,
        action=envelope.action,
        organization_id=envelope.organization_id,
        actor_user_id=envelope.actor_user_id,
        subject_type=envelope.subject_type,
        subject_id=envelope.subject_id,
        occurred_at=envelope.occurred_at,
        target_reference=envelope.target_reference,
        policy_decision_reference=envelope.policy_decision_reference,
        evidence_references=envelope.evidence_references,
        redaction_status=envelope.redaction_status,
        retention_class=envelope.retention_class,
        access_policy=envelope.access_policy,
        integrity=envelope.integrity,
        export_hash=export_hash,
    )
    validate_security_event_envelope(finalized)
    return finalized


def _event_type(event: ImmutableAuditEvent) -> SecurityEventType:
    subject = event.subject_type.lower()
    if event.action is AuditAction.POLICY_DECISION:
        if "redaction" in subject:
            return SecurityEventType.REDACTION
        return SecurityEventType.AUTHORIZATION
    if event.action in {AuditAction.JOB_LIFECYCLE, AuditAction.RUNNER_CALLBACK}:
        return SecurityEventType.RUNNER
    if event.action is AuditAction.EVIDENCE_CREATION:
        return SecurityEventType.EVIDENCE
    if event.action is AuditAction.SCHEDULER_CONTROL and "kill" in subject:
        return SecurityEventType.KILL_SWITCH
    if event.action is AuditAction.REPORT_GENERATION:
        return SecurityEventType.REPORTING
    if event.action is AuditAction.EXPORT:
        return SecurityEventType.EXPORT
    return SecurityEventType.AUDIT


def _target_reference(event: ImmutableAuditEvent) -> str | None:
    if event.subject_type in {"target", "scope_target", "active_job_request", "job", "kill_switch"}:
        return event.subject_id
    return None


def _policy_decision_reference(event: ImmutableAuditEvent) -> str | None:
    if event.action is AuditAction.POLICY_DECISION:
        return event.id
    return None


def _evidence_references_for_event(
    event: ImmutableAuditEvent,
    evidence_records: tuple[EvidenceRecord, ...],
) -> tuple[EvidenceEventReference, ...]:
    refs = []
    for record in sorted(evidence_records, key=lambda item: item.id):
        if record.organization_id != event.organization_id:
            continue
        if event.subject_type == "evidence" and record.id != event.subject_id:
            continue
        if event.subject_type in {"job", "runner_callback"} and record.source_job_id != event.subject_id:
            continue
        if event.subject_type not in {"evidence", "job", "runner_callback"}:
            continue
        refs.append(_evidence_reference(record))
    return tuple(refs)


def _evidence_reference(record: EvidenceRecord) -> EvidenceEventReference:
    return EvidenceEventReference(
        evidence_id=record.id,
        source_job_id=record.source_job_id,
        kind=record.kind.value,
        redaction_status=record.redaction_status,
        retention_class=record.retention_class,
        access_policy=record.access_policy,
        content_hash=record.content_hash,
        metadata_hash=record.metadata_hash,
        integrity_hash=record.integrity_hash,
    )


def _retained_evidence(record: EvidenceRecord, profile: SecurityEventExportProfile) -> EvidenceRecord | None:
    if profile.preserve_legal_hold and record.retention_class is RetentionClass.LEGAL_HOLD:
        return record
    if record.retention_class not in profile.include_retention_classes:
        return None
    if profile.retention_cutoff_at is not None and record.created_at < profile.retention_cutoff_at:
        return None
    return record


def _aggregate_redaction_status(refs: tuple[EvidenceEventReference, ...]) -> RedactionStatus:
    statuses = {ref.redaction_status for ref in refs}
    if RedactionStatus.BLOCKED in statuses:
        return RedactionStatus.BLOCKED
    if RedactionStatus.REDACTED in statuses:
        return RedactionStatus.REDACTED
    if RedactionStatus.RAW_ALLOWED in statuses:
        return RedactionStatus.RAW_ALLOWED
    return RedactionStatus.NOT_APPLICABLE


def _aggregate_retention_class(refs: tuple[EvidenceEventReference, ...]) -> RetentionClass | None:
    classes = {ref.retention_class for ref in refs}
    if RetentionClass.LEGAL_HOLD in classes:
        return RetentionClass.LEGAL_HOLD
    if RetentionClass.STANDARD in classes:
        return RetentionClass.STANDARD
    if RetentionClass.SHORT in classes:
        return RetentionClass.SHORT
    return None


def _aggregate_access_policy(refs: tuple[EvidenceEventReference, ...]) -> EvidenceAccessPolicy | None:
    policies = {ref.access_policy for ref in refs}
    if EvidenceAccessPolicy.SECURITY_LEADS_ONLY in policies:
        return EvidenceAccessPolicy.SECURITY_LEADS_ONLY
    if EvidenceAccessPolicy.REVIEWERS_ONLY in policies:
        return EvidenceAccessPolicy.REVIEWERS_ONLY
    if EvidenceAccessPolicy.ENGAGEMENT_MEMBERS in policies:
        return EvidenceAccessPolicy.ENGAGEMENT_MEMBERS
    return None


def _validate_request(request: SecurityEventExportRequest) -> None:
    for field_name, value in (
        ("export_id", request.export_id),
        ("organization_id", request.organization_id),
        ("exported_by_user_id", request.exported_by_user_id),
        ("profile_id", request.profile.profile_id),
        ("schema_version", request.profile.schema_version),
        ("destination_label", request.profile.destination_label),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.exported_at)
    if request.profile.retention_cutoff_at is not None:
        _require_timezone(request.profile.retention_cutoff_at)
    if not request.profile.include_retention_classes and not request.profile.preserve_legal_hold:
        raise ValueError("retention_policy_exports_nothing")


def _envelope_hash(envelope: SecurityEventEnvelope, *, include_export_hash: bool) -> str:
    return _canonical_sha256(_envelope_payload(envelope, include_export_hash=include_export_hash))


def _envelope_payload(envelope: SecurityEventEnvelope, *, include_export_hash: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": envelope.schema_version,
        "event_id": envelope.event_id,
        "event_type": envelope.event_type.value,
        "action": envelope.action.value,
        "organization_id": envelope.organization_id,
        "actor_user_id": envelope.actor_user_id,
        "subject_type": envelope.subject_type,
        "subject_id": envelope.subject_id,
        "occurred_at": envelope.occurred_at.isoformat(),
        "target_reference": envelope.target_reference,
        "policy_decision_reference": envelope.policy_decision_reference,
        "evidence_references": tuple(_evidence_ref_payload(ref) for ref in envelope.evidence_references),
        "redaction_status": envelope.redaction_status.value,
        "retention_class": envelope.retention_class.value if envelope.retention_class else None,
        "access_policy": envelope.access_policy.value if envelope.access_policy else None,
        "integrity": {
            "source_event_hash": envelope.integrity.source_event_hash,
            "previous_event_hash": envelope.integrity.previous_event_hash,
            "details_hash": envelope.integrity.details_hash,
            "evidence_integrity_hashes": envelope.integrity.evidence_integrity_hashes,
        },
    }
    if include_export_hash:
        payload["export_hash"] = envelope.export_hash
    return payload


def _evidence_ref_payload(ref: EvidenceEventReference) -> dict[str, object]:
    return {
        "evidence_id": ref.evidence_id,
        "source_job_id": ref.source_job_id,
        "kind": ref.kind,
        "redaction_status": ref.redaction_status.value,
        "retention_class": ref.retention_class.value,
        "access_policy": ref.access_policy.value,
        "content_hash": ref.content_hash,
        "metadata_hash": ref.metadata_hash,
        "integrity_hash": ref.integrity_hash,
    }


def _ensure_export_payload_safe(payload: dict[str, object]) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    try:
        assert_no_sensitive_output(encoded, RedactionArtifactClass.JSON_SARIF)
    except ValueError as exc:
        raise ValueError("sensitive_event_field_forbidden") from exc


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
