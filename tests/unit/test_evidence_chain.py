from dataclasses import replace
from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_chain


NOW = datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc)


def test_audit_action_taxonomy_covers_r008_required_actions() -> None:
    assert evidence_chain.missing_required_audit_actions(set(evidence_chain.AuditAction)) == ()
    assert evidence_chain.REQUIRED_AUDIT_ACTIONS == {
        evidence_chain.AuditAction.LOGIN,
        evidence_chain.AuditAction.POLICY_DECISION,
        evidence_chain.AuditAction.TARGET_CHANGE,
        evidence_chain.AuditAction.JOB_LIFECYCLE,
        evidence_chain.AuditAction.RUNNER_CALLBACK,
        evidence_chain.AuditAction.EVIDENCE_CREATION,
        evidence_chain.AuditAction.FINDING_CHANGE,
        evidence_chain.AuditAction.REPORT_GENERATION,
        evidence_chain.AuditAction.EXPORT,
    }


def test_audit_events_are_hash_chained() -> None:
    chain = evidence_chain.EvidenceChain()
    chain = chain.append_audit_event(
        event_id="audit-1",
        organization_id="org-1",
        actor_user_id="user-1",
        action=evidence_chain.AuditAction.LOGIN,
        subject_type="session",
        subject_id="session-1",
        occurred_at=NOW,
        details={"result": "success"},
    )
    chain = chain.append_audit_event(
        event_id="audit-2",
        organization_id="org-1",
        actor_user_id="user-1",
        action=evidence_chain.AuditAction.POLICY_DECISION,
        subject_type="policy_decision",
        subject_id="decision-1",
        occurred_at=NOW,
        details={"outcome": "allow"},
    )

    assert chain.audit_events[0].previous_hash is None
    assert chain.audit_events[1].previous_hash == chain.audit_events[0].event_hash
    assert chain.audit_events[0].event_hash != chain.audit_events[1].event_hash


def test_evidence_record_contains_required_chain_metadata() -> None:
    chain = evidence_chain.EvidenceChain().append_evidence_record(
        evidence_id="evidence-1",
        organization_id="org-1",
        source_job_id="job-1",
        kind=domain.EvidenceKind.HTTP_METADATA,
        created_at=NOW,
        redaction_status=evidence_chain.RedactionStatus.NOT_APPLICABLE,
        retention_class=evidence_chain.RetentionClass.STANDARD,
        access_policy=evidence_chain.EvidenceAccessPolicy.ENGAGEMENT_MEMBERS,
        content=b"sanitized metadata",
        contains_sensitive_capture=False,
        metadata={"target": "example.com"},
    )

    record = chain.evidence_records[0]
    assert record.source_job_id == "job-1"
    assert record.created_at == NOW
    assert record.content_hash
    assert record.metadata_hash
    assert record.integrity_hash
    assert record.redaction_status is evidence_chain.RedactionStatus.NOT_APPLICABLE
    assert record.retention_class is evidence_chain.RetentionClass.STANDARD
    assert record.access_policy is evidence_chain.EvidenceAccessPolicy.ENGAGEMENT_MEMBERS
    assert evidence_chain.verify_evidence_record(record)


def test_sensitive_capture_requires_redacted_or_blocked_status() -> None:
    with pytest.raises(ValueError, match="sensitive_capture_requires_redacted_or_blocked_status"):
        evidence_chain.build_evidence_record(
            evidence_id="evidence-1",
            organization_id="org-1",
            source_job_id="job-1",
            kind=domain.EvidenceKind.SCANNER_OUTPUT,
            created_at=NOW,
            redaction_status=evidence_chain.RedactionStatus.RAW_ALLOWED,
            retention_class=evidence_chain.RetentionClass.STANDARD,
            access_policy=evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=b"raw request with sensitive data",
            contains_sensitive_capture=True,
            metadata={},
            previous_hash=None,
        )


def test_blocked_sensitive_capture_stores_marker_hash_only() -> None:
    record = evidence_chain.build_evidence_record(
        evidence_id="evidence-1",
        organization_id="org-1",
        source_job_id="job-1",
        kind=domain.EvidenceKind.SCANNER_OUTPUT,
        created_at=NOW,
        redaction_status=evidence_chain.RedactionStatus.BLOCKED,
        retention_class=evidence_chain.RetentionClass.SHORT,
        access_policy=evidence_chain.EvidenceAccessPolicy.SECURITY_LEADS_ONLY,
        content=None,
        contains_sensitive_capture=True,
        metadata={"reason": "blocked_by_redaction_policy"},
        previous_hash=None,
    )

    assert record.content_hash
    assert record.redaction_status is evidence_chain.RedactionStatus.BLOCKED
    assert evidence_chain.verify_evidence_record(record)


def test_blocked_capture_cannot_store_content() -> None:
    with pytest.raises(ValueError, match="blocked_capture_must_not_store_content"):
        evidence_chain.build_evidence_record(
            evidence_id="evidence-1",
            organization_id="org-1",
            source_job_id="job-1",
            kind=domain.EvidenceKind.SCANNER_OUTPUT,
            created_at=NOW,
            redaction_status=evidence_chain.RedactionStatus.BLOCKED,
            retention_class=evidence_chain.RetentionClass.STANDARD,
            access_policy=evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=b"must not be retained",
            contains_sensitive_capture=True,
            metadata={},
            previous_hash=None,
        )


def test_duplicate_evidence_id_cannot_silently_overwrite() -> None:
    chain = evidence_chain.EvidenceChain().append_evidence_record(
        evidence_id="evidence-1",
        organization_id="org-1",
        source_job_id="job-1",
        kind=domain.EvidenceKind.COMMAND_LOG,
        created_at=NOW,
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
        retention_class=evidence_chain.RetentionClass.LEGAL_HOLD,
        access_policy=evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=b"redacted command log",
        contains_sensitive_capture=True,
        metadata={"redactor": "policy"},
    )

    with pytest.raises(evidence_chain.EvidenceOverwriteError, match="evidence_id_already_exists"):
        chain.append_evidence_record(
            evidence_id="evidence-1",
            organization_id="org-1",
            source_job_id="job-2",
            kind=domain.EvidenceKind.COMMAND_LOG,
            created_at=NOW,
            redaction_status=evidence_chain.RedactionStatus.REDACTED,
            retention_class=evidence_chain.RetentionClass.LEGAL_HOLD,
            access_policy=evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=b"different redacted command log",
            contains_sensitive_capture=True,
            metadata={"redactor": "policy"},
        )


def test_metadata_tampering_breaks_integrity_verification() -> None:
    chain = evidence_chain.EvidenceChain().append_evidence_record(
        evidence_id="evidence-1",
        organization_id="org-1",
        source_job_id="job-1",
        kind=domain.EvidenceKind.COMMAND_LOG,
        created_at=NOW,
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
        retention_class=evidence_chain.RetentionClass.LEGAL_HOLD,
        access_policy=evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=b"redacted command log",
        contains_sensitive_capture=True,
        metadata={"redactor": "policy"},
    )
    record = chain.evidence_records[0]
    tampered = replace(record, source_job_id="job-tampered")

    assert evidence_chain.verify_evidence_record(record)
    assert not evidence_chain.verify_evidence_record(tampered)


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValueError, match="timezone_required"):
        evidence_chain.build_audit_event(
            event_id="audit-1",
            organization_id="org-1",
            actor_user_id="user-1",
            action=evidence_chain.AuditAction.LOGIN,
            subject_type="session",
            subject_id="session-1",
            occurred_at=datetime(2026, 7, 8, 12, 0),
            details={},
            previous_hash=None,
        )
