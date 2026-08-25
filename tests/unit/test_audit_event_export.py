from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import audit_event_export, domain, evidence_chain


NOW = datetime(2026, 7, 9, 14, 20, tzinfo=timezone.utc)


def profile(**overrides: object) -> audit_event_export.SecurityEventExportProfile:
    values = {
        "profile_id": "siem-profile-1",
        "schema_version": "redagent.security_event.v1",
        "destination_label": "local-siem-buffer",
        "include_retention_classes": (
            evidence_chain.RetentionClass.SHORT,
            evidence_chain.RetentionClass.STANDARD,
        ),
        "retention_cutoff_at": None,
        "preserve_legal_hold": True,
    }
    values.update(overrides)
    return audit_event_export.SecurityEventExportProfile(**values)  # type: ignore[arg-type]


def evidence_record(
    *,
    evidence_id: str = "evidence-1",
    source_job_id: str = "job-1",
    created_at: datetime = NOW,
    redaction_status: evidence_chain.RedactionStatus = evidence_chain.RedactionStatus.REDACTED,
    retention_class: evidence_chain.RetentionClass = evidence_chain.RetentionClass.STANDARD,
    access_policy: evidence_chain.EvidenceAccessPolicy = evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
) -> evidence_chain.EvidenceRecord:
    content = None if redaction_status is evidence_chain.RedactionStatus.BLOCKED else b"redacted evidence"
    chain = evidence_chain.EvidenceChain().append_evidence_record(
        evidence_id=evidence_id,
        organization_id="org-1",
        source_job_id=source_job_id,
        kind=domain.EvidenceKind.COMMAND_LOG,
        created_at=created_at,
        redaction_status=redaction_status,
        retention_class=retention_class,
        access_policy=access_policy,
        content=content,
        contains_sensitive_capture=redaction_status is evidence_chain.RedactionStatus.REDACTED,
        metadata={"source": "unit-test"},
    )
    return chain.evidence_records[0]


def audit_chain_with_events() -> evidence_chain.EvidenceChain:
    return (
        evidence_chain.EvidenceChain()
        .append_audit_event(
            event_id="policy-1",
            organization_id="org-1",
            actor_user_id="operator-1",
            action=evidence_chain.AuditAction.POLICY_DECISION,
            subject_type="active_job_request",
            subject_id="job-1",
            occurred_at=NOW,
            details={"outcome": "allow", "details_are_hashed": True},
        )
        .append_audit_event(
            event_id="runner-1",
            organization_id="org-1",
            actor_user_id="runner-1",
            action=evidence_chain.AuditAction.JOB_LIFECYCLE,
            subject_type="job",
            subject_id="job-1",
            occurred_at=NOW + timedelta(seconds=1),
            details={"transition": "completed"},
        )
    )


def request(
    *,
    audit_chain_obj: evidence_chain.EvidenceChain | None = None,
    evidence_records: tuple[evidence_chain.EvidenceRecord, ...] | None = None,
    export_profile: audit_event_export.SecurityEventExportProfile | None = None,
) -> audit_event_export.SecurityEventExportRequest:
    return audit_event_export.SecurityEventExportRequest(
        export_id="export-1",
        organization_id="org-1",
        exported_by_user_id="auditor-1",
        exported_at=NOW + timedelta(minutes=5),
        audit_chain=audit_chain_obj or audit_chain_with_events(),
        evidence_records=evidence_records if evidence_records is not None else (evidence_record(),),
        profile=export_profile or profile(),
    )


def test_event_schema_includes_actor_references_and_integrity_metadata() -> None:
    batch = audit_event_export.build_security_event_export(request())

    assert batch.schema_version == "redagent.security_event.v1"
    assert batch.source_event_count == 2
    assert batch.exported_event_count == 2
    policy_event = batch.events[0]
    audit_event_export.validate_security_event_envelope(policy_event)
    assert policy_event.event_type is audit_event_export.SecurityEventType.AUTHORIZATION
    assert policy_event.actor_user_id == "operator-1"
    assert policy_event.target_reference == "job-1"
    assert policy_event.policy_decision_reference == "policy-1"
    assert policy_event.integrity.source_event_hash
    assert policy_event.integrity.details_hash


def test_secret_like_event_fields_are_blocked_from_export() -> None:
    unsafe_chain = evidence_chain.EvidenceChain().append_audit_event(
        event_id="policy-unsafe",
        organization_id="org-1",
        actor_user_id="operator-1",
        action=evidence_chain.AuditAction.POLICY_DECISION,
        subject_type="active_job_request",
        subject_id="session=abc123",
        occurred_at=NOW,
        details={"details_are_hashed": True},
    )

    with pytest.raises(ValueError, match="sensitive_event_field_forbidden"):
        audit_event_export.build_security_event_export(request(audit_chain_obj=unsafe_chain))


def test_runner_event_export_attaches_evidence_references_without_raw_content() -> None:
    batch = audit_event_export.build_security_event_export(request())
    runner_event = batch.events[1]

    assert runner_event.event_type is audit_event_export.SecurityEventType.RUNNER
    assert runner_event.evidence_references[0].evidence_id == "evidence-1"
    assert runner_event.evidence_references[0].content_hash
    assert runner_event.redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert "redacted evidence" not in runner_event.export_hash


def test_kill_switch_event_export_is_classified_for_soc_triage() -> None:
    kill_chain = evidence_chain.EvidenceChain().append_audit_event(
        event_id="kill-1",
        organization_id="org-1",
        actor_user_id="lead-1",
        action=evidence_chain.AuditAction.SCHEDULER_CONTROL,
        subject_type="kill_switch",
        subject_id="eng-1",
        occurred_at=NOW,
        details={"reason": "operator_stop"},
    )

    batch = audit_event_export.build_security_event_export(
        request(audit_chain_obj=kill_chain, evidence_records=())
    )

    assert batch.events[0].event_type is audit_event_export.SecurityEventType.KILL_SWITCH
    assert batch.events[0].target_reference == "eng-1"


def test_evidence_reference_export_preserves_redaction_retention_and_access_metadata() -> None:
    record = evidence_record(
        redaction_status=evidence_chain.RedactionStatus.BLOCKED,
        retention_class=evidence_chain.RetentionClass.LEGAL_HOLD,
        access_policy=evidence_chain.EvidenceAccessPolicy.SECURITY_LEADS_ONLY,
    )
    chain = evidence_chain.EvidenceChain().append_audit_event(
        event_id="evidence-created-1",
        organization_id="org-1",
        actor_user_id="runner-1",
        action=evidence_chain.AuditAction.EVIDENCE_CREATION,
        subject_type="evidence",
        subject_id=record.id,
        occurred_at=NOW,
        details={"recorded": True},
    )

    batch = audit_event_export.build_security_event_export(
        request(audit_chain_obj=chain, evidence_records=(record,))
    )

    event = batch.events[0]
    assert event.event_type is audit_event_export.SecurityEventType.EVIDENCE
    assert event.redaction_status is evidence_chain.RedactionStatus.BLOCKED
    assert event.retention_class is evidence_chain.RetentionClass.LEGAL_HOLD
    assert event.access_policy is evidence_chain.EvidenceAccessPolicy.SECURITY_LEADS_ONLY
    assert event.evidence_references[0].integrity_hash == record.integrity_hash


def test_retention_filtering_drops_expired_standard_evidence_but_preserves_legal_hold() -> None:
    old_standard = evidence_record(
        evidence_id="evidence-old",
        created_at=NOW - timedelta(days=30),
        retention_class=evidence_chain.RetentionClass.STANDARD,
    )
    legal_hold = evidence_record(
        evidence_id="evidence-legal",
        created_at=NOW - timedelta(days=90),
        retention_class=evidence_chain.RetentionClass.LEGAL_HOLD,
    )
    chain = (
        evidence_chain.EvidenceChain()
        .append_audit_event(
            event_id="old-evidence-event",
            organization_id="org-1",
            actor_user_id="runner-1",
            action=evidence_chain.AuditAction.EVIDENCE_CREATION,
            subject_type="evidence",
            subject_id=old_standard.id,
            occurred_at=NOW,
            details={"recorded": True},
        )
        .append_audit_event(
            event_id="legal-evidence-event",
            organization_id="org-1",
            actor_user_id="runner-1",
            action=evidence_chain.AuditAction.EVIDENCE_CREATION,
            subject_type="evidence",
            subject_id=legal_hold.id,
            occurred_at=NOW + timedelta(seconds=1),
            details={"recorded": True},
        )
    )
    batch = audit_event_export.build_security_event_export(
        request(
            audit_chain_obj=chain,
            evidence_records=(old_standard, legal_hold),
            export_profile=profile(retention_cutoff_at=NOW - timedelta(days=7)),
        )
    )

    assert batch.events[0].evidence_references == ()
    assert batch.events[1].evidence_references[0].evidence_id == "evidence-legal"


def test_export_replay_is_deterministic() -> None:
    export_request = request()
    first = audit_event_export.build_security_event_export(export_request)
    second = audit_event_export.build_security_event_export(export_request)

    assert first.batch_hash == second.batch_hash
    assert audit_event_export.replay_batch_hash(first) == first.batch_hash
    assert tuple(event.export_hash for event in first.events) == tuple(event.export_hash for event in second.events)
