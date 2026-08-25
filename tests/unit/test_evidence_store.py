from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_chain, evidence_store, reporting


NOW = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)


def write_request(**overrides: object) -> evidence_store.EvidenceArtifactWriteRequest:
    values = {
        "evidence_id": "evidence-1",
        "organization_id": "org-1",
        "source_job_id": "job-1",
        "kind": domain.EvidenceKind.COMMAND_LOG,
        "created_at": NOW,
        "redaction_status": evidence_chain.RedactionStatus.REDACTED,
        "retention_class": evidence_chain.RetentionClass.STANDARD,
        "access_policy": evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
        "content": b"redacted command log",
        "contains_sensitive_capture": True,
        "artifact_metadata": {"source": "unit-test", "redaction": "applied"},
        "operator_user_id": "operator-1",
        "runner_id": "runner-1",
    }
    values.update(overrides)
    return evidence_store.EvidenceArtifactWriteRequest(**values)  # type: ignore[arg-type]


def approved_review() -> reporting.RedactionReview:
    return reporting.RedactionReview(
        review_id="review-1",
        status=reporting.RedactionReviewStatus.APPROVED,
        reviewer_user_id="reviewer-1",
        reviewed_at=NOW,
        notes="Approved for external export.",
    )


def pending_review() -> reporting.RedactionReview:
    return reporting.RedactionReview(
        review_id="review-2",
        status=reporting.RedactionReviewStatus.PENDING,
        reviewer_user_id=None,
        reviewed_at=None,
        notes="Pending review.",
    )


def test_redacted_capture_writes_manifest_and_verifies_artifact(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)

    result = store.write_artifact(write_request(), evidence_chain.EvidenceChain())

    manifest = result.manifest
    assert manifest.manifest_id == "evidence-1:manifest"
    assert manifest.content_hash == result.evidence_record.content_hash
    assert manifest.metadata_hash == result.evidence_record.metadata_hash
    assert manifest.evidence_integrity_hash == result.evidence_record.integrity_hash
    assert manifest.retention_class is evidence_chain.RetentionClass.STANDARD
    assert manifest.access_policy is evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY
    assert manifest.redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert manifest.source_job_id == "job-1"
    assert manifest.operator_user_id == "operator-1"
    assert manifest.runner_id == "runner-1"
    assert manifest.created_at == NOW
    assert store.verify_artifact("evidence-1").ok
    assert evidence_chain.verify_evidence_record(manifest.to_evidence_record())


def test_duplicate_evidence_id_fails_closed_without_overwrite(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    first = store.write_artifact(write_request(content=b"first redacted log"), evidence_chain.EvidenceChain())
    artifact_path = tmp_path / first.manifest.artifact_path
    original_content = artifact_path.read_bytes()

    with pytest.raises(evidence_chain.EvidenceOverwriteError, match="evidence_id_already_exists"):
        store.write_artifact(write_request(content=b"second redacted log"), evidence_chain.EvidenceChain())

    assert artifact_path.read_bytes() == original_content
    assert store.read_manifest("evidence-1").content_hash == first.manifest.content_hash


def test_blocked_capture_stores_manifest_without_artifact_bytes(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)

    result = store.write_artifact(
        write_request(
            redaction_status=evidence_chain.RedactionStatus.BLOCKED,
            retention_class=evidence_chain.RetentionClass.SHORT,
            access_policy=evidence_chain.EvidenceAccessPolicy.SECURITY_LEADS_ONLY,
            content=None,
            contains_sensitive_capture=True,
            artifact_metadata={"reason": "blocked_by_policy"},
        ),
        evidence_chain.EvidenceChain(),
    )

    assert result.manifest.artifact_path is None
    assert result.manifest.artifact_size_bytes == 0
    assert result.manifest.redaction_status is evidence_chain.RedactionStatus.BLOCKED
    assert store.verify_artifact("evidence-1").reason == "verified"
    assert not (tmp_path / "artifacts" / "evidence-1.bin").exists()


def test_legal_hold_prevents_disposal(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    store.write_artifact(
        write_request(retention_class=evidence_chain.RetentionClass.LEGAL_HOLD),
        evidence_chain.EvidenceChain(),
    )

    with pytest.raises(evidence_store.EvidenceArtifactRetentionError, match="legal_hold_prevents_disposal"):
        store.assert_disposal_allowed("evidence-1")


def test_missing_artifact_fails_repository_local_verification(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    result = store.write_artifact(write_request(), evidence_chain.EvidenceChain())
    (tmp_path / result.manifest.artifact_path).unlink()

    verification = store.verify_artifact("evidence-1")

    assert not verification.ok
    assert verification.reason == "missing_artifact"


def test_export_requires_redaction_review_and_records_audit_events(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    store.write_artifact(write_request(), evidence_chain.EvidenceChain())

    denied = store.export_artifact(
        evidence_store.EvidenceArtifactExportRequest(
            export_id="export-1",
            evidence_id="evidence-1",
            requested_by_user_id="operator-1",
            requested_at=NOW,
            redaction_review=pending_review(),
            destination_label="customer-report",
        ),
        evidence_chain.EvidenceChain(),
    )

    assert not denied.approved
    assert denied.denied_reason == "redaction_review_required"
    assert denied.content is None
    assert denied.audit_chain.audit_events[-1].action is evidence_chain.AuditAction.EXPORT

    approved = store.export_artifact(
        evidence_store.EvidenceArtifactExportRequest(
            export_id="export-2",
            evidence_id="evidence-1",
            requested_by_user_id="operator-1",
            requested_at=NOW,
            redaction_review=approved_review(),
            destination_label="customer-report",
        ),
        denied.audit_chain,
    )

    assert approved.approved
    assert approved.denied_reason is None
    assert approved.content == b"redacted command log"
    assert approved.audit_chain.audit_events[-1].action is evidence_chain.AuditAction.EXPORT
    assert approved.audit_chain.audit_events[-1].previous_hash == denied.audit_chain.audit_events[-1].event_hash


def test_report_evidence_lock_uses_store_evidence_record(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    result = store.write_artifact(write_request(), evidence_chain.EvidenceChain())
    record = result.manifest.to_evidence_record()

    report_result = reporting.generate_report_package(
        reporting.ReportInput(
            report_id="report-1",
            organization_id="org-1",
            title="Evidence Store Report",
            audience=reporting.ReportAudience.TECHNICAL,
            generated_by_user_id="reporter-1",
            generated_at=NOW,
            scope=reporting.ReportScope(
                engagement_id="eng-1",
                target_summary="local evidence store fixture",
                testing_window="2026-07-09 local unit test",
                allowed_modes=("local_fixture",),
            ),
            findings=(),
            evidence_records=(record,),
            methodology=("Verified immutable local evidence artifact store output.",),
            limitations=("No active target interaction was performed.",),
            redaction_review=approved_review(),
        ),
        evidence_chain.EvidenceChain(),
    )

    assert store.verify_artifact("evidence-1").ok
    assert report_result.package.evidence_lock_hash
    assert "[evidence: evidence-1]" in reporting.render_report_markdown(
        report_result.package,
        external_share=True,
    )
