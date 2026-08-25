from dataclasses import replace
from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_chain, findings, issue_connectors, report_publication, reporting


NOW = datetime(2026, 7, 9, 12, 20, tzinfo=timezone.utc)


def evidence_record() -> evidence_chain.EvidenceRecord:
    chain = evidence_chain.EvidenceChain().append_evidence_record(
        evidence_id="evidence-1",
        organization_id="org-1",
        source_job_id="job-1",
        kind=domain.EvidenceKind.REPORT_SOURCE,
        created_at=NOW,
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
        retention_class=evidence_chain.RetentionClass.STANDARD,
        access_policy=evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=b"redacted reviewed evidence",
        contains_sensitive_capture=True,
        metadata={"source": "unit-test"},
    )
    return chain.evidence_records[0]


def finding(record: evidence_chain.EvidenceRecord | None = None, **overrides: object) -> findings.FindingRecord:
    record = record or evidence_record()
    values = {
        "id": "finding-1",
        "title": "Missing strict transport security",
        "status": domain.FindingStatus.CONFIRMED,
        "affected_asset_id": "target-1",
        "affected_asset_value": "https://www.agentique.io",
        "confidence": findings.Confidence.CONFIRMED,
        "risk": findings.RiskFactors(
            severity=findings.Severity.HIGH,
            exploit_likelihood=findings.ExploitLikelihood.MEDIUM,
            asset_criticality=findings.AssetCriticality.HIGH,
            business_impact=findings.BusinessImpact.MODERATE,
            vulnerability_intelligence=findings.VulnerabilityIntelligence(
                cve_ids=("CVE-2026-12345",),
                cwe_ids=("CWE-693",),
                cvss_score=7.2,
                epss_probability=0.12,
                kev_listed=False,
            ),
        ),
        "reproduction_summary": "Confirmed from redacted passive metadata and reviewer decision.",
        "evidence_links": (
            findings.EvidenceLink(
                evidence_id=record.id,
                integrity_hash=record.integrity_hash,
                redaction_status=record.redaction_status,
                contains_sensitive_payload=True,
            ),
        ),
        "remediation": "Set the expected HTTP security header at the edge.",
        "owner_user_id": "owner-1",
        "source": "zap_passive",
        "source_rule_id": "10035",
    }
    values.update(overrides)
    return findings.FindingRecord(**values)  # type: ignore[arg-type]


def redaction_review(
    status: reporting.RedactionReviewStatus = reporting.RedactionReviewStatus.APPROVED,
) -> reporting.RedactionReview:
    return reporting.RedactionReview(
        review_id="review-1",
        status=status,
        reviewer_user_id="reviewer-1" if status is reporting.RedactionReviewStatus.APPROVED else None,
        reviewed_at=NOW if status is reporting.RedactionReviewStatus.APPROVED else None,
        notes="Approved for customer sharing." if status is reporting.RedactionReviewStatus.APPROVED else "Pending.",
    )


def report_input(**overrides: object) -> reporting.ReportInput:
    record = evidence_record()
    values = {
        "report_id": "report-1",
        "organization_id": "org-1",
        "title": "Agentique RedAgent Assessment",
        "audience": reporting.ReportAudience.TECHNICAL,
        "generated_by_user_id": "reporter-1",
        "generated_at": NOW,
        "scope": reporting.ReportScope(
            engagement_id="eng-1",
            target_summary="agentique.io and www.agentique.io",
            testing_window="2026-07-07 14:00-18:00 Asia/Taipei",
            allowed_modes=("passive_scan",),
        ),
        "findings": (finding(record),),
        "evidence_records": (record,),
        "methodology": ("Reviewed locked evidence and confirmed findings.",),
        "limitations": ("No active exploitation was performed.",),
        "redaction_review": redaction_review(),
        "canary_markers": ("CANARY-REPORT-SECRET",),
    }
    values.update(overrides)
    return reporting.ReportInput(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> report_publication.ReportPublicationProfile:
    values = {
        "profile_id": "publication-profile-1",
        "allow_customer_variant": True,
        "allow_issue_export": True,
        "require_approved_redaction": True,
        "require_confirmed_findings": True,
    }
    values.update(overrides)
    return report_publication.ReportPublicationProfile(**values)  # type: ignore[arg-type]


def review_state(**overrides: object) -> report_publication.PublicationReviewState:
    values = {
        "evidence_reviewed": True,
        "claim_reviewed": True,
        "redaction_reviewed": True,
        "internal_variant_ready": True,
        "customer_variant_ready": True,
        "approval_status": report_publication.PublicationApprovalStatus.APPROVED,
        "approved_by_user_id": "lead-1",
        "approved_at": NOW,
        "closeout_ready": True,
    }
    values.update(overrides)
    return report_publication.PublicationReviewState(**values)  # type: ignore[arg-type]


def connection() -> issue_connectors.IssueTrackerConnection:
    return issue_connectors.IssueTrackerConnection(
        connector_id="connector-1",
        kind=issue_connectors.ConnectorKind.GENERIC_ISSUE_TRACKER,
        display_name="Internal issue tracker",
        project_key="SEC",
        credential_reference_id="credential-ref-1",
        redaction_label="issue-tracker-token",
    )


def request(**overrides: object) -> report_publication.ReportPublicationRequest:
    values = {
        "publication_id": "publication-1",
        "report_input": report_input(),
        "review_state": review_state(),
        "profile": profile(),
        "requested_at": NOW,
        "actor_user_id": "publisher-1",
        "issue_connection": connection(),
        "existing_issue_exports": (),
        "canary_markers": ("CANARY-REPORT-SECRET",),
    }
    values.update(overrides)
    return report_publication.ReportPublicationRequest(**values)  # type: ignore[arg-type]


def test_publication_workflow_supports_review_variants_export_and_closeout() -> None:
    result = report_publication.build_publication_workflow(request(), evidence_chain.EvidenceChain())

    assert result.package.review_state.evidence_reviewed
    assert result.package.review_state.claim_reviewed
    assert result.package.review_state.redaction_reviewed
    assert tuple(variant.kind for variant in result.package.variants) == (
        report_publication.ReportVariantKind.INTERNAL,
        report_publication.ReportVariantKind.CUSTOMER,
    )
    assert result.package.export_state is report_publication.PublicationExportState.COMPLETE
    assert result.package.closeout_ready
    assert result.package.issue_exports[0].remediation_owner_user_id == "owner-1"
    assert result.package.issue_exports[0].retest_state == domain.FindingStatus.CONFIRMED.value
    state = report_publication.workflow_state_for_ui(result.package)
    assert state["variants"] == ("internal", "customer")
    review = state["review"]
    assert isinstance(review, dict)
    assert review["approval_status"] == "approved"
    assert result.audit_chain.audit_events[-1].action is evidence_chain.AuditAction.EXPORT


def test_publication_denies_claim_without_evidence_or_assumption() -> None:
    generated = reporting.generate_report_package(report_input(), evidence_chain.EvidenceChain()).package
    bad_section = replace(
        generated.sections[0],
        claims=(reporting.ReportClaim(text="Unsupported claim"),),
    )
    bad_package = replace(generated, sections=(bad_section,) + generated.sections[1:])

    with pytest.raises(ValueError, match="claim_requires_evidence_or_assumption"):
        report_publication.render_publication_variants(
            bad_package,
            allow_customer_variant=True,
            require_approved_redaction=True,
        )


def test_redaction_blocked_report_cannot_be_shared_externally() -> None:
    pending = report_input(redaction_review=redaction_review(reporting.RedactionReviewStatus.PENDING))

    with pytest.raises(ValueError, match="redaction_review_required"):
        report_publication.build_publication_workflow(
            request(report_input=pending),
            evidence_chain.EvidenceChain(),
        )


def test_issue_export_is_deduplicated_and_uses_sanitized_payload() -> None:
    base = request()
    finding_record = base.report_input.findings[0]
    payload = issue_connectors.build_issue_payload(connection(), finding_record)
    existing = issue_connectors.ExistingIssueExport(
        external_key=payload.external_key,
        issue_key="SEC-123",
        finding_id=finding_record.id,
        connector_id="connector-1",
    )

    result = report_publication.build_publication_workflow(
        request(existing_issue_exports=(existing,)),
        evidence_chain.EvidenceChain(),
    )

    assert result.package.issue_exports[0].action is issue_connectors.IssueExportAction.UPDATED_EXISTING
    assert result.package.issue_exports[0].issue_key == "SEC-123"
    assert result.package.issue_exports[0].deduplication_key == findings.duplicate_correlation_key(finding_record)


def test_canary_leak_blocks_publication_and_export() -> None:
    unsafe_input = report_input(limitations=("CANARY-REPORT-SECRET",))

    with pytest.raises(ValueError, match="canary_marker_leaked"):
        report_publication.build_publication_workflow(
            request(report_input=unsafe_input),
            evidence_chain.EvidenceChain(),
        )


def test_publication_regeneration_is_deterministic() -> None:
    publication_request = request()
    first = report_publication.build_publication_workflow(publication_request, evidence_chain.EvidenceChain())
    second = report_publication.build_publication_workflow(publication_request, evidence_chain.EvidenceChain())

    assert first.package.report_hash == second.package.report_hash
    assert first.package.evidence_lock_hash == second.package.evidence_lock_hash
    assert tuple(variant.content_hash for variant in first.package.variants) == tuple(
        variant.content_hash for variant in second.package.variants
    )
    assert tuple(export.payload_hash for export in first.package.issue_exports) == tuple(
        export.payload_hash for export in second.package.issue_exports
    )
