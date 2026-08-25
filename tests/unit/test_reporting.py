from dataclasses import replace
from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_chain, findings, reporting


NOW = datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc)


def evidence_record() -> evidence_chain.EvidenceRecord:
    chain = evidence_chain.EvidenceChain().append_evidence_record(
        evidence_id="evidence-1",
        organization_id="org-1",
        source_job_id="job-1",
        kind=domain.EvidenceKind.HTTP_METADATA,
        created_at=NOW,
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
        retention_class=evidence_chain.RetentionClass.STANDARD,
        access_policy=evidence_chain.EvidenceAccessPolicy.ENGAGEMENT_MEMBERS,
        content=b"redacted passive metadata",
        contains_sensitive_capture=True,
        metadata={"source": "unit-test"},
    )
    return chain.evidence_records[0]


def finding(record: evidence_chain.EvidenceRecord | None = None, **overrides: object) -> findings.FindingRecord:
    record = record or evidence_record()
    risk = findings.RiskFactors(
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
    )
    values = {
        "id": "finding-1",
        "title": "Missing strict transport security",
        "status": domain.FindingStatus.CONFIRMED,
        "affected_asset_id": "target-1",
        "affected_asset_value": "https://www.agentique.io",
        "confidence": findings.Confidence.CONFIRMED,
        "risk": risk,
        "reproduction_summary": "Confirmed from redacted passive metadata.",
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
        notes="Approved for external sharing." if status is reporting.RedactionReviewStatus.APPROVED else "Pending.",
    )


def report_input(**overrides: object) -> reporting.ReportInput:
    record = evidence_record()
    values = {
        "report_id": "report-1",
        "organization_id": "org-1",
        "title": "Agentique Passive Assessment",
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
        "methodology": ("Reviewed locked passive metadata evidence and confirmed findings.",),
        "limitations": ("No active exploitation or authenticated testing was performed.",),
        "redaction_review": redaction_review(),
        "canary_markers": ("CANARY-REPORT-SECRET",),
    }
    values.update(overrides)
    return reporting.ReportInput(**values)  # type: ignore[arg-type]


def test_report_contains_required_sections_and_evidence_backed_claims() -> None:
    result = reporting.generate_report_package(report_input(), evidence_chain.EvidenceChain())

    assert tuple(section.kind for section in result.package.sections) == reporting.REQUIRED_REPORT_SECTIONS
    rendered = reporting.render_report_markdown(result.package, external_share=True)
    assert "## Executive Summary" in rendered
    assert "## Technical Findings" in rendered
    assert "## ATT&CK Coverage" in rendered
    assert "## OWASP Coverage" in rendered
    assert "## Risk Trends" in rendered
    assert "## Scope" in rendered
    assert "## Methodology" in rendered
    assert "## Limitations" in rendered
    assert "## Appendix" in rendered
    assert "[evidence: evidence-1]" in rendered
    assert "[assumption:" in rendered
    assert result.audit_chain.audit_events[0].action is evidence_chain.AuditAction.REPORT_GENERATION


def test_report_claims_require_evidence_or_assumption() -> None:
    result = reporting.generate_report_package(report_input(), evidence_chain.EvidenceChain())
    bad_section = replace(
        result.package.sections[0],
        claims=(reporting.ReportClaim(text="Unsupported claim"),),
    )
    bad_package = replace(result.package, sections=(bad_section,) + result.package.sections[1:])

    with pytest.raises(ValueError, match="claim_requires_evidence_or_assumption"):
        reporting.validate_report_package(bad_package)


def test_report_regeneration_is_deterministic_from_locked_evidence() -> None:
    input_one = report_input()
    first = reporting.generate_report_package(input_one, evidence_chain.EvidenceChain())
    second = reporting.generate_report_package(input_one, evidence_chain.EvidenceChain())

    assert first.package.evidence_lock_hash == second.package.evidence_lock_hash
    assert first.package.report_hash == second.package.report_hash
    assert reporting.render_report_markdown(first.package, external_share=False) == reporting.render_report_markdown(
        second.package, external_share=False
    )


def test_redaction_review_is_required_before_external_sharing() -> None:
    result = reporting.generate_report_package(
        report_input(redaction_review=redaction_review(reporting.RedactionReviewStatus.PENDING)),
        evidence_chain.EvidenceChain(),
    )

    assert "Redaction review: pending" in reporting.render_report_markdown(result.package, external_share=False)
    with pytest.raises(ValueError, match="redaction_review_required"):
        reporting.render_report_markdown(result.package, external_share=True)


def test_reports_reject_unlocked_evidence_secret_text_and_canaries() -> None:
    record = evidence_record()
    missing_evidence_finding = finding(
        record,
        evidence_links=(
            findings.EvidenceLink(
                evidence_id="missing-evidence",
                integrity_hash="c" * 64,
                redaction_status=evidence_chain.RedactionStatus.REDACTED,
                contains_sensitive_payload=True,
            ),
        ),
    )
    with pytest.raises(ValueError, match="finding_evidence_not_locked"):
        reporting.generate_report_package(
            report_input(evidence_records=(record,), findings=(missing_evidence_finding,)),
            evidence_chain.EvidenceChain(),
        )

    with pytest.raises(ValueError, match="secret_like_text_forbidden"):
        reporting.generate_report_package(
            report_input(findings=(finding(record, remediation="Rotate token=abc123 immediately."),)),
            evidence_chain.EvidenceChain(),
        )

    with pytest.raises(ValueError, match="canary_marker_leaked"):
        reporting.generate_report_package(
            report_input(limitations=("CANARY-REPORT-SECRET",)),
            evidence_chain.EvidenceChain(),
        )
