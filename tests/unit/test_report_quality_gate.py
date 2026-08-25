from dataclasses import replace
from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_chain, findings, report_quality_gate, reporting


NOW = datetime(2026, 7, 9, 13, 30, tzinfo=timezone.utc)


def evidence_record(
    *,
    redaction_status: evidence_chain.RedactionStatus = evidence_chain.RedactionStatus.REDACTED,
) -> evidence_chain.EvidenceRecord:
    content = None if redaction_status is evidence_chain.RedactionStatus.BLOCKED else b"redacted report evidence"
    chain = evidence_chain.EvidenceChain().append_evidence_record(
        evidence_id="evidence-1",
        organization_id="org-1",
        source_job_id="job-1",
        kind=domain.EvidenceKind.REPORT_SOURCE,
        created_at=NOW,
        redaction_status=redaction_status,
        retention_class=evidence_chain.RetentionClass.STANDARD,
        access_policy=evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=content,
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


def report_input(
    *,
    record: evidence_chain.EvidenceRecord | None = None,
    finding_record: findings.FindingRecord | None = None,
    **overrides: object,
) -> reporting.ReportInput:
    record = record or evidence_record()
    finding_record = finding_record or finding(record)
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
        "findings": (finding_record,),
        "evidence_records": (record,),
        "methodology": ("Reviewed locked evidence and confirmed findings.",),
        "limitations": ("No active exploitation was performed.",),
        "redaction_review": redaction_review(),
        "canary_markers": ("CANARY-REPORT-SECRET",),
    }
    values.update(overrides)
    return reporting.ReportInput(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> report_quality_gate.ReportQualityProfile:
    values = {
        "profile_id": "quality-profile-1",
        "allow_customer_variant": True,
        "require_approved_redaction": True,
        "require_claim_evidence_or_justification": True,
        "require_risk_source_support": True,
        "require_retest_closeout": True,
    }
    values.update(overrides)
    return report_quality_gate.ReportQualityProfile(**values)  # type: ignore[arg-type]


def review_state(**overrides: object) -> report_quality_gate.ReportQualityReviewState:
    values = {
        "evidence_reviewed": True,
        "redaction_reviewed": True,
        "claim_reviewed": True,
        "risk_reviewed": True,
        "closeout_ready": True,
        "approved_by_user_id": "lead-1",
        "approved_at": NOW,
    }
    values.update(overrides)
    return report_quality_gate.ReportQualityReviewState(**values)  # type: ignore[arg-type]


def generated_package(
    *,
    record: evidence_chain.EvidenceRecord | None = None,
    finding_record: findings.FindingRecord | None = None,
    redaction_status: reporting.RedactionReviewStatus = reporting.RedactionReviewStatus.APPROVED,
) -> tuple[reporting.ReportPackage, findings.FindingRecord]:
    record = record or evidence_record()
    finding_record = finding_record or finding(record)
    package = reporting.generate_report_package(
        report_input(
            record=record,
            finding_record=finding_record,
            redaction_review=redaction_review(redaction_status),
        ),
        evidence_chain.EvidenceChain(),
    ).package
    return package, finding_record


def justifications_for_package(
    package: reporting.ReportPackage,
) -> tuple[report_quality_gate.ClaimReviewJustification, ...]:
    return tuple(
        report_quality_gate.ClaimReviewJustification(
            claim_hash=report_quality_gate.claim_review_hash(claim),
            reviewer_user_id="reviewer-1",
            rationale="Reviewed non-evidence report context for publication.",
            reviewed_at=NOW,
        )
        for section in package.sections
        for claim in section.claims
        if not claim.evidence_ids
    )


def request(
    *,
    package: reporting.ReportPackage | None = None,
    finding_record: findings.FindingRecord | None = None,
    justifications: tuple[report_quality_gate.ClaimReviewJustification, ...] | None = None,
    **overrides: object,
) -> report_quality_gate.ReportQualityGateRequest:
    if package is None or finding_record is None:
        package, finding_record = generated_package()
    values = {
        "gate_id": "quality-gate-1",
        "package": package,
        "findings": (finding_record,),
        "profile": profile(),
        "review_state": review_state(),
        "requested_at": NOW,
        "actor_user_id": "publisher-1",
        "justifications": justifications if justifications is not None else justifications_for_package(package),
    }
    values.update(overrides)
    return report_quality_gate.ReportQualityGateRequest(**values)  # type: ignore[arg-type]


def test_quality_gate_renders_internal_and_customer_variants_with_evidence_traceability() -> None:
    package, finding_record = generated_package()

    result = report_quality_gate.evaluate_report_quality_gate(
        request(package=package, finding_record=finding_record),
        evidence_chain.EvidenceChain(),
    )

    assert result.decision is report_quality_gate.ReportQualityDecision.APPROVED
    assert tuple(variant.kind.value for variant in result.variants) == ("internal", "customer")
    assert result.variants[0].evidence_trace_ids == ("evidence-1",)
    assert result.variants[1].evidence_trace_ids == ("evidence-1",)
    assert "reviewer_user_id" in result.variants[1].minimized_fields
    assert result.finding_summaries[0].cvss_score == 7.2
    assert result.closeout_ready
    assert result.audit_chain.audit_events[-1].subject_type == "report_quality_gate"


def test_unsupported_claim_without_evidence_or_review_is_denied() -> None:
    package, finding_record = generated_package()
    unsupported = reporting.ReportClaim(
        text="Exploitability is proven and remediation priority is urgent.",
        assumption="Author statement without reviewer support.",
    )
    bad_section = replace(package.sections[0], claims=(unsupported,))
    bad_package = replace(package, sections=(bad_section,) + package.sections[1:])

    with pytest.raises(ValueError, match="claim_requires_evidence_or_justification"):
        report_quality_gate.evaluate_report_quality_gate(
            request(package=bad_package, finding_record=finding_record, justifications=()),
            evidence_chain.EvidenceChain(),
        )


def test_cvss_epss_and_kev_consistency_blocks_conflicting_priority_claims() -> None:
    record = evidence_record()
    inconsistent_risk = findings.RiskFactors(
        severity=findings.Severity.LOW,
        exploit_likelihood=findings.ExploitLikelihood.UNKNOWN,
        asset_criticality=findings.AssetCriticality.HIGH,
        business_impact=findings.BusinessImpact.MODERATE,
        vulnerability_intelligence=findings.VulnerabilityIntelligence(
            cve_ids=("CVE-2026-12345",),
            cwe_ids=("CWE-693",),
            cvss_score=9.4,
            epss_probability=0.81,
            kev_listed=True,
        ),
    )
    finding_record = finding(record, risk=inconsistent_risk)
    package, finding_record = generated_package(record=record, finding_record=finding_record)

    with pytest.raises(ValueError, match="cvss_severity_inconsistent"):
        report_quality_gate.evaluate_report_quality_gate(
            request(package=package, finding_record=finding_record),
            evidence_chain.EvidenceChain(),
        )


def test_redaction_blocked_publication_is_denied() -> None:
    package, finding_record = generated_package(redaction_status=reporting.RedactionReviewStatus.BLOCKED)

    with pytest.raises(ValueError, match="redaction_review_required"):
        report_quality_gate.evaluate_report_quality_gate(
            request(package=package, finding_record=finding_record),
            evidence_chain.EvidenceChain(),
        )

    blocked_record = evidence_record(redaction_status=evidence_chain.RedactionStatus.BLOCKED)
    blocked_finding = finding(blocked_record)
    package, blocked_finding = generated_package(record=blocked_record, finding_record=blocked_finding)

    with pytest.raises(ValueError, match="redaction_blocked_evidence"):
        report_quality_gate.evaluate_report_quality_gate(
            request(package=package, finding_record=blocked_finding),
            evidence_chain.EvidenceChain(),
        )


def test_retest_closeout_requires_closed_retest_lifecycle() -> None:
    retest_finding = finding(status=domain.FindingStatus.RETEST_REQUESTED)
    package, retest_finding = generated_package(finding_record=retest_finding)

    with pytest.raises(ValueError, match="retest_closeout_not_ready"):
        report_quality_gate.evaluate_report_quality_gate(
            request(package=package, finding_record=retest_finding),
            evidence_chain.EvidenceChain(),
        )

    passed_finding = finding(status=domain.FindingStatus.RETEST_PASSED)
    package, passed_finding = generated_package(finding_record=passed_finding)
    result = report_quality_gate.evaluate_report_quality_gate(
        request(package=package, finding_record=passed_finding),
        evidence_chain.EvidenceChain(),
    )

    assert result.closeout_ready
    assert result.finding_summaries[0].status == domain.FindingStatus.RETEST_PASSED.value


def test_quality_gate_regeneration_is_deterministic() -> None:
    package, finding_record = generated_package()
    gate_request = request(package=package, finding_record=finding_record)

    first = report_quality_gate.evaluate_report_quality_gate(gate_request, evidence_chain.EvidenceChain())
    second = report_quality_gate.evaluate_report_quality_gate(gate_request, evidence_chain.EvidenceChain())

    assert first.result_hash == second.result_hash
    assert tuple(variant.content_hash for variant in first.variants) == tuple(
        variant.content_hash for variant in second.variants
    )
