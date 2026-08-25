import pytest

from redagent_platform import domain, evidence_chain, findings


def evidence_link(**overrides: object) -> findings.EvidenceLink:
    values = {
        "evidence_id": "evidence-1",
        "integrity_hash": "a" * 64,
        "redaction_status": evidence_chain.RedactionStatus.REDACTED,
        "contains_sensitive_payload": True,
    }
    values.update(overrides)
    return findings.EvidenceLink(**values)  # type: ignore[arg-type]


def intel(**overrides: object) -> findings.VulnerabilityIntelligence:
    values = {
        "cve_ids": ("CVE-2026-12345",),
        "cwe_ids": ("CWE-79",),
        "cvss_score": 8.7,
        "epss_probability": 0.42,
        "kev_listed": True,
    }
    values.update(overrides)
    return findings.VulnerabilityIntelligence(**values)  # type: ignore[arg-type]


def risk(**overrides: object) -> findings.RiskFactors:
    values = {
        "severity": findings.Severity.HIGH,
        "exploit_likelihood": findings.ExploitLikelihood.MEDIUM,
        "asset_criticality": findings.AssetCriticality.HIGH,
        "business_impact": findings.BusinessImpact.MODERATE,
        "vulnerability_intelligence": intel(),
    }
    values.update(overrides)
    return findings.RiskFactors(**values)  # type: ignore[arg-type]


def finding(**overrides: object) -> findings.FindingRecord:
    values = {
        "id": "finding-1",
        "title": "Missing content security policy",
        "status": domain.FindingStatus.NEEDS_REVIEW,
        "affected_asset_id": "target-1",
        "affected_asset_value": "https://example.com",
        "confidence": findings.Confidence.HIGH,
        "risk": risk(),
        "reproduction_summary": "Observed from sanitized HTTP metadata.",
        "evidence_links": (evidence_link(),),
        "remediation": "Define a restrictive CSP and test report-only rollout.",
        "owner_user_id": "owner-1",
        "source": "zap",
        "source_rule_id": "10038",
    }
    values.update(overrides)
    return findings.FindingRecord(**values)  # type: ignore[arg-type]


def test_finding_schema_supports_r011_required_fields() -> None:
    record = finding()
    findings.validate_finding(record)

    assert record.severity is findings.Severity.HIGH
    assert record.confidence is findings.Confidence.HIGH
    assert record.risk.exploit_likelihood is findings.ExploitLikelihood.MEDIUM
    assert record.risk.business_impact is findings.BusinessImpact.MODERATE
    assert record.risk.vulnerability_intelligence.cve_ids == ("CVE-2026-12345",)
    assert record.risk.vulnerability_intelligence.cwe_ids == ("CWE-79",)
    assert record.risk.vulnerability_intelligence.cvss_score == 8.7
    assert record.risk.vulnerability_intelligence.epss_probability == 0.42
    assert record.risk.vulnerability_intelligence.kev_listed
    assert record.affected_asset_id == "target-1"
    assert record.evidence_links == (evidence_link(),)
    assert record.owner_user_id == "owner-1"
    assert record.status is domain.FindingStatus.NEEDS_REVIEW


def test_risk_score_keeps_separate_risk_factors() -> None:
    risk_factors = risk(
        severity=findings.Severity.CRITICAL,
        exploit_likelihood=findings.ExploitLikelihood.LOW,
        asset_criticality=findings.AssetCriticality.CRITICAL,
        business_impact=findings.BusinessImpact.SEVERE,
    )

    assert risk_factors.severity is findings.Severity.CRITICAL
    assert risk_factors.exploit_likelihood is findings.ExploitLikelihood.LOW
    assert risk_factors.asset_criticality is findings.AssetCriticality.CRITICAL
    assert risk_factors.business_impact is findings.BusinessImpact.SEVERE
    assert findings.priority_score(risk_factors) > findings.priority_score(risk(severity=findings.Severity.LOW))


def test_invalid_cvss_and_epss_are_rejected() -> None:
    with pytest.raises(ValueError, match="invalid_cvss_score"):
        findings.validate_finding(finding(risk=risk(vulnerability_intelligence=intel(cvss_score=10.1))))
    with pytest.raises(ValueError, match="invalid_epss_probability"):
        findings.validate_finding(finding(risk=risk(vulnerability_intelligence=intel(epss_probability=1.1))))


def test_duplicate_correlation_key_is_deterministic() -> None:
    first = finding(
        title="  Missing   Content Security Policy ",
        risk=risk(vulnerability_intelligence=intel(cve_ids=("CVE-2026-22222", "CVE-2026-11111"))),
    )
    second = finding(
        title="missing content security policy",
        risk=risk(vulnerability_intelligence=intel(cve_ids=("CVE-2026-11111", "CVE-2026-22222"))),
    )

    assert findings.duplicate_correlation_key(first) == findings.duplicate_correlation_key(second)


def test_sanitized_export_contains_evidence_ids_not_raw_payloads() -> None:
    exported = findings.export_sanitized_finding(finding())

    assert exported["evidence"] == (
        {
            "evidence_id": "evidence-1",
            "integrity_hash": "a" * 64,
            "redaction_status": "redacted",
        },
    )
    assert "raw" not in exported
    assert exported["risk"]["severity"] == "high"  # type: ignore[index]
    assert exported["vulnerability_intelligence"]["kev_listed"] is True  # type: ignore[index]


def test_export_rejects_secret_like_text() -> None:
    with pytest.raises(ValueError, match="secret_like_text_forbidden"):
        findings.export_sanitized_finding(finding(reproduction_summary="Authorization: Bearer example"))


def test_export_rejects_unredacted_sensitive_evidence() -> None:
    with pytest.raises(ValueError, match="unredacted_sensitive_evidence_forbidden"):
        findings.export_sanitized_finding(
            finding(
                evidence_links=(
                    evidence_link(
                        redaction_status=evidence_chain.RedactionStatus.RAW_ALLOWED,
                        contains_sensitive_payload=True,
                    ),
                )
            )
        )


def test_non_sensitive_raw_allowed_evidence_can_export() -> None:
    exported = findings.export_sanitized_finding(
        finding(
            evidence_links=(
                evidence_link(
                    redaction_status=evidence_chain.RedactionStatus.RAW_ALLOWED,
                    contains_sensitive_payload=False,
                ),
            )
        )
    )

    assert exported["evidence"][0]["redaction_status"] == "raw_allowed"  # type: ignore[index]
