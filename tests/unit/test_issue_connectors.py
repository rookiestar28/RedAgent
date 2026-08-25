from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_chain, findings, issue_connectors


NOW = datetime(2026, 7, 8, 11, 0, tzinfo=timezone.utc)


def evidence_link(
    *,
    redaction_status: evidence_chain.RedactionStatus = evidence_chain.RedactionStatus.REDACTED,
    contains_sensitive_payload: bool = True,
) -> findings.EvidenceLink:
    return findings.EvidenceLink(
        evidence_id="evidence-1",
        integrity_hash="b" * 64,
        redaction_status=redaction_status,
        contains_sensitive_payload=contains_sensitive_payload,
    )


def finding(**overrides: object) -> findings.FindingRecord:
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
        "reproduction_summary": "Confirmed from redacted passive metadata and reviewer decision.",
        "evidence_links": (evidence_link(),),
        "remediation": "Set the expected HTTP security header at the edge.",
        "owner_user_id": "owner-1",
        "source": "zap_passive",
        "source_rule_id": "10035",
    }
    values.update(overrides)
    return findings.FindingRecord(**values)  # type: ignore[arg-type]


def connection(**overrides: object) -> issue_connectors.IssueTrackerConnection:
    values = {
        "connector_id": "connector-1",
        "kind": issue_connectors.ConnectorKind.GENERIC_ISSUE_TRACKER,
        "display_name": "Internal issue tracker",
        "project_key": "SEC",
        "credential_reference_id": "credential-ref-1",
        "redaction_label": "issue-tracker-token",
    }
    values.update(overrides)
    return issue_connectors.IssueTrackerConnection(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> issue_connectors.IssueExportRequest:
    values = {
        "export_id": "export-1",
        "organization_id": "org-1",
        "actor_user_id": "reviewer-1",
        "connection": connection(),
        "finding": finding(),
        "requested_at": NOW,
        "audit_chain": evidence_chain.EvidenceChain(),
        "existing_exports": (),
        "canary_markers": ("CANARY-SECRET-DO-NOT-EXPORT",),
    }
    values.update(overrides)
    return issue_connectors.IssueExportRequest(**values)  # type: ignore[arg-type]


def test_generic_issue_connector_exports_confirmed_finding() -> None:
    connector: issue_connectors.IssueConnector = issue_connectors.GenericIssueTrackerConnector()
    result = issue_connectors.export_finding_to_issue(connector, request())

    assert result.action is issue_connectors.IssueExportAction.CREATED_NEW
    assert result.issue_key.startswith("SEC-")
    assert result.payload.summary == "Missing strict transport security"
    assert result.payload.severity == "high"
    assert result.payload.owner_user_id == "owner-1"
    assert result.payload.remediation == "Set the expected HTTP security header at the edge."
    assert result.payload.evidence_links[0].evidence_id == "evidence-1"
    assert result.payload.evidence_links[0].redaction_status == "redacted"
    assert result.payload.taxonomy.source == "zap_passive"
    assert result.payload.taxonomy.source_rule_id == "10035"
    assert result.payload.taxonomy.cve_ids == ("CVE-2026-12345",)
    assert result.payload.taxonomy.cwe_ids == ("CWE-693",)
    assert "severity:high" in result.payload.labels
    assert result.audit_chain.audit_events[0].action is evidence_chain.AuditAction.EXPORT


def test_connector_rejects_non_confirmed_findings() -> None:
    with pytest.raises(ValueError, match="finding_must_be_confirmed"):
        issue_connectors.GenericIssueTrackerConnector().export_finding(
            request(finding=finding(status=domain.FindingStatus.NEEDS_REVIEW))
        )


def test_duplicate_export_is_idempotent() -> None:
    connector = issue_connectors.GenericIssueTrackerConnector()
    first = connector.export_finding(request())
    duplicate = connector.export_finding(
        request(
            export_id="export-2",
            existing_exports=(
                issue_connectors.ExistingIssueExport(
                    external_key=first.payload.external_key,
                    issue_key=first.issue_key,
                    finding_id="finding-1",
                    connector_id="connector-1",
                ),
            ),
        )
    )

    assert duplicate.action is issue_connectors.IssueExportAction.UPDATED_EXISTING
    assert duplicate.issue_key == first.issue_key
    assert duplicate.payload.external_key == first.payload.external_key


def test_secrets_and_canaries_are_not_exported() -> None:
    with pytest.raises(ValueError, match="secret_like_text_forbidden"):
        issue_connectors.GenericIssueTrackerConnector().export_finding(
            request(finding=finding(remediation="Rotate token=abc123 immediately."))
        )

    with pytest.raises(ValueError, match="canary_marker_leaked"):
        issue_connectors.GenericIssueTrackerConnector().export_finding(
            request(finding=finding(remediation="CANARY-SECRET-DO-NOT-EXPORT"))
        )


def test_raw_sensitive_evidence_is_not_exported() -> None:
    unsafe = finding(
        evidence_links=(
            evidence_link(
                redaction_status=evidence_chain.RedactionStatus.RAW_ALLOWED,
                contains_sensitive_payload=True,
            ),
        )
    )

    with pytest.raises(ValueError, match="unredacted_sensitive_evidence_forbidden"):
        issue_connectors.GenericIssueTrackerConnector().export_finding(request(finding=unsafe))
