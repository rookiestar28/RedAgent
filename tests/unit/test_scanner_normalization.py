from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    domain,
    evidence_chain,
    finding_review,
    findings,
    issue_connectors,
    scanner_normalization,
)
from redagent_platform.job_queue import JobRecord, PolicyGrant
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


NOW = datetime(2026, 7, 9, 11, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def evidence_link(
    evidence_id: str = "evidence-1",
    integrity_hash: str = "a" * 64,
    *,
    redaction_status: evidence_chain.RedactionStatus = evidence_chain.RedactionStatus.REDACTED,
    contains_sensitive_payload: bool = True,
) -> findings.EvidenceLink:
    return findings.EvidenceLink(
        evidence_id=evidence_id,
        integrity_hash=integrity_hash,
        redaction_status=redaction_status,
        contains_sensitive_payload=contains_sensitive_payload,
    )


def risk(**overrides: object) -> findings.RiskFactors:
    values = {
        "severity": findings.Severity.MEDIUM,
        "exploit_likelihood": findings.ExploitLikelihood.UNKNOWN,
        "asset_criticality": findings.AssetCriticality.MEDIUM,
        "business_impact": findings.BusinessImpact.LOW,
        "vulnerability_intelligence": findings.VulnerabilityIntelligence(cve_ids=(), cwe_ids=("CWE-693",)),
    }
    values.update(overrides)
    return findings.RiskFactors(**values)  # type: ignore[arg-type]


def finding(**overrides: object) -> findings.FindingRecord:
    values = {
        "id": "finding-1",
        "title": "Missing security header",
        "status": domain.FindingStatus.NEEDS_REVIEW,
        "affected_asset_id": TARGET.normalized().value,
        "affected_asset_value": "/",
        "confidence": findings.Confidence.MEDIUM,
        "risk": risk(),
        "reproduction_summary": "Scanner observation from sanitized evidence.",
        "evidence_links": (evidence_link(),),
        "remediation": "Review and configure the affected security control.",
        "owner_user_id": "owner-1",
        "source": "zap_active",
        "source_rule_id": "10021",
    }
    values.update(overrides)
    return findings.FindingRecord(**values)  # type: ignore[arg-type]


def normalized(
    record: findings.FindingRecord,
    *,
    source_family: scanner_normalization.ScannerSourceFamily = scanner_normalization.ScannerSourceFamily.ZAP,
    source_result_id: str = "source-result-1",
) -> scanner_normalization.NormalizedScannerFinding:
    return scanner_normalization.normalize_scanner_finding(
        finding=record,
        source_family=source_family,
        source_result_id=source_result_id,
    )


def test_duplicate_merge_preserves_evidence_lineage_and_source_rule() -> None:
    first = normalized(finding())
    second = normalized(
        finding(
            id="finding-2",
            evidence_links=(evidence_link("evidence-2", "a" * 64),),
        ),
        source_result_id="source-result-2",
    )
    report = scanner_normalization.deduplicate_scanner_findings((first, second))

    assert report.total_findings == 2
    assert report.duplicate_count == 1
    assert len(report.unique_groups) == 1
    group = report.unique_groups[0]
    assert group.primary.source_rule_id == "10021"
    assert group.primary.normalized_severity is findings.Severity.MEDIUM
    assert group.primary.normalized_confidence is findings.Confidence.MEDIUM
    assert len(group.merged_evidence_lineage) == 2
    assert {lineage.evidence_id for lineage in group.merged_evidence_lineage} == {"evidence-1", "evidence-2"}


def test_source_conflict_is_reported_without_unsafe_cross_source_merge() -> None:
    zap = normalized(finding())
    nuclei = normalized(
        finding(
            id="finding-2",
            source="nuclei",
            evidence_links=(evidence_link("nuclei-evidence", "b" * 64),),
            risk=risk(severity=findings.Severity.HIGH),
        ),
        source_family=scanner_normalization.ScannerSourceFamily.NUCLEI,
        source_result_id="nuclei-result-1",
    )
    report = scanner_normalization.deduplicate_scanner_findings((zap, nuclei))

    assert len(report.unique_groups) == 2
    assert report.duplicate_count == 0
    assert len(report.source_conflicts) == 1
    assert report.source_conflicts[0].sources == ("nuclei", "zap")
    assert set(report.source_conflicts[0].finding_ids) == {"finding-1", "finding-2"}


def test_severity_and_confidence_labels_are_normalized() -> None:
    assert scanner_normalization.normalize_severity_label("Informational") is findings.Severity.INFO
    assert scanner_normalization.normalize_severity_label("moderate") is findings.Severity.MEDIUM
    assert scanner_normalization.normalize_confidence_label("confirmed") is findings.Confidence.CONFIRMED
    assert scanner_normalization.normalize_confidence_label("unknown") is findings.Confidence.LOW

    with pytest.raises(ValueError, match="unknown_severity_label"):
        scanner_normalization.normalize_severity_label("urgent")


def test_retest_inheritance_stays_audit_backed_for_normalized_finding() -> None:
    reviewed = finding_review.apply_review_decision(
        finding=finding(status=domain.FindingStatus.NEEDS_REVIEW),
        decision=finding_review.FindingReviewDecision(
            decision_id="decision-1",
            finding_id="finding-1",
            reviewer_user_id="reviewer-1",
            decision=finding_review.ReviewDecisionKind.REQUEST_RETEST,
            rationale="Retest after remediation.",
            decided_at=NOW,
        ),
        audit_chain=evidence_chain.EvidenceChain(),
        organization_id="org-1",
    )
    envelope = normalized(reviewed.finding)
    plan = finding_review.build_retest_job_plan(
        retest_job_id="retest-job-1",
        finding=envelope.finding,
        original_job=original_job(),
        original_scope=scope(),
        original_policy=policy(),
    )

    assert reviewed.audit_chain.audit_events[0].action is evidence_chain.AuditAction.FINDING_CHANGE
    assert plan.status is domain.JobStatus.PLANNED
    assert plan.inherited_policy_decision_id == "policy-1"
    assert plan.target == TARGET


def test_issue_export_payload_redaction_for_normalized_confirmed_finding() -> None:
    confirmed = replace(finding(), status=domain.FindingStatus.CONFIRMED)
    envelope = normalized(confirmed)
    connector = issue_connectors.GenericIssueTrackerConnector()
    result = connector.export_finding(
        issue_connectors.IssueExportRequest(
            export_id="export-1",
            organization_id="org-1",
            actor_user_id="reviewer-1",
            connection=connection(),
            finding=envelope.finding,
            requested_at=NOW,
            audit_chain=evidence_chain.EvidenceChain(),
        )
    )

    assert result.payload.taxonomy.source_rule_id == "10021"
    assert result.payload.evidence_links[0].redaction_status == "redacted"
    assert result.audit_chain.audit_events[0].action is evidence_chain.AuditAction.EXPORT

    unsafe = replace(
        confirmed,
        evidence_links=(
            evidence_link(
                redaction_status=evidence_chain.RedactionStatus.RAW_ALLOWED,
                contains_sensitive_payload=True,
            ),
        ),
    )
    with pytest.raises(ValueError, match="unredacted_sensitive_evidence_forbidden"):
        connector.export_finding(
            issue_connectors.IssueExportRequest(
                export_id="export-2",
                organization_id="org-1",
                actor_user_id="reviewer-1",
                connection=connection(),
                finding=normalized(unsafe).finding,
                requested_at=NOW,
                audit_chain=evidence_chain.EvidenceChain(),
            )
        )


def scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-1",
        organization_id="org-1",
        authorization_status=domain.AuthorizationStatus.APPROVED,
        approved_by_user_id="lead-1",
        allowed_targets=(TARGET,),
        forbidden_targets=(),
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        window_start=NOW - timedelta(hours=1),
        window_end=NOW + timedelta(hours=1),
        max_interactions=20,
        max_rate_per_second=1.0,
        emergency_contact_method="email",
    )


def original_job() -> JobRecord:
    return JobRecord(
        job_id="job-1",
        organization_id="org-1",
        engagement_id="eng-1",
        test_definition_id="dast-workflow-policy",
        target=TARGET,
        mode=domain.TestMode.ACTIVE_SCAN,
        status=domain.JobStatus.EVIDENCE_LOCKED,
        projected_interactions=5,
        timeout_seconds=120,
        cleanup_required=True,
        max_attempts=1,
        policy_decision_id="policy-1",
        policy_expires_at=NOW + timedelta(hours=1),
    )


def policy() -> PolicyGrant:
    return PolicyGrant(
        decision_id="policy-1",
        organization_id="org-1",
        outcome=domain.PolicyDecisionOutcome.ALLOW,
        decided_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        reason="active_policy_authorized",
    )


def connection() -> issue_connectors.IssueTrackerConnection:
    return issue_connectors.IssueTrackerConnection(
        connector_id="connector-1",
        kind=issue_connectors.ConnectorKind.GENERIC_ISSUE_TRACKER,
        display_name="Internal issue tracker",
        project_key="SEC",
        credential_reference_id="credential-ref-1",
        redaction_label="issue-tracker-token",
    )
