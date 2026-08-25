from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import domain, evidence_chain, finding_review, findings
from redagent_platform.job_queue import JobRecord, PolicyGrant
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


NOW = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def evidence_link() -> findings.EvidenceLink:
    return findings.EvidenceLink(
        evidence_id="evidence-1",
        integrity_hash="a" * 64,
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
        contains_sensitive_payload=True,
    )


def finding(**overrides: object) -> findings.FindingRecord:
    risk = findings.RiskFactors(
        severity=findings.Severity.MEDIUM,
        exploit_likelihood=findings.ExploitLikelihood.UNKNOWN,
        asset_criticality=findings.AssetCriticality.MEDIUM,
        business_impact=findings.BusinessImpact.LOW,
        vulnerability_intelligence=findings.VulnerabilityIntelligence(cve_ids=(), cwe_ids=("CWE-693",)),
    )
    values = {
        "id": "finding-1",
        "title": "Missing security header",
        "status": domain.FindingStatus.NEEDS_REVIEW,
        "affected_asset_id": "target-1",
        "affected_asset_value": "https://www.agentique.io",
        "confidence": findings.Confidence.MEDIUM,
        "risk": risk,
        "reproduction_summary": "Observed in redacted passive metadata.",
        "evidence_links": (evidence_link(),),
        "remediation": "Review and configure the missing header.",
        "owner_user_id": "owner-1",
        "source": "zap_passive",
        "source_rule_id": "10021",
    }
    values.update(overrides)
    return findings.FindingRecord(**values)  # type: ignore[arg-type]


def decision(**overrides: object) -> finding_review.FindingReviewDecision:
    values = {
        "decision_id": "decision-1",
        "finding_id": "finding-1",
        "reviewer_user_id": "reviewer-1",
        "decision": finding_review.ReviewDecisionKind.CONFIRM,
        "rationale": "Evidence and policy context validate the issue.",
        "decided_at": NOW,
    }
    values.update(overrides)
    return finding_review.FindingReviewDecision(**values)  # type: ignore[arg-type]


def scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-1",
        organization_id="org-1",
        authorization_status=domain.AuthorizationStatus.APPROVED,
        approved_by_user_id="lead-1",
        allowed_targets=(TARGET,),
        forbidden_targets=(),
        allowed_modes=(domain.TestMode.PASSIVE_SCAN,),
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
        test_definition_id="test-1",
        target=TARGET,
        mode=domain.TestMode.PASSIVE_SCAN,
        status=domain.JobStatus.COMPLETED,
        projected_interactions=5,
        timeout_seconds=60,
        cleanup_required=False,
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
        reason="scope_authorized",
    )


def test_r021_required_finding_states_are_supported() -> None:
    assert finding_review.r021_statuses_supported()


def test_review_decision_requires_rationale_and_writes_audit() -> None:
    result = finding_review.apply_review_decision(
        finding=finding(),
        decision=decision(),
        audit_chain=evidence_chain.EvidenceChain(),
        organization_id="org-1",
    )

    assert result.finding.status is domain.FindingStatus.CONFIRMED
    assert result.audit_chain.audit_events[0].action is evidence_chain.AuditAction.FINDING_CHANGE
    assert result.audit_chain.audit_events[0].subject_id == "finding-1"

    with pytest.raises(ValueError, match="missing_rationale"):
        finding_review.apply_review_decision(
            finding=finding(),
            decision=decision(rationale=""),
            audit_chain=evidence_chain.EvidenceChain(),
            organization_id="org-1",
        )


def test_review_workflow_supports_false_positive_risk_fixed_and_retest_states() -> None:
    transitions = {
        finding_review.ReviewDecisionKind.MARK_FALSE_POSITIVE: domain.FindingStatus.FALSE_POSITIVE,
        finding_review.ReviewDecisionKind.ACCEPT_RISK: domain.FindingStatus.RISK_ACCEPTED,
        finding_review.ReviewDecisionKind.MARK_FIXED: domain.FindingStatus.FIXED,
        finding_review.ReviewDecisionKind.REQUEST_RETEST: domain.FindingStatus.RETEST_REQUESTED,
        finding_review.ReviewDecisionKind.MARK_RETEST_PASSED: domain.FindingStatus.RETEST_PASSED,
        finding_review.ReviewDecisionKind.MARK_RETEST_FAILED: domain.FindingStatus.RETEST_FAILED,
    }

    for decision_kind, expected_status in transitions.items():
        result = finding_review.apply_review_decision(
            finding=finding(),
            decision=decision(decision=decision_kind),
            audit_chain=evidence_chain.EvidenceChain(),
            organization_id="org-1",
        )
        assert result.finding.status is expected_status


def test_retest_job_plan_inherits_original_scope_and_policy_gates() -> None:
    retest_finding = finding(status=domain.FindingStatus.RETEST_REQUESTED)
    plan = finding_review.build_retest_job_plan(
        retest_job_id="retest-job-1",
        finding=retest_finding,
        original_job=original_job(),
        original_scope=scope(),
        original_policy=policy(),
    )

    assert plan.status is domain.JobStatus.PLANNED
    assert plan.target == TARGET
    assert plan.mode is domain.TestMode.PASSIVE_SCAN
    assert plan.inherited_scope_engagement_id == "eng-1"
    assert plan.inherited_policy_decision_id == "policy-1"
    assert plan.inherited_policy_expires_at == NOW + timedelta(hours=1)
    assert plan.projected_interactions == 5
    assert plan.timeout_seconds == 60


def test_retest_plan_rejects_scope_or_policy_drift() -> None:
    retest_finding = finding(status=domain.FindingStatus.RETEST_REQUESTED)
    drifted_job = replace(
        original_job(),
        target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://admin.agentique.io"),
    )

    with pytest.raises(ValueError, match="original_job_target_not_in_scope"):
        finding_review.build_retest_job_plan(
            retest_job_id="retest-job-2",
            finding=retest_finding,
            original_job=drifted_job,
            original_scope=scope(),
            original_policy=policy(),
        )


def test_metrics_distinguish_raw_alerts_from_confirmed_findings() -> None:
    metrics = finding_review.summarize_finding_metrics(
        (
            finding(status=domain.FindingStatus.NEW),
            finding(id="finding-2", status=domain.FindingStatus.NEEDS_REVIEW),
            finding(id="finding-3", status=domain.FindingStatus.CONFIRMED),
            finding(id="finding-4", status=domain.FindingStatus.FALSE_POSITIVE),
            finding(id="finding-5", status=domain.FindingStatus.RETEST_PASSED),
        )
    )

    assert metrics.total == 5
    assert metrics.raw_alerts == 2
    assert metrics.confirmed_findings == 1
    assert metrics.false_positives == 1
    assert metrics.retest_passed == 1
    assert metrics.reviewed_findings == 3
