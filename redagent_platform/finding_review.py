"""Finding review, retest planning, and review metrics contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.domain import FindingStatus, JobStatus, TestMode
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.findings import FindingRecord, validate_finding
from redagent_platform.job_queue import JobRecord, PolicyGrant
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


class ReviewDecisionKind(str, Enum):
    MARK_NEEDS_REVIEW = "mark_needs_review"
    CONFIRM = "confirm"
    MARK_FALSE_POSITIVE = "mark_false_positive"
    ACCEPT_RISK = "accept_risk"
    MARK_FIXED = "mark_fixed"
    REQUEST_RETEST = "request_retest"
    MARK_RETEST_PASSED = "mark_retest_passed"
    MARK_RETEST_FAILED = "mark_retest_failed"


@dataclass(frozen=True, kw_only=True)
class FindingReviewDecision:
    decision_id: str
    finding_id: str
    reviewer_user_id: str
    decision: ReviewDecisionKind
    rationale: str
    decided_at: datetime


@dataclass(frozen=True, kw_only=True)
class FindingReviewResult:
    finding: FindingRecord
    audit_chain: EvidenceChain


@dataclass(frozen=True, kw_only=True)
class RetestJobPlan:
    retest_job_id: str
    finding_id: str
    original_job_id: str
    organization_id: str
    engagement_id: str
    test_definition_id: str
    target: ScopeTarget
    mode: TestMode
    status: JobStatus
    inherited_scope_engagement_id: str
    inherited_allowed_target_count: int
    inherited_policy_decision_id: str
    inherited_policy_expires_at: datetime
    projected_interactions: int
    timeout_seconds: int


@dataclass(frozen=True, kw_only=True)
class FindingWorkflowMetrics:
    total: int
    raw_alerts: int
    reviewed_findings: int
    confirmed_findings: int
    false_positives: int
    risk_accepted: int
    fixed: int
    retest_requested: int
    retest_passed: int
    retest_failed: int


REQUIRED_R021_STATUSES = frozenset(
    {
        FindingStatus.NEW,
        FindingStatus.NEEDS_REVIEW,
        FindingStatus.CONFIRMED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.FIXED,
        FindingStatus.RETEST_REQUESTED,
        FindingStatus.RETEST_PASSED,
        FindingStatus.RETEST_FAILED,
    }
)

_STATUS_BY_DECISION = {
    ReviewDecisionKind.MARK_NEEDS_REVIEW: FindingStatus.NEEDS_REVIEW,
    ReviewDecisionKind.CONFIRM: FindingStatus.CONFIRMED,
    ReviewDecisionKind.MARK_FALSE_POSITIVE: FindingStatus.FALSE_POSITIVE,
    ReviewDecisionKind.ACCEPT_RISK: FindingStatus.RISK_ACCEPTED,
    ReviewDecisionKind.MARK_FIXED: FindingStatus.FIXED,
    ReviewDecisionKind.REQUEST_RETEST: FindingStatus.RETEST_REQUESTED,
    ReviewDecisionKind.MARK_RETEST_PASSED: FindingStatus.RETEST_PASSED,
    ReviewDecisionKind.MARK_RETEST_FAILED: FindingStatus.RETEST_FAILED,
}


def statuses_supported() -> bool:
    return REQUIRED_R021_STATUSES.issubset(set(FindingStatus))


def apply_review_decision(
    *,
    finding: FindingRecord,
    decision: FindingReviewDecision,
    audit_chain: EvidenceChain,
    organization_id: str,
) -> FindingReviewResult:
    validate_finding(finding)
    _validate_decision(decision, finding)
    next_status = _STATUS_BY_DECISION[decision.decision]
    reviewed = _replace_finding_status(finding, next_status)
    next_chain = audit_chain.append_audit_event(
        event_id=decision.decision_id,
        organization_id=organization_id,
        actor_user_id=decision.reviewer_user_id,
        action=AuditAction.FINDING_CHANGE,
        subject_type="finding",
        subject_id=finding.id,
        occurred_at=decision.decided_at,
        details={
            "decision": decision.decision.value,
            "from_status": finding.status.value,
            "to_status": next_status.value,
            "rationale": decision.rationale,
        },
    )
    return FindingReviewResult(finding=reviewed, audit_chain=next_chain)


def build_retest_job_plan(
    *,
    retest_job_id: str,
    finding: FindingRecord,
    original_job: JobRecord,
    original_scope: EngagementScope,
    original_policy: PolicyGrant,
) -> RetestJobPlan:
    _require_non_empty("retest_job_id", retest_job_id)
    if finding.status is not FindingStatus.RETEST_REQUESTED:
        raise ValueError("finding_must_be_retest_requested")
    if original_job.target.normalized() not in tuple(target.normalized() for target in original_scope.allowed_targets):
        raise ValueError("original_job_target_not_in_scope")
    if original_job.mode not in original_scope.allowed_modes:
        raise ValueError("original_job_mode_not_in_scope")
    if original_policy.decision_id != original_job.policy_decision_id:
        raise ValueError("policy_decision_mismatch")
    if original_job.policy_expires_at != original_policy.expires_at:
        raise ValueError("policy_expiry_mismatch")
    return RetestJobPlan(
        retest_job_id=retest_job_id.strip(),
        finding_id=finding.id,
        original_job_id=original_job.job_id,
        organization_id=original_job.organization_id,
        engagement_id=original_job.engagement_id,
        test_definition_id=original_job.test_definition_id,
        target=original_job.target,
        mode=original_job.mode,
        status=JobStatus.PLANNED,
        inherited_scope_engagement_id=original_scope.engagement_id,
        inherited_allowed_target_count=len(original_scope.allowed_targets),
        inherited_policy_decision_id=original_policy.decision_id,
        inherited_policy_expires_at=original_policy.expires_at,
        projected_interactions=original_job.projected_interactions,
        timeout_seconds=original_job.timeout_seconds,
    )


def summarize_finding_metrics(findings: tuple[FindingRecord, ...]) -> FindingWorkflowMetrics:
    statuses = [finding.status for finding in findings]
    raw_alerts = sum(1 for status in statuses if status in {FindingStatus.NEW, FindingStatus.RAW_ALERT, FindingStatus.NEEDS_REVIEW})
    confirmed = statuses.count(FindingStatus.CONFIRMED)
    false_positive = statuses.count(FindingStatus.FALSE_POSITIVE)
    risk_accepted = statuses.count(FindingStatus.RISK_ACCEPTED)
    fixed = statuses.count(FindingStatus.FIXED) + statuses.count(FindingStatus.REMEDIATED)
    retest_requested = statuses.count(FindingStatus.RETEST_REQUESTED) + statuses.count(FindingStatus.RETEST_REQUIRED)
    retest_passed = statuses.count(FindingStatus.RETEST_PASSED)
    retest_failed = statuses.count(FindingStatus.RETEST_FAILED)
    reviewed = confirmed + false_positive + risk_accepted + fixed + retest_requested + retest_passed + retest_failed
    return FindingWorkflowMetrics(
        total=len(findings),
        raw_alerts=raw_alerts,
        reviewed_findings=reviewed,
        confirmed_findings=confirmed,
        false_positives=false_positive,
        risk_accepted=risk_accepted,
        fixed=fixed,
        retest_requested=retest_requested,
        retest_passed=retest_passed,
        retest_failed=retest_failed,
    )


def _replace_finding_status(finding: FindingRecord, status: FindingStatus) -> FindingRecord:
    return FindingRecord(
        id=finding.id,
        title=finding.title,
        status=status,
        affected_asset_id=finding.affected_asset_id,
        affected_asset_value=finding.affected_asset_value,
        confidence=finding.confidence,
        risk=finding.risk,
        reproduction_summary=finding.reproduction_summary,
        evidence_links=finding.evidence_links,
        remediation=finding.remediation,
        owner_user_id=finding.owner_user_id,
        source=finding.source,
        source_rule_id=finding.source_rule_id,
    )


def _validate_decision(decision: FindingReviewDecision, finding: FindingRecord) -> None:
    for field_name, value in (
        ("decision_id", decision.decision_id),
        ("finding_id", decision.finding_id),
        ("reviewer_user_id", decision.reviewer_user_id),
        ("rationale", decision.rationale),
    ):
        _require_non_empty(field_name, value)
    if decision.finding_id != finding.id:
        raise ValueError("finding_decision_mismatch")
    if decision.decided_at.tzinfo is None or decision.decided_at.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
