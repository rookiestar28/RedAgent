"""Email domain-control assessment and phishing-resilience policy gates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping


class DomainControlCheckType(str, Enum):
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    MX = "mx"
    HTTPS = "https"
    HSTS = "hsts"


class DomainControlStatus(str, Enum):
    PRESENT = "present"
    MISSING = "missing"
    WEAK = "weak"
    UNKNOWN = "unknown"


class SimulationDecisionReason(str, Enum):
    APPROVED_FOR_REVIEW_QUEUE = "approved_for_review_queue"
    MISSING_APPROVAL = "missing_approval"
    PROHIBITED_ACTIVITY = "prohibited_activity"
    UNSANCTIONED_RECIPIENTS = "unsanctioned_recipients"
    INVALID_REQUEST = "invalid_request"


class ProhibitedSimulationActivity(str, Enum):
    CREDENTIAL_COLLECTION = "credential_collection"
    MALWARE_ATTACHMENT = "malware_attachment"
    DECEPTIVE_THIRD_PARTY_BRANDING = "deceptive_third_party_branding"
    UNSANCTIONED_EXTERNAL_RECIPIENT = "unsanctioned_external_recipient"


REQUIRED_DOMAIN_CHECKS: frozenset[DomainControlCheckType] = frozenset(DomainControlCheckType)


@dataclass(frozen=True, kw_only=True)
class DomainControlCheck:
    check_type: DomainControlCheckType
    status: DomainControlStatus
    observation: str
    remediation: str


@dataclass(frozen=True, kw_only=True)
class DomainControlAssessment:
    domain: str
    checks: tuple[DomainControlCheck, ...]
    collected_at: datetime
    source: str = "read_only_domain_control_plan"


@dataclass(frozen=True, kw_only=True)
class SimulationApproval:
    executive_approved_by_user_id: str | None
    legal_privacy_review_id: str | None
    audience_scope_id: str | None
    message_review_id: str | None
    schedule_id: str | None
    opt_out_exception_process_id: str | None
    incident_response_coordination_id: str | None


@dataclass(frozen=True, kw_only=True)
class RecipientScope:
    authorized_domains: tuple[str, ...]
    requested_recipient_domains: tuple[str, ...]
    audience_description: str


@dataclass(frozen=True, kw_only=True)
class PhishingSimulationRequest:
    simulation_id: str
    organization_id: str
    engagement_id: str
    requested_by_user_id: str
    approval: SimulationApproval
    recipient_scope: RecipientScope
    requested_activities: tuple[ProhibitedSimulationActivity, ...]
    created_at: datetime


@dataclass(frozen=True, kw_only=True)
class SimulationPolicyDecision:
    allowed: bool
    reason: SimulationDecisionReason
    details: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class AggregateCampaignMetrics:
    delivered_count: int
    reported_count: int
    clicked_count: int
    training_completed_count: int


@dataclass(frozen=True, kw_only=True)
class EmailResilienceEvidence:
    evidence_id: str
    domain: str
    aggregate_metrics: AggregateCampaignMetrics | None
    domain_control_summary: Mapping[DomainControlCheckType, DomainControlStatus]
    personal_mailbox_content_present: bool = False


@dataclass(frozen=True, kw_only=True)
class EmailResilienceReport:
    report_id: str
    domain_control_findings: tuple[dict[str, str], ...]
    campaign_outcomes: tuple[dict[str, int | str], ...]


def validate_domain_control_assessment(assessment: DomainControlAssessment) -> None:
    _require_non_empty("domain", assessment.domain)
    _require_non_empty("source", assessment.source)
    _require_timezone(assessment.collected_at)
    if not assessment.checks:
        raise ValueError("missing_domain_control_checks")
    present_types = {check.check_type for check in assessment.checks}
    missing = REQUIRED_DOMAIN_CHECKS - present_types
    if missing:
        missing_names = ",".join(sorted(check.value for check in missing))
        raise ValueError(f"missing_domain_control_checks:{missing_names}")
    for check in assessment.checks:
        _require_non_empty("observation", check.observation)
        _require_non_empty("remediation", check.remediation)


def summarize_domain_control(assessment: DomainControlAssessment) -> dict[DomainControlCheckType, DomainControlStatus]:
    validate_domain_control_assessment(assessment)
    return {check.check_type: check.status for check in assessment.checks}


def evaluate_phishing_simulation_request(request: PhishingSimulationRequest) -> SimulationPolicyDecision:
    try:
        _validate_simulation_request(request)
    except ValueError as exc:
        return SimulationPolicyDecision(allowed=False, reason=SimulationDecisionReason.INVALID_REQUEST, details=(str(exc),))

    missing_approvals = _missing_approval_fields(request.approval)
    if missing_approvals:
        return SimulationPolicyDecision(
            allowed=False,
            reason=SimulationDecisionReason.MISSING_APPROVAL,
            details=missing_approvals,
        )
    if request.requested_activities:
        return SimulationPolicyDecision(
            allowed=False,
            reason=SimulationDecisionReason.PROHIBITED_ACTIVITY,
            details=tuple(activity.value for activity in request.requested_activities),
        )
    unsanctioned_domains = _unsanctioned_recipient_domains(request.recipient_scope)
    if unsanctioned_domains:
        return SimulationPolicyDecision(
            allowed=False,
            reason=SimulationDecisionReason.UNSANCTIONED_RECIPIENTS,
            details=unsanctioned_domains,
        )
    return SimulationPolicyDecision(
        allowed=True,
        reason=SimulationDecisionReason.APPROVED_FOR_REVIEW_QUEUE,
        details=("policy_review_queue_only",),
    )


def export_aggregate_evidence(evidence: EmailResilienceEvidence) -> dict[str, object]:
    _require_non_empty("evidence_id", evidence.evidence_id)
    _require_non_empty("domain", evidence.domain)
    if evidence.personal_mailbox_content_present:
        raise ValueError("personal_mailbox_content_forbidden")
    if not evidence.domain_control_summary:
        raise ValueError("missing_domain_control_summary")
    payload: dict[str, object] = {
        "evidence_id": evidence.evidence_id,
        "domain": evidence.domain,
        "domain_control_summary": {
            check.value: status.value for check, status in sorted(evidence.domain_control_summary.items(), key=lambda item: item[0].value)
        },
        "personal_mailbox_content_stored": False,
    }
    if evidence.aggregate_metrics is not None:
        _validate_aggregate_metrics(evidence.aggregate_metrics)
        payload["aggregate_metrics"] = {
            "delivered_count": evidence.aggregate_metrics.delivered_count,
            "reported_count": evidence.aggregate_metrics.reported_count,
            "clicked_count": evidence.aggregate_metrics.clicked_count,
            "training_completed_count": evidence.aggregate_metrics.training_completed_count,
        }
    return payload


def build_email_resilience_report(
    *,
    report_id: str,
    domain_assessment: DomainControlAssessment,
    evidence: EmailResilienceEvidence,
) -> EmailResilienceReport:
    _require_non_empty("report_id", report_id)
    summary = summarize_domain_control(domain_assessment)
    exported = export_aggregate_evidence(evidence)
    metrics = exported.get("aggregate_metrics", {})
    if metrics and not isinstance(metrics, dict):
        raise ValueError("invalid_aggregate_metrics")
    return EmailResilienceReport(
        report_id=report_id,
        domain_control_findings=tuple(
            {
                "domain": domain_assessment.domain,
                "check_type": check_type.value,
                "status": status.value,
            }
            for check_type, status in sorted(summary.items(), key=lambda item: item[0].value)
        ),
        campaign_outcomes=(
            {
                "domain": evidence.domain,
                "delivered_count": int(metrics.get("delivered_count", 0)) if isinstance(metrics, dict) else 0,
                "reported_count": int(metrics.get("reported_count", 0)) if isinstance(metrics, dict) else 0,
                "clicked_count": int(metrics.get("clicked_count", 0)) if isinstance(metrics, dict) else 0,
                "training_completed_count": int(metrics.get("training_completed_count", 0)) if isinstance(metrics, dict) else 0,
            },
        ),
    )


def _validate_simulation_request(request: PhishingSimulationRequest) -> None:
    for field_name, value in (
        ("simulation_id", request.simulation_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("requested_by_user_id", request.requested_by_user_id),
        ("audience_description", request.recipient_scope.audience_description),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.created_at)
    if not request.recipient_scope.authorized_domains:
        raise ValueError("missing_authorized_recipient_domains")
    if not request.recipient_scope.requested_recipient_domains:
        raise ValueError("missing_requested_recipient_domains")
    for domain in request.recipient_scope.authorized_domains + request.recipient_scope.requested_recipient_domains:
        _require_non_empty("recipient_domain", domain)


def _missing_approval_fields(approval: SimulationApproval) -> tuple[str, ...]:
    fields = (
        ("executive_approved_by_user_id", approval.executive_approved_by_user_id),
        ("legal_privacy_review_id", approval.legal_privacy_review_id),
        ("audience_scope_id", approval.audience_scope_id),
        ("message_review_id", approval.message_review_id),
        ("schedule_id", approval.schedule_id),
        ("opt_out_exception_process_id", approval.opt_out_exception_process_id),
        ("incident_response_coordination_id", approval.incident_response_coordination_id),
    )
    return tuple(field_name for field_name, value in fields if not value or not value.strip())


def _unsanctioned_recipient_domains(scope: RecipientScope) -> tuple[str, ...]:
    authorized = {_normalize_domain(domain) for domain in scope.authorized_domains}
    requested = {_normalize_domain(domain) for domain in scope.requested_recipient_domains}
    return tuple(sorted(requested - authorized))


def _validate_aggregate_metrics(metrics: AggregateCampaignMetrics) -> None:
    for field_name, value in (
        ("delivered_count", metrics.delivered_count),
        ("reported_count", metrics.reported_count),
        ("clicked_count", metrics.clicked_count),
        ("training_completed_count", metrics.training_completed_count),
    ):
        if value < 0:
            raise ValueError(f"invalid_{field_name}")


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
