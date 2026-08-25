"""R017-gated Nuclei controlled execution planning and result normalization."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from redagent_platform.active_policy import ActiveJobRequest, ActivePolicyResult
from redagent_platform.domain import EvidenceKind, FindingStatus, JobStatus, PolicyDecisionOutcome, TestRiskClass
from redagent_platform.evidence_chain import AuditAction, EvidenceAccessPolicy, EvidenceChain, EvidenceRecord, RedactionStatus, RetentionClass
from redagent_platform.findings import (
    AssetCriticality,
    BusinessImpact,
    Confidence,
    EvidenceLink,
    ExploitLikelihood,
    FindingRecord,
    RiskFactors,
    Severity,
    VulnerabilityIntelligence,
    validate_finding,
)
from redagent_platform.job_queue import JobRecord
from redagent_platform.nuclei_metadata import NucleiReviewStatus, NucleiSeverity, NucleiTemplateReview
from redagent_platform.redaction import RedactionArtifactClass, sanitize_text


@dataclass(frozen=True, kw_only=True)
class NucleiExecutionPolicy:
    approved_template_ids: tuple[str, ...]
    allowed_severities: tuple[NucleiSeverity, ...]
    allowed_risk_classes: tuple[TestRiskClass, ...]
    allowed_protocols: tuple[str, ...]
    max_rate_per_second: float
    timeout_seconds: int
    max_results: int
    oast_allowed: bool
    output_redaction_required: bool
    cancellation_required: bool


@dataclass(frozen=True, kw_only=True)
class NucleiExecutionPlanRequest:
    plan_id: str
    active_request: ActiveJobRequest
    active_policy: ActivePolicyResult
    template_review: NucleiTemplateReview
    execution_policy: NucleiExecutionPolicy
    planned_at: datetime


@dataclass(frozen=True, kw_only=True)
class NucleiExecutionPlan:
    plan_id: str
    job: JobRecord
    template_id: str
    protocols: tuple[str, ...]
    severity: NucleiSeverity
    risk_class: TestRiskClass
    rate_limit_per_second: float
    timeout_seconds: int
    max_results: int
    output_redaction_required: bool
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class NucleiCancellationPlan:
    plan_id: str
    job_id: str
    status: JobStatus
    reason: str
    audit_chain: EvidenceChain


@dataclass(frozen=True, kw_only=True)
class NucleiResult:
    template_id: str
    matcher_name: str
    matched_at: str
    host: str
    url: str
    extracted_results: tuple[str, ...]
    request: str | None = None
    response: str | None = None


@dataclass(frozen=True, kw_only=True)
class NucleiEvidenceResult:
    chain: EvidenceChain
    record: EvidenceRecord
    sanitized_content: dict[str, object]
    redacted: bool


_OAST_MARKERS = frozenset({"oast", "interactsh"})


def build_nuclei_execution_plan(request: NucleiExecutionPlanRequest) -> NucleiExecutionPlan:
    _validate_plan_request(request)
    active_request = request.active_request
    grant = request.active_policy.decision.policy_grant
    template = request.template_review.template
    job = JobRecord(
        job_id=active_request.job_id,
        organization_id=active_request.organization_id,
        engagement_id=active_request.engagement_id,
        test_definition_id=template.template_id,
        target=active_request.target.normalized(),
        mode=active_request.mode,
        status=JobStatus.AUTHORIZED,
        projected_interactions=active_request.projected_requests,
        timeout_seconds=min(active_request.projected_duration_seconds, request.execution_policy.timeout_seconds),
        cleanup_required=True,
        max_attempts=1,
        policy_decision_id=grant.decision_id if grant else None,
        policy_expires_at=grant.expires_at if grant else None,
        last_transition_at=request.planned_at,
    )
    return NucleiExecutionPlan(
        plan_id=request.plan_id.strip(),
        job=job,
        template_id=template.template_id,
        protocols=template.protocol_types,
        severity=template.severity,
        risk_class=template.risk_class,
        rate_limit_per_second=min(active_request.requested_rate_per_second, request.execution_policy.max_rate_per_second),
        timeout_seconds=job.timeout_seconds,
        max_results=request.execution_policy.max_results,
        output_redaction_required=True,
        cancellation_supported=True,
    )


def build_nuclei_cancellation_plan(
    *,
    plan: NucleiExecutionPlan,
    reason: str,
    actor_user_id: str,
    event_id: str,
    occurred_at: datetime,
    audit_chain: EvidenceChain,
) -> NucleiCancellationPlan:
    _require_non_empty("cancel_reason", reason)
    _require_non_empty("actor_user_id", actor_user_id)
    _require_non_empty("event_id", event_id)
    _require_timezone(occurred_at)
    next_chain = audit_chain.append_audit_event(
        event_id=event_id,
        organization_id=plan.job.organization_id,
        actor_user_id=actor_user_id,
        action=AuditAction.SCHEDULER_CONTROL,
        subject_type="nuclei_execution_plan",
        subject_id=plan.plan_id,
        occurred_at=occurred_at,
        details={"control": "cancel", "job_id": plan.job.job_id, "reason": reason},
    )
    return NucleiCancellationPlan(plan_id=plan.plan_id, job_id=plan.job.job_id, status=JobStatus.CANCELLED, reason=reason, audit_chain=next_chain)


def append_nuclei_result_evidence(
    *,
    chain: EvidenceChain,
    plan: NucleiExecutionPlan,
    result: NucleiResult,
    evidence_id: str,
    observed_at: datetime,
) -> NucleiEvidenceResult:
    _validate_result(plan, result)
    _require_non_empty("evidence_id", evidence_id)
    _require_timezone(observed_at)
    content, redacted = _sanitize_result(plan, result)
    next_chain = chain.append_evidence_record(
        evidence_id=evidence_id,
        organization_id=plan.job.organization_id,
        source_job_id=plan.job.job_id,
        kind=EvidenceKind.SCANNER_OUTPUT,
        created_at=observed_at,
        redaction_status=RedactionStatus.REDACTED if redacted else RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=json.dumps(content, sort_keys=True).encode("utf-8"),
        contains_sensitive_capture=redacted,
        metadata={"adapter": "nuclei_controlled", "template_id": result.template_id},
    )
    return NucleiEvidenceResult(chain=next_chain, record=next_chain.evidence_records[-1], sanitized_content=content, redacted=redacted)


def normalize_nuclei_result_to_finding(
    *,
    finding_id: str,
    plan: NucleiExecutionPlan,
    result: NucleiResult,
    evidence_record: EvidenceRecord,
    owner_user_id: str | None = None,
) -> FindingRecord:
    _validate_result(plan, result)
    evidence_link = EvidenceLink(
        evidence_id=evidence_record.id,
        integrity_hash=evidence_record.integrity_hash,
        redaction_status=evidence_record.redaction_status,
        contains_sensitive_payload=evidence_record.redaction_status is RedactionStatus.REDACTED,
    )
    finding = FindingRecord(
        id=finding_id.strip(),
        title=f"Nuclei template {plan.template_id} matched",
        status=FindingStatus.NEEDS_REVIEW,
        affected_asset_id=plan.job.target.normalized().value,
        affected_asset_value=result.url.strip(),
        confidence=Confidence.MEDIUM,
        risk=RiskFactors(
            severity=_map_severity(plan.severity),
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=f"Nuclei template {plan.template_id} matched {result.matcher_name} at {result.url}.",
        evidence_links=(evidence_link,),
        remediation="Review the matched template context and remediate according to the approved advisory.",
        owner_user_id=owner_user_id,
        source="nuclei",
        source_rule_id=plan.template_id,
    )
    validate_finding(finding)
    return finding


def _validate_plan_request(request: NucleiExecutionPlanRequest) -> None:
    _require_non_empty("plan_id", request.plan_id)
    _require_timezone(request.planned_at)
    if not request.active_policy.decision.allowed:
        raise ValueError(f"active_policy_denied:{request.active_policy.decision.reason}")
    if request.active_policy.decision.outcome is not PolicyDecisionOutcome.ALLOW:
        raise ValueError("active_policy_must_allow")
    if request.active_policy.decision.policy_grant is None:
        raise ValueError("active_policy_grant_required")
    template = request.template_review.template
    policy = request.execution_policy
    _validate_policy(policy)
    if request.template_review.status is not NucleiReviewStatus.APPROVED:
        raise ValueError("template_review_must_be_approved")
    if request.template_review.execution_enabled:
        raise ValueError("r016_execution_flag_must_remain_disabled")
    if template.template_id not in policy.approved_template_ids:
        raise ValueError("template_id_not_approved")
    if template.severity not in policy.allowed_severities:
        raise ValueError("severity_not_allowed")
    if template.risk_class not in policy.allowed_risk_classes:
        raise ValueError("risk_class_not_allowed")
    if not set(template.protocol_types).issubset(set(policy.allowed_protocols)):
        raise ValueError("protocol_not_allowed")
    if not policy.oast_allowed and _template_requires_oast(template.high_risk_reasons, template.tags):
        raise ValueError("oast_not_allowed")
    if request.active_request.requested_rate_per_second > policy.max_rate_per_second:
        raise ValueError("rate_limit_exceeded")
    if request.active_request.projected_duration_seconds > policy.timeout_seconds:
        raise ValueError("timeout_exceeded")
    if not policy.output_redaction_required:
        raise ValueError("output_redaction_required")
    if not policy.cancellation_required:
        raise ValueError("cancellation_required")


def _validate_policy(policy: NucleiExecutionPolicy) -> None:
    if not policy.approved_template_ids:
        raise ValueError("missing_approved_template_ids")
    if not policy.allowed_severities:
        raise ValueError("missing_allowed_severities")
    if not policy.allowed_risk_classes:
        raise ValueError("missing_allowed_risk_classes")
    if not policy.allowed_protocols:
        raise ValueError("missing_allowed_protocols")
    if policy.max_rate_per_second <= 0:
        raise ValueError("invalid_rate_limit")
    if policy.timeout_seconds <= 0:
        raise ValueError("invalid_timeout")
    if policy.max_results <= 0:
        raise ValueError("invalid_max_results")


def _validate_result(plan: NucleiExecutionPlan, result: NucleiResult) -> None:
    for field_name, value in (
        ("template_id", result.template_id),
        ("matcher_name", result.matcher_name),
        ("matched_at", result.matched_at),
        ("host", result.host),
        ("url", result.url),
    ):
        _require_non_empty(field_name, value)
    if result.template_id != plan.template_id:
        raise ValueError("result_template_mismatch")


def _sanitize_result(plan: NucleiExecutionPlan, result: NucleiResult) -> tuple[dict[str, object], bool]:
    fields = {
        "request": result.request,
        "response": result.response,
        "extracted_results": "\n".join(result.extracted_results),
    }
    sanitized: dict[str, str | None] = {}
    redacted = False
    for key, value in fields.items():
        if value is None:
            sanitized[key] = None
            continue
        redaction_result = sanitize_text(value, RedactionArtifactClass.SCANNER_OUTPUT)
        redacted = redacted or redaction_result.redacted
        sanitized[key] = redaction_result.sanitized_text
    return (
        {
            "plan_id": plan.plan_id,
            "template_id": result.template_id,
            "matcher_name": result.matcher_name,
            "matched_at": result.matched_at,
            "host": result.host,
            "url": result.url,
            **sanitized,
        },
        redacted,
    )


def _template_requires_oast(reasons: tuple[str, ...], tags: tuple[str, ...]) -> bool:
    return any(marker in tag for marker in _OAST_MARKERS for tag in tags) or any(
        marker in reason for marker in _OAST_MARKERS for reason in reasons
    )


def _map_severity(severity: NucleiSeverity) -> Severity:
    return {
        NucleiSeverity.INFO: Severity.INFO,
        NucleiSeverity.LOW: Severity.LOW,
        NucleiSeverity.MEDIUM: Severity.MEDIUM,
        NucleiSeverity.HIGH: Severity.HIGH,
        NucleiSeverity.CRITICAL: Severity.CRITICAL,
        NucleiSeverity.UNKNOWN: Severity.INFO,
    }[severity]


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
