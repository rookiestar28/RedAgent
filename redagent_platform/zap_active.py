"""R017-gated ZAP active scan planning and result normalization contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from redagent_platform.active_policy import ActiveJobRequest, ActivePolicyResult, PayloadClass
from redagent_platform.auth_sessions import AuthenticatedSessionContext
from redagent_platform.domain import EvidenceKind, FindingStatus, JobStatus, PolicyDecisionOutcome, TargetType
from redagent_platform.evidence_chain import (
    AuditAction,
    EvidenceAccessPolicy,
    EvidenceChain,
    EvidenceRecord,
    RedactionStatus,
    RetentionClass,
)
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
from redagent_platform.redaction import RedactionArtifactClass, sanitize_text
from redagent_platform.zap_passive import ZapConfidence, ZapRisk


@dataclass(frozen=True, kw_only=True)
class ZapActiveScanPolicy:
    policy_id: str
    display_name: str
    payload_class: PayloadClass
    max_rule_strength: str


@dataclass(frozen=True, kw_only=True)
class ZapActiveWarning:
    warning_id: str
    title: str
    body: str


@dataclass(frozen=True, kw_only=True)
class ZapActiveWarningAcknowledgement:
    acknowledgement_id: str
    displayed_to_operator: bool
    acknowledged_by_user_id: str
    acknowledged_at: datetime
    warning_ids: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class ZapActiveLabValidation:
    validation_id: str
    passed: bool
    validated_at: datetime
    lab_target_id: str
    scan_policy_ids: tuple[str, ...]
    evidence_id: str


@dataclass(frozen=True, kw_only=True)
class ZapActiveScanPlanRequest:
    plan_id: str
    active_request: ActiveJobRequest
    active_policy: ActivePolicyResult
    scan_policy: ZapActiveScanPolicy
    warnings: tuple[ZapActiveWarning, ...]
    warning_acknowledgement: ZapActiveWarningAcknowledgement
    lab_validation: ZapActiveLabValidation | None
    authenticated_context: AuthenticatedSessionContext | None
    planned_at: datetime


@dataclass(frozen=True, kw_only=True)
class ZapActiveScanPlan:
    plan_id: str
    job: JobRecord
    scan_policy_id: str
    payload_class: PayloadClass
    authenticated_context_id: str | None
    warning_acknowledgement_id: str
    lab_validation_id: str | None
    timeout_seconds: int
    rate_limit_per_second: float
    max_requests: int
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class ZapActiveCancellationPlan:
    plan_id: str
    job_id: str
    status: JobStatus
    reason: str
    audit_chain: EvidenceChain


@dataclass(frozen=True, kw_only=True)
class ZapActiveAlert:
    plugin_id: str
    alert_id: str
    name: str
    risk: ZapRisk
    confidence: ZapConfidence
    url: str
    method: str
    attack: str
    evidence: str
    description: str
    solution: str
    cwe_id: str | None = None
    request_header: str | None = None
    response_header: str | None = None


@dataclass(frozen=True, kw_only=True)
class ZapActiveEvidenceResult:
    chain: EvidenceChain
    record: EvidenceRecord
    sanitized_content: dict[str, object]
    redacted: bool


def build_zap_active_scan_plan(request: ZapActiveScanPlanRequest) -> ZapActiveScanPlan:
    _validate_plan_request(request)
    active_request = request.active_request
    grant = request.active_policy.decision.policy_grant
    job = JobRecord(
        job_id=active_request.job_id,
        organization_id=active_request.organization_id,
        engagement_id=active_request.engagement_id,
        test_definition_id=request.scan_policy.policy_id,
        target=active_request.target.normalized(),
        mode=active_request.mode,
        status=JobStatus.AUTHORIZED,
        projected_interactions=active_request.projected_requests,
        timeout_seconds=active_request.projected_duration_seconds,
        cleanup_required=True,
        max_attempts=1,
        policy_decision_id=grant.decision_id if grant else None,
        policy_expires_at=grant.expires_at if grant else None,
        last_transition_at=request.planned_at,
    )
    return ZapActiveScanPlan(
        plan_id=request.plan_id.strip(),
        job=job,
        scan_policy_id=request.scan_policy.policy_id.strip(),
        payload_class=request.scan_policy.payload_class,
        authenticated_context_id=request.authenticated_context.session_id if request.authenticated_context else None,
        warning_acknowledgement_id=request.warning_acknowledgement.acknowledgement_id,
        lab_validation_id=request.lab_validation.validation_id if request.lab_validation else None,
        timeout_seconds=active_request.projected_duration_seconds,
        rate_limit_per_second=active_request.requested_rate_per_second,
        max_requests=active_request.projected_requests,
        cancellation_supported=True,
    )


def build_zap_active_cancellation_plan(
    *,
    plan: ZapActiveScanPlan,
    reason: str,
    actor_user_id: str,
    event_id: str,
    occurred_at: datetime,
    audit_chain: EvidenceChain,
) -> ZapActiveCancellationPlan:
    _require_non_empty("cancel_reason", reason)
    _require_non_empty("actor_user_id", actor_user_id)
    _require_non_empty("event_id", event_id)
    _require_timezone(occurred_at)
    next_chain = audit_chain.append_audit_event(
        event_id=event_id,
        organization_id=plan.job.organization_id,
        actor_user_id=actor_user_id,
        action=AuditAction.SCHEDULER_CONTROL,
        subject_type="zap_active_scan_plan",
        subject_id=plan.plan_id,
        occurred_at=occurred_at,
        details={"control": "cancel", "job_id": plan.job.job_id, "reason": reason},
    )
    return ZapActiveCancellationPlan(
        plan_id=plan.plan_id,
        job_id=plan.job.job_id,
        status=JobStatus.CANCELLED,
        reason=reason,
        audit_chain=next_chain,
    )


def append_zap_active_evidence(
    *,
    chain: EvidenceChain,
    plan: ZapActiveScanPlan,
    alert: ZapActiveAlert,
    evidence_id: str,
    observed_at: datetime,
) -> ZapActiveEvidenceResult:
    _validate_alert(alert)
    _require_non_empty("evidence_id", evidence_id)
    _require_timezone(observed_at)
    sanitized_content, redacted = _sanitized_alert_content(plan, alert)
    next_chain = chain.append_evidence_record(
        evidence_id=evidence_id,
        organization_id=plan.job.organization_id,
        source_job_id=plan.job.job_id,
        kind=EvidenceKind.SCANNER_OUTPUT,
        created_at=observed_at,
        redaction_status=RedactionStatus.REDACTED if redacted else RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=json.dumps(sanitized_content, sort_keys=True).encode("utf-8"),
        contains_sensitive_capture=redacted,
        metadata={
            "adapter": "zap_active",
            "plugin_id": alert.plugin_id,
            "scan_policy_id": plan.scan_policy_id,
        },
    )
    return ZapActiveEvidenceResult(
        chain=next_chain,
        record=next_chain.evidence_records[-1],
        sanitized_content=sanitized_content,
        redacted=redacted,
    )


def normalize_zap_active_alert_to_finding(
    *,
    finding_id: str,
    plan: ZapActiveScanPlan,
    alert: ZapActiveAlert,
    evidence_record: EvidenceRecord,
    owner_user_id: str | None = None,
) -> FindingRecord:
    _validate_alert(alert)
    _require_non_empty("finding_id", finding_id)
    evidence_link = EvidenceLink(
        evidence_id=evidence_record.id,
        integrity_hash=evidence_record.integrity_hash,
        redaction_status=evidence_record.redaction_status,
        contains_sensitive_payload=evidence_record.redaction_status is RedactionStatus.REDACTED,
    )
    finding = FindingRecord(
        id=finding_id.strip(),
        title=alert.name.strip(),
        status=FindingStatus.NEEDS_REVIEW,
        affected_asset_id=plan.job.target.normalized().value,
        affected_asset_value=alert.url.strip(),
        confidence=_map_confidence(alert.confidence),
        risk=RiskFactors(
            severity=_map_risk(alert.risk),
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(
                cve_ids=(),
                cwe_ids=(f"CWE-{alert.cwe_id}",) if alert.cwe_id and alert.cwe_id.isdigit() else (),
            ),
        ),
        reproduction_summary=f"ZAP active rule {alert.plugin_id} reported on {alert.method.upper()} {alert.url}.",
        evidence_links=(evidence_link,),
        remediation=alert.solution.strip(),
        owner_user_id=owner_user_id,
        source="zap_active",
        source_rule_id=alert.plugin_id.strip(),
    )
    validate_finding(finding)
    return finding


def _validate_plan_request(request: ZapActiveScanPlanRequest) -> None:
    _require_non_empty("plan_id", request.plan_id)
    _require_timezone(request.planned_at)
    if not request.active_policy.decision.allowed:
        raise ValueError(f"active_policy_denied:{request.active_policy.decision.reason}")
    if request.active_policy.decision.policy_grant is None:
        raise ValueError("active_policy_grant_required")
    if request.active_policy.decision.outcome is not PolicyDecisionOutcome.ALLOW:
        raise ValueError("active_policy_must_allow")
    _validate_scan_policy(request.scan_policy)
    if request.scan_policy.payload_class is not request.active_request.payload_class:
        raise ValueError("scan_policy_payload_class_mismatch")
    _validate_warning_acknowledgement(request)
    _validate_authenticated_context(request)
    _validate_lab_gate(request)


def _validate_scan_policy(policy: ZapActiveScanPolicy) -> None:
    for field_name, value in (
        ("policy_id", policy.policy_id),
        ("display_name", policy.display_name),
        ("max_rule_strength", policy.max_rule_strength),
    ):
        _require_non_empty(field_name, value)


def _validate_warning_acknowledgement(request: ZapActiveScanPlanRequest) -> None:
    acknowledgement = request.warning_acknowledgement
    _require_non_empty("acknowledgement_id", acknowledgement.acknowledgement_id)
    _require_non_empty("acknowledged_by_user_id", acknowledgement.acknowledged_by_user_id)
    _require_timezone(acknowledgement.acknowledged_at)
    if acknowledgement.acknowledged_at > request.planned_at:
        raise ValueError("warning_acknowledgement_after_plan")
    if not acknowledgement.displayed_to_operator:
        raise ValueError("active_warnings_not_displayed")
    warning_ids = {warning.warning_id for warning in request.warnings}
    if not warning_ids:
        raise ValueError("active_warnings_required")
    if set(acknowledgement.warning_ids) != warning_ids:
        raise ValueError("active_warning_acknowledgement_incomplete")


def _validate_authenticated_context(request: ZapActiveScanPlanRequest) -> None:
    context = request.authenticated_context
    if context is None:
        return
    if context.target.normalized() != request.active_request.target.normalized():
        raise ValueError("authenticated_context_target_mismatch")
    if context.mode is not request.active_request.mode:
        raise ValueError("authenticated_context_mode_mismatch")
    if request.planned_at >= context.expires_at:
        raise ValueError("authenticated_context_expired")


def _validate_lab_gate(request: ZapActiveScanPlanRequest) -> None:
    target_type = request.active_request.target.target_type
    if target_type is TargetType.LAB_TARGET:
        return
    validation = request.lab_validation
    if validation is None:
        raise ValueError("lab_validation_required_for_enterprise_target")
    _require_timezone(validation.validated_at)
    if not validation.passed:
        raise ValueError("lab_validation_must_pass")
    if request.scan_policy.policy_id not in validation.scan_policy_ids:
        raise ValueError("scan_policy_not_lab_validated")
    _require_non_empty("lab_validation_evidence_id", validation.evidence_id)


def _validate_alert(alert: ZapActiveAlert) -> None:
    for field_name, value in (
        ("plugin_id", alert.plugin_id),
        ("alert_id", alert.alert_id),
        ("name", alert.name),
        ("url", alert.url),
        ("method", alert.method),
        ("attack", alert.attack),
        ("evidence", alert.evidence),
        ("description", alert.description),
        ("solution", alert.solution),
    ):
        _require_non_empty(field_name, value)


def _sanitized_alert_content(plan: ZapActiveScanPlan, alert: ZapActiveAlert) -> tuple[dict[str, object], bool]:
    fields = {
        "request_header": alert.request_header,
        "response_header": alert.response_header,
        "attack": alert.attack,
        "evidence": alert.evidence,
        "description": alert.description,
    }
    sanitized: dict[str, str | None] = {}
    redacted = False
    for key, value in fields.items():
        if value is None:
            sanitized[key] = None
            continue
        result = sanitize_text(value, RedactionArtifactClass.SCANNER_OUTPUT)
        redacted = redacted or result.redacted
        sanitized[key] = result.sanitized_text
    return (
        {
            "plan_id": plan.plan_id,
            "plugin_id": alert.plugin_id,
            "alert_id": alert.alert_id,
            "name": alert.name,
            "risk": alert.risk.value,
            "confidence": alert.confidence.value,
            "url": alert.url,
            "method": alert.method.upper(),
            **sanitized,
        },
        redacted,
    )


def _map_risk(risk: ZapRisk) -> Severity:
    return {
        ZapRisk.INFORMATIONAL: Severity.INFO,
        ZapRisk.LOW: Severity.LOW,
        ZapRisk.MEDIUM: Severity.MEDIUM,
        ZapRisk.HIGH: Severity.HIGH,
    }[risk]


def _map_confidence(confidence: ZapConfidence) -> Confidence:
    return {
        ZapConfidence.FALSE_POSITIVE: Confidence.LOW,
        ZapConfidence.LOW: Confidence.LOW,
        ZapConfidence.MEDIUM: Confidence.MEDIUM,
        ZapConfidence.HIGH: Confidence.HIGH,
        ZapConfidence.CONFIRMED: Confidence.CONFIRMED,
    }[confidence]


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
