"""ZAP passive alert ingestion contracts.

This adapter normalizes supplied ZAP passive metadata. It never starts ZAP,
calls ZAP APIs, spiders, active-scans, or contacts targets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.domain import EvidenceKind, FindingStatus, TargetType, TestMode
from redagent_platform.evidence_chain import (
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
from redagent_platform.redaction import RedactionArtifactClass, sanitize_text
from redagent_platform.scope_authorization import EngagementScope, JobScopeRequest, ScopeTarget, decide_scope


class ZapRisk(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ZapConfidence(str, Enum):
    FALSE_POSITIVE = "False Positive"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CONFIRMED = "Confirmed"


@dataclass(frozen=True, kw_only=True)
class ZapPassiveCaptureContext:
    capture_id: str
    organization_id: str
    engagement_id: str
    target: ScopeTarget
    mode: TestMode
    captured_at: datetime
    projected_interactions: int = 1


@dataclass(frozen=True, kw_only=True)
class ZapPassiveAlert:
    plugin_id: str
    name: str
    risk: ZapRisk
    confidence: ZapConfidence
    url: str
    method: str
    evidence: str
    description: str
    solution: str
    cwe_id: str | None = None
    request_header: str | None = None
    response_header: str | None = None


@dataclass(frozen=True, kw_only=True)
class ZapPassiveAuthorization:
    allowed: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class ZapPassiveEvidenceResult:
    chain: EvidenceChain
    record: EvidenceRecord
    sanitized_content: dict[str, object]
    redacted: bool


def authorize_passive_capture(scope: EngagementScope, capture: ZapPassiveCaptureContext) -> ZapPassiveAuthorization:
    _validate_capture(capture)
    if capture.mode not in {TestMode.PASSIVE_SCAN, TestMode.LAB_ONLY_RUN}:
        return ZapPassiveAuthorization(allowed=False, reason="zap_passive_mode_required")
    if capture.mode is TestMode.LAB_ONLY_RUN and capture.target.target_type is not TargetType.LAB_TARGET:
        return ZapPassiveAuthorization(allowed=False, reason="lab_target_required")
    decision = decide_scope(
        scope,
        JobScopeRequest(
            target=capture.target,
            mode=capture.mode,
            requested_at=capture.captured_at,
            projected_interactions=capture.projected_interactions,
        ),
    )
    return ZapPassiveAuthorization(allowed=decision.allowed, reason=decision.reason)


def append_zap_passive_evidence(
    *,
    chain: EvidenceChain,
    capture: ZapPassiveCaptureContext,
    alert: ZapPassiveAlert,
    evidence_id: str,
    authorization: ZapPassiveAuthorization,
) -> ZapPassiveEvidenceResult:
    if not authorization.allowed:
        raise ValueError(f"zap_passive_capture_denied:{authorization.reason}")
    _validate_alert(alert)
    sanitized_content, redacted = _sanitized_alert_content(capture, alert)
    next_chain = chain.append_evidence_record(
        evidence_id=evidence_id,
        organization_id=capture.organization_id,
        source_job_id=capture.capture_id,
        kind=EvidenceKind.HTTP_METADATA,
        created_at=capture.captured_at,
        redaction_status=RedactionStatus.REDACTED if redacted else RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=json.dumps(sanitized_content, sort_keys=True).encode("utf-8"),
        contains_sensitive_capture=redacted,
        metadata={
            "adapter": "zap_passive",
            "plugin_id": alert.plugin_id,
            "target": capture.target.normalized().value,
        },
    )
    return ZapPassiveEvidenceResult(
        chain=next_chain,
        record=next_chain.evidence_records[-1],
        sanitized_content=sanitized_content,
        redacted=redacted,
    )


def normalize_zap_alert_to_finding(
    *,
    finding_id: str,
    capture: ZapPassiveCaptureContext,
    alert: ZapPassiveAlert,
    evidence_record: EvidenceRecord,
    authorization: ZapPassiveAuthorization,
    owner_user_id: str | None = None,
) -> FindingRecord:
    if not authorization.allowed:
        raise ValueError(f"zap_passive_capture_denied:{authorization.reason}")
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
        affected_asset_id=capture.target.normalized().value,
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
        reproduction_summary=f"ZAP passive rule {alert.plugin_id} observed metadata on {alert.method.upper()} {alert.url}.",
        evidence_links=(evidence_link,),
        remediation=alert.solution.strip(),
        owner_user_id=owner_user_id,
        source="zap_passive",
        source_rule_id=alert.plugin_id.strip(),
    )
    validate_finding(finding)
    return finding


def start_active_scan(*_: object, **__: object) -> None:
    raise ValueError("zap_active_scan_disabled_by_policy")


def spider_target(*_: object, **__: object) -> None:
    raise ValueError("zap_spider_disabled_by_policy")


def _sanitized_alert_content(capture: ZapPassiveCaptureContext, alert: ZapPassiveAlert) -> tuple[dict[str, object], bool]:
    fields = {
        "request_header": alert.request_header,
        "response_header": alert.response_header,
        "evidence": alert.evidence,
        "description": alert.description,
    }
    sanitized: dict[str, str | None] = {}
    redacted = False
    for key, value in fields.items():
        if value is None:
            sanitized[key] = None
            continue
        result = sanitize_text(value, RedactionArtifactClass.HTTP_METADATA)
        redacted = redacted or result.redacted
        sanitized[key] = result.sanitized_text
    return (
        {
            "capture_id": capture.capture_id,
            "plugin_id": alert.plugin_id,
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


def _validate_capture(capture: ZapPassiveCaptureContext) -> None:
    for field_name, value in (
        ("capture_id", capture.capture_id),
        ("organization_id", capture.organization_id),
        ("engagement_id", capture.engagement_id),
    ):
        _require_non_empty(field_name, value)
    if capture.projected_interactions <= 0:
        raise ValueError("invalid_projected_interactions")
    if capture.captured_at.tzinfo is None or capture.captured_at.utcoffset() is None:
        raise ValueError("timezone_required")


def _validate_alert(alert: ZapPassiveAlert) -> None:
    for field_name, value in (
        ("plugin_id", alert.plugin_id),
        ("name", alert.name),
        ("url", alert.url),
        ("method", alert.method),
        ("evidence", alert.evidence),
        ("description", alert.description),
        ("solution", alert.solution),
    ):
        _require_non_empty(field_name, value)


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
