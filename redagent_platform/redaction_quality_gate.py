"""Redaction quality and data-classification export gate contracts.

The gate evaluates supplied local artifacts only. It does not publish reports,
call DLP services, dispatch runners, or interact with targets.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.evidence_chain import AuditAction, EvidenceChain, RedactionStatus
from redagent_platform.redaction import (
    RedactionArtifactClass,
    RedactionCategory,
    RedactionConfig,
    RedactionResult,
    sanitize_text,
)


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class RedactionQualityRisk(str, Enum):
    CANARY_LEAK = "canary_leak"
    KEY_MATERIAL = "key_material"
    RAW_AUTH_MATERIAL = "raw_auth_material"
    SENSITIVE_PERSONAL_DATA = "sensitive_personal_data"
    UNREVIEWED_HIGH_RISK_FIELD = "unreviewed_high_risk_field"


HIGH_RISK_CLASSIFICATIONS: frozenset[DataClassification] = frozenset(
    {DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED}
)
NON_OVERRIDABLE_RISKS: frozenset[RedactionQualityRisk] = frozenset(
    {
        RedactionQualityRisk.CANARY_LEAK,
        RedactionQualityRisk.KEY_MATERIAL,
        RedactionQualityRisk.RAW_AUTH_MATERIAL,
        RedactionQualityRisk.SENSITIVE_PERSONAL_DATA,
    }
)


@dataclass(frozen=True, kw_only=True)
class ClassifiedArtifact:
    artifact_id: str
    artifact_class: RedactionArtifactClass
    classification: DataClassification
    redaction_status: RedactionStatus
    content: str
    high_risk_field_names: tuple[str, ...] = ()
    evidence_attestation_hash: str | None = None


@dataclass(frozen=True, kw_only=True)
class ManualReviewOverride:
    override_id: str
    reviewer_user_id: str
    reason: str
    scope_artifact_ids: tuple[str, ...]
    approved_at: datetime
    expires_at: datetime
    allowed_risks: tuple[RedactionQualityRisk, ...]
    audit_event_hash: str
    override_hash: str


@dataclass(frozen=True, kw_only=True)
class ArtifactQualityFinding:
    artifact_id: str
    risk: RedactionQualityRisk
    category: RedactionCategory | None
    reason: str
    overridable: bool
    finding_hash: str


@dataclass(frozen=True, kw_only=True)
class ArtifactQualityResult:
    artifact_id: str
    artifact_class: RedactionArtifactClass
    classification: DataClassification
    redaction_status: RedactionStatus
    sanitized_hash: str
    findings: tuple[ArtifactQualityFinding, ...]
    allowed: bool
    reason: str
    result_hash: str


@dataclass(frozen=True, kw_only=True)
class RedactionQualityGateRequest:
    gate_id: str
    organization_id: str
    requested_by_user_id: str
    requested_at: datetime
    artifacts: tuple[ClassifiedArtifact, ...]
    canary_markers: tuple[str, ...] = ()
    manual_override: ManualReviewOverride | None = None


@dataclass(frozen=True, kw_only=True)
class RedactionQualityGateResult:
    gate_id: str
    allowed: bool
    reason: str
    artifact_results: tuple[ArtifactQualityResult, ...]
    audit_chain: EvidenceChain
    result_hash: str


def build_manual_review_override(
    *,
    override_id: str,
    organization_id: str,
    reviewer_user_id: str,
    reason: str,
    scope_artifact_ids: tuple[str, ...],
    approved_at: datetime,
    expires_at: datetime,
    allowed_risks: tuple[RedactionQualityRisk, ...],
    audit_chain: EvidenceChain,
) -> tuple[ManualReviewOverride, EvidenceChain]:
    for field_name, value in (
        ("override_id", override_id),
        ("organization_id", organization_id),
        ("reviewer_user_id", reviewer_user_id),
        ("reason", reason),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(approved_at)
    _require_timezone(expires_at)
    if expires_at <= approved_at:
        raise ValueError("manual_override_expiry_invalid")
    if not scope_artifact_ids:
        raise ValueError("manual_override_scope_required")
    if not allowed_risks:
        raise ValueError("manual_override_risks_required")
    if any(risk in NON_OVERRIDABLE_RISKS for risk in allowed_risks):
        raise ValueError("manual_override_non_overridable_risk")
    scope = tuple(sorted(_clean_identifier("scope_artifact_id", artifact_id) for artifact_id in scope_artifact_ids))
    risks = tuple(sorted(allowed_risks, key=lambda risk: risk.value))
    next_chain = audit_chain.append_audit_event(
        event_id=f"{override_id.strip()}:manual-redaction-override",
        organization_id=organization_id.strip(),
        actor_user_id=reviewer_user_id.strip(),
        action=AuditAction.POLICY_DECISION,
        subject_type="redaction_quality_override",
        subject_id=override_id.strip(),
        occurred_at=approved_at,
        details={
            "scope_artifact_ids": scope,
            "allowed_risks": tuple(risk.value for risk in risks),
            "expires_at": expires_at.isoformat(),
            "reason_hash": _sha256_text(reason.strip()),
        },
    )
    payload = {
        "override_id": override_id.strip(),
        "reviewer_user_id": reviewer_user_id.strip(),
        "reason_hash": _sha256_text(reason.strip()),
        "scope_artifact_ids": scope,
        "approved_at": approved_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "allowed_risks": tuple(risk.value for risk in risks),
        "audit_event_hash": next_chain.audit_events[-1].event_hash,
    }
    override = ManualReviewOverride(
        override_id=override_id.strip(),
        reviewer_user_id=reviewer_user_id.strip(),
        reason=reason.strip(),
        scope_artifact_ids=scope,
        approved_at=approved_at,
        expires_at=expires_at,
        allowed_risks=risks,
        audit_event_hash=next_chain.audit_events[-1].event_hash,
        override_hash=_canonical_sha256(payload),
    )
    return override, next_chain


def evaluate_redaction_quality_gate(
    request: RedactionQualityGateRequest,
    audit_chain: EvidenceChain,
) -> RedactionQualityGateResult:
    _validate_request(request)
    artifact_results = tuple(_evaluate_artifact(request, artifact) for artifact in request.artifacts)
    allowed = all(result.allowed for result in artifact_results)
    reason = "redaction_quality_allowed" if allowed else "redaction_quality_denied"
    next_chain = audit_chain.append_audit_event(
        event_id=f"{request.gate_id}:redaction-quality-gate",
        organization_id=request.organization_id,
        actor_user_id=request.requested_by_user_id,
        action=AuditAction.POLICY_DECISION,
        subject_type="redaction_quality_gate",
        subject_id=request.gate_id,
        occurred_at=request.requested_at,
        details={
            "allowed": allowed,
            "artifact_result_hashes": tuple(result.result_hash for result in artifact_results),
            "manual_override_hash": request.manual_override.override_hash if request.manual_override else None,
        },
    )
    payload = {
        "gate_id": request.gate_id,
        "allowed": allowed,
        "reason": reason,
        "artifact_result_hashes": tuple(result.result_hash for result in artifact_results),
        "audit_event_hash": next_chain.audit_events[-1].event_hash,
    }
    return RedactionQualityGateResult(
        gate_id=request.gate_id,
        allowed=allowed,
        reason=reason,
        artifact_results=artifact_results,
        audit_chain=next_chain,
        result_hash=_canonical_sha256(payload),
    )


def _evaluate_artifact(
    request: RedactionQualityGateRequest,
    artifact: ClassifiedArtifact,
) -> ArtifactQualityResult:
    _validate_artifact(artifact)
    redaction_result = sanitize_text(
        artifact.content,
        artifact.artifact_class,
        RedactionConfig(canary_markers=request.canary_markers),
    )
    findings = tuple(_findings_for_artifact(artifact, redaction_result, request))
    unwaived = tuple(finding for finding in findings if not _override_allows(request.manual_override, artifact, finding, request.requested_at))
    allowed = not unwaived
    reason = "artifact_redaction_quality_allowed" if allowed else unwaived[0].reason
    payload = {
        "artifact_id": artifact.artifact_id,
        "artifact_class": artifact.artifact_class.value,
        "classification": artifact.classification.value,
        "redaction_status": artifact.redaction_status.value,
        "sanitized_hash": redaction_result.sanitized_hash,
        "findings": tuple(_finding_payload(finding) for finding in findings),
        "allowed": allowed,
        "reason": reason,
    }
    return ArtifactQualityResult(
        artifact_id=artifact.artifact_id,
        artifact_class=artifact.artifact_class,
        classification=artifact.classification,
        redaction_status=artifact.redaction_status,
        sanitized_hash=redaction_result.sanitized_hash,
        findings=findings,
        allowed=allowed,
        reason=reason,
        result_hash=_canonical_sha256(payload),
    )


def _findings_for_artifact(
    artifact: ClassifiedArtifact,
    redaction_result: RedactionResult,
    request: RedactionQualityGateRequest,
) -> tuple[ArtifactQualityFinding, ...]:
    findings: list[ArtifactQualityFinding] = []
    raw_content_changed = redaction_result.sanitized_text != artifact.content
    categories = {finding.category for finding in redaction_result.evidence}
    for category in sorted(categories, key=lambda item: item.value):
        risk = _risk_for_category(category)
        if risk is None:
            continue
        if category is RedactionCategory.CANARY:
            findings.append(_finding(artifact.artifact_id, risk, category, "canary_leak_detected"))
        elif category is RedactionCategory.KEY_BLOCK:
            findings.append(_finding(artifact.artifact_id, risk, category, "key_material_detected"))
        elif raw_content_changed:
            findings.append(_finding(artifact.artifact_id, risk, category, f"{risk.value}_detected"))

    if _high_risk_requires_review(artifact) and not _has_valid_high_risk_review(artifact, request):
        findings.append(
            _finding(
                artifact.artifact_id,
                RedactionQualityRisk.UNREVIEWED_HIGH_RISK_FIELD,
                None,
                "unreviewed_high_risk_field",
            )
        )
    return tuple(findings)


def _risk_for_category(category: RedactionCategory) -> RedactionQualityRisk | None:
    if category is RedactionCategory.CANARY:
        return RedactionQualityRisk.CANARY_LEAK
    if category is RedactionCategory.KEY_BLOCK:
        return RedactionQualityRisk.KEY_MATERIAL
    if category in {
        RedactionCategory.AUTH_HEADER,
        RedactionCategory.BEARER_AUTH,
        RedactionCategory.SENSITIVE_ASSIGNMENT,
    }:
        return RedactionQualityRisk.RAW_AUTH_MATERIAL
    if category in {RedactionCategory.EMAIL, RedactionCategory.PHONE, RedactionCategory.SSN}:
        return RedactionQualityRisk.SENSITIVE_PERSONAL_DATA
    return None


def _finding(
    artifact_id: str,
    risk: RedactionQualityRisk,
    category: RedactionCategory | None,
    reason: str,
) -> ArtifactQualityFinding:
    payload = {
        "artifact_id": artifact_id,
        "risk": risk.value,
        "category": category.value if category else None,
        "reason": reason,
        "overridable": risk not in NON_OVERRIDABLE_RISKS,
    }
    return ArtifactQualityFinding(
        artifact_id=artifact_id,
        risk=risk,
        category=category,
        reason=reason,
        overridable=risk not in NON_OVERRIDABLE_RISKS,
        finding_hash=_canonical_sha256(payload),
    )


def _override_allows(
    override: ManualReviewOverride | None,
    artifact: ClassifiedArtifact,
    finding: ArtifactQualityFinding,
    requested_at: datetime,
) -> bool:
    if not finding.overridable or override is None:
        return False
    return (
        artifact.artifact_id in override.scope_artifact_ids
        and finding.risk in override.allowed_risks
        and requested_at < override.expires_at
    )


def _high_risk_requires_review(artifact: ClassifiedArtifact) -> bool:
    if artifact.classification not in HIGH_RISK_CLASSIFICATIONS and not artifact.high_risk_field_names:
        return False
    return artifact.redaction_status not in {RedactionStatus.REDACTED, RedactionStatus.BLOCKED}


def _has_valid_high_risk_review(
    artifact: ClassifiedArtifact,
    request: RedactionQualityGateRequest,
) -> bool:
    if request.manual_override is None:
        return False
    return _override_allows(
        request.manual_override,
        artifact,
        _finding(
            artifact.artifact_id,
            RedactionQualityRisk.UNREVIEWED_HIGH_RISK_FIELD,
            None,
            "unreviewed_high_risk_field",
        ),
        request.requested_at,
    )


def _validate_request(request: RedactionQualityGateRequest) -> None:
    for field_name, value in (
        ("gate_id", request.gate_id),
        ("organization_id", request.organization_id),
        ("requested_by_user_id", request.requested_by_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    if not request.artifacts:
        raise ValueError("redaction_gate_artifacts_required")
    if request.manual_override is not None and request.manual_override.expires_at <= request.requested_at:
        raise ValueError("manual_override_expired")


def _validate_artifact(artifact: ClassifiedArtifact) -> None:
    _clean_identifier("artifact_id", artifact.artifact_id)
    if not isinstance(artifact.artifact_class, RedactionArtifactClass):
        raise ValueError("artifact_class_required")
    if not isinstance(artifact.classification, DataClassification):
        raise ValueError("data_classification_required")
    if not isinstance(artifact.redaction_status, RedactionStatus):
        raise ValueError("redaction_status_required")
    if artifact.content is None:
        raise ValueError("artifact_content_required")
    if artifact.evidence_attestation_hash is not None:
        _require_non_empty("evidence_attestation_hash", artifact.evidence_attestation_hash)


def _finding_payload(finding: ArtifactQualityFinding) -> dict[str, object]:
    return {
        "artifact_id": finding.artifact_id,
        "risk": finding.risk.value,
        "category": finding.category.value if finding.category else None,
        "reason": finding.reason,
        "overridable": finding.overridable,
        "finding_hash": finding.finding_hash,
    }


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")


def _clean_identifier(field_name: str, value: str) -> str:
    _require_non_empty(field_name, value)
    return value.strip()
