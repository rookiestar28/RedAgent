"""Report quality gate for claim evidence, risk support, and variants."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import reporting
from redagent_platform.domain import FindingStatus
from redagent_platform.evidence_chain import AuditAction, EvidenceChain, RedactionStatus
from redagent_platform.findings import (
    AssetCriticality,
    BusinessImpact,
    ExploitLikelihood,
    FindingRecord,
    Severity,
    priority_score,
    validate_finding,
)
from redagent_platform.report_publication import ReportVariantKind


class ReportQualityDecision(str, Enum):
    APPROVED = "approved"
    BLOCKED = "blocked"


@dataclass(frozen=True, kw_only=True)
class ReportQualityProfile:
    profile_id: str
    allow_customer_variant: bool
    require_approved_redaction: bool
    require_claim_evidence_or_justification: bool
    require_risk_source_support: bool
    require_retest_closeout: bool


@dataclass(frozen=True, kw_only=True)
class ClaimReviewJustification:
    claim_hash: str
    reviewer_user_id: str
    rationale: str
    reviewed_at: datetime


@dataclass(frozen=True, kw_only=True)
class ReportQualityReviewState:
    evidence_reviewed: bool
    redaction_reviewed: bool
    claim_reviewed: bool
    risk_reviewed: bool
    closeout_ready: bool
    approved_by_user_id: str | None
    approved_at: datetime | None


@dataclass(frozen=True, kw_only=True)
class ReportQualityGateRequest:
    gate_id: str
    package: reporting.ReportPackage
    findings: tuple[FindingRecord, ...]
    profile: ReportQualityProfile
    review_state: ReportQualityReviewState
    requested_at: datetime
    actor_user_id: str
    justifications: tuple[ClaimReviewJustification, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ReportQualityFindingSummary:
    finding_id: str
    status: str
    severity: str
    exploit_likelihood: str
    cvss_score: float | None
    epss_probability: float | None
    kev_listed: bool
    priority_score: int


@dataclass(frozen=True, kw_only=True)
class ReportQualityVariant:
    kind: ReportVariantKind
    markdown: str
    content_hash: str
    evidence_trace_ids: tuple[str, ...]
    minimized_fields: tuple[str, ...]
    external_share_ready: bool


@dataclass(frozen=True, kw_only=True)
class ReportQualityGateResult:
    gate_id: str
    decision: ReportQualityDecision
    variants: tuple[ReportQualityVariant, ...]
    finding_summaries: tuple[ReportQualityFindingSummary, ...]
    closeout_ready: bool
    result_hash: str
    audit_chain: EvidenceChain


RISK_CLAIM_TERMS = (
    "cvss",
    "epss",
    "kev",
    "exploit",
    "impact",
    "priority",
    "rated",
    "risk",
    "remediation",
)


def evaluate_report_quality_gate(
    request: ReportQualityGateRequest,
    audit_chain: EvidenceChain,
) -> ReportQualityGateResult:
    _validate_request(request)
    reporting.validate_report_package(request.package)
    justifications = _justifications_by_claim_hash(request.justifications)
    evidence_index = _findings_by_evidence_id(request.findings)

    if request.profile.require_approved_redaction:
        _validate_redaction_ready(request)
    _validate_review_state(request.review_state, request.profile)
    if request.profile.require_claim_evidence_or_justification:
        _validate_claim_support(request.package, justifications)
    if request.profile.require_risk_source_support:
        _validate_finding_risk_consistency(request.findings)
        _validate_risk_claim_support(request.package, justifications, evidence_index)
    closeout_ready = _closeout_ready(request.findings, request.review_state)
    if request.profile.require_retest_closeout and not closeout_ready:
        raise ValueError("retest_closeout_not_ready")

    variants = _render_quality_variants(request.package, request.profile)
    summaries = tuple(_finding_summary(finding) for finding in sorted(request.findings, key=lambda item: item.id))
    result_hash = _result_hash(
        request=request,
        variants=variants,
        summaries=summaries,
        closeout_ready=closeout_ready,
    )
    next_chain = audit_chain.append_audit_event(
        event_id=f"{request.gate_id}:report-quality",
        organization_id=request.package.organization_id,
        actor_user_id=request.actor_user_id,
        action=AuditAction.REPORT_GENERATION,
        subject_type="report_quality_gate",
        subject_id=request.gate_id,
        occurred_at=request.requested_at,
        details={
            "decision": ReportQualityDecision.APPROVED.value,
            "report_id": request.package.report_id,
            "report_hash": request.package.report_hash,
            "evidence_lock_hash": request.package.evidence_lock_hash,
            "variant_count": len(variants),
            "closeout_ready": closeout_ready,
            "result_hash": result_hash,
        },
    )
    return ReportQualityGateResult(
        gate_id=request.gate_id.strip(),
        decision=ReportQualityDecision.APPROVED,
        variants=variants,
        finding_summaries=summaries,
        closeout_ready=closeout_ready,
        result_hash=result_hash,
        audit_chain=next_chain,
    )


def claim_review_hash(claim: reporting.ReportClaim) -> str:
    payload = {
        "text": claim.text.strip(),
        "evidence_ids": tuple(sorted(claim.evidence_ids)),
        "assumption": claim.assumption,
    }
    return _canonical_sha256(payload)


def _validate_request(request: ReportQualityGateRequest) -> None:
    for field_name, value in (
        ("gate_id", request.gate_id),
        ("actor_user_id", request.actor_user_id),
        ("profile_id", request.profile.profile_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    for finding in request.findings:
        validate_finding(finding)
    for justification in request.justifications:
        _validate_justification(justification)


def _validate_justification(justification: ClaimReviewJustification) -> None:
    for field_name, value in (
        ("claim_hash", justification.claim_hash),
        ("reviewer_user_id", justification.reviewer_user_id),
        ("rationale", justification.rationale),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(justification.reviewed_at)


def _validate_review_state(state: ReportQualityReviewState, profile: ReportQualityProfile) -> None:
    required = {
        "evidence_review_required": state.evidence_reviewed,
        "claim_review_required": state.claim_reviewed,
    }
    if profile.require_approved_redaction:
        required["redaction_review_required"] = state.redaction_reviewed
    if profile.require_risk_source_support:
        required["risk_review_required"] = state.risk_reviewed
    for reason, passed in required.items():
        if not passed:
            raise ValueError(reason)
    _require_non_empty("approved_by_user_id", state.approved_by_user_id or "")
    if state.approved_at is None:
        raise ValueError("approval_timestamp_required")
    _require_timezone(state.approved_at)


def _validate_redaction_ready(request: ReportQualityGateRequest) -> None:
    if request.package.redaction_review.status is not reporting.RedactionReviewStatus.APPROVED:
        raise ValueError("redaction_review_required")
    if not request.package.redaction_review.reviewer_user_id or request.package.redaction_review.reviewed_at is None:
        raise ValueError("redaction_review_metadata_required")
    for finding in request.findings:
        for evidence in finding.evidence_links:
            if evidence.redaction_status is RedactionStatus.BLOCKED:
                raise ValueError("redaction_blocked_evidence")
            if evidence.contains_sensitive_payload and evidence.redaction_status is not RedactionStatus.REDACTED:
                raise ValueError("sensitive_evidence_redaction_required")


def _validate_claim_support(
    package: reporting.ReportPackage,
    justifications: dict[str, ClaimReviewJustification],
) -> None:
    for section in package.sections:
        for claim in section.claims:
            if claim.evidence_ids:
                continue
            if claim_review_hash(claim) not in justifications:
                raise ValueError("claim_requires_evidence_or_justification")


def _validate_risk_claim_support(
    package: reporting.ReportPackage,
    justifications: dict[str, ClaimReviewJustification],
    evidence_index: dict[str, tuple[FindingRecord, ...]],
) -> None:
    for section in package.sections:
        for claim in section.claims:
            if not _is_risk_claim(claim.text):
                continue
            linked_findings = _linked_findings(claim, evidence_index)
            if not linked_findings:
                if claim_review_hash(claim) not in justifications:
                    raise ValueError("risk_claim_requires_source_or_justification")
                continue
            for finding in linked_findings:
                if not _finding_supports_risk_claim(finding) and claim_review_hash(claim) not in justifications:
                    raise ValueError("risk_claim_requires_source_or_justification")


def _validate_finding_risk_consistency(findings: tuple[FindingRecord, ...]) -> None:
    for finding in findings:
        intelligence = finding.risk.vulnerability_intelligence
        if intelligence.kev_listed and not intelligence.cve_ids:
            raise ValueError("kev_requires_cve")
        if intelligence.cvss_score is not None:
            _validate_cvss_severity_consistency(finding.severity, intelligence.cvss_score)
        if intelligence.epss_probability is not None and intelligence.epss_probability >= 0.70:
            if finding.risk.exploit_likelihood in {ExploitLikelihood.LOW, ExploitLikelihood.UNKNOWN}:
                raise ValueError("epss_exploitability_inconsistent")
        if intelligence.kev_listed and finding.risk.exploit_likelihood is ExploitLikelihood.UNKNOWN:
            raise ValueError("kev_exploitability_inconsistent")


def _validate_cvss_severity_consistency(severity: Severity, cvss_score: float) -> None:
    if cvss_score >= 9.0 and severity not in {Severity.CRITICAL, Severity.HIGH}:
        raise ValueError("cvss_severity_inconsistent")
    if cvss_score >= 7.0 and severity in {Severity.LOW, Severity.INFO}:
        raise ValueError("cvss_severity_inconsistent")
    if cvss_score < 4.0 and severity in {Severity.HIGH, Severity.CRITICAL}:
        raise ValueError("cvss_severity_inconsistent")


def _render_quality_variants(
    package: reporting.ReportPackage,
    profile: ReportQualityProfile,
) -> tuple[ReportQualityVariant, ...]:
    evidence_trace_ids = _package_evidence_trace_ids(package)
    internal_markdown = reporting.render_report_markdown(package, external_share=False)
    variants = [
        ReportQualityVariant(
            kind=ReportVariantKind.INTERNAL,
            markdown=internal_markdown,
            content_hash=_sha256_text(internal_markdown),
            evidence_trace_ids=evidence_trace_ids,
            minimized_fields=(),
            external_share_ready=False,
        )
    ]
    if profile.allow_customer_variant:
        customer_markdown = reporting.render_report_markdown(package, external_share=True)
        variants.append(
            ReportQualityVariant(
                kind=ReportVariantKind.CUSTOMER,
                markdown=customer_markdown,
                content_hash=_sha256_text(customer_markdown),
                evidence_trace_ids=evidence_trace_ids,
                minimized_fields=("generated_by_user_id", "reviewer_user_id", "internal_review_notes"),
                external_share_ready=True,
            )
        )
    return tuple(variants)


def _closeout_ready(findings: tuple[FindingRecord, ...], review_state: ReportQualityReviewState) -> bool:
    open_retest = {
        FindingStatus.RETEST_REQUESTED,
        FindingStatus.RETEST_FAILED,
        FindingStatus.RETEST_REQUIRED,
    }
    return review_state.closeout_ready and all(finding.status not in open_retest for finding in findings)


def _finding_summary(finding: FindingRecord) -> ReportQualityFindingSummary:
    intelligence = finding.risk.vulnerability_intelligence
    return ReportQualityFindingSummary(
        finding_id=finding.id,
        status=finding.status.value,
        severity=finding.severity.value,
        exploit_likelihood=finding.risk.exploit_likelihood.value,
        cvss_score=intelligence.cvss_score,
        epss_probability=intelligence.epss_probability,
        kev_listed=intelligence.kev_listed,
        priority_score=priority_score(finding.risk),
    )


def _result_hash(
    *,
    request: ReportQualityGateRequest,
    variants: tuple[ReportQualityVariant, ...],
    summaries: tuple[ReportQualityFindingSummary, ...],
    closeout_ready: bool,
) -> str:
    payload = {
        "gate_id": request.gate_id.strip(),
        "profile_id": request.profile.profile_id.strip(),
        "report_hash": request.package.report_hash,
        "evidence_lock_hash": request.package.evidence_lock_hash,
        "closeout_ready": closeout_ready,
        "variants": tuple(
            {
                "kind": variant.kind.value,
                "content_hash": variant.content_hash,
                "evidence_trace_ids": variant.evidence_trace_ids,
                "minimized_fields": variant.minimized_fields,
                "external_share_ready": variant.external_share_ready,
            }
            for variant in variants
        ),
        "finding_summaries": tuple(summary.__dict__ for summary in summaries),
    }
    return _canonical_sha256(payload)


def _justifications_by_claim_hash(
    justifications: tuple[ClaimReviewJustification, ...],
) -> dict[str, ClaimReviewJustification]:
    indexed: dict[str, ClaimReviewJustification] = {}
    for justification in justifications:
        if justification.claim_hash in indexed:
            raise ValueError("duplicate_claim_justification")
        indexed[justification.claim_hash] = justification
    return indexed


def _findings_by_evidence_id(findings: tuple[FindingRecord, ...]) -> dict[str, tuple[FindingRecord, ...]]:
    indexed: dict[str, list[FindingRecord]] = {}
    for finding in findings:
        for evidence in finding.evidence_links:
            indexed.setdefault(evidence.evidence_id, []).append(finding)
    return {evidence_id: tuple(items) for evidence_id, items in indexed.items()}


def _linked_findings(
    claim: reporting.ReportClaim,
    evidence_index: dict[str, tuple[FindingRecord, ...]],
) -> tuple[FindingRecord, ...]:
    findings: dict[str, FindingRecord] = {}
    for evidence_id in claim.evidence_ids:
        for finding in evidence_index.get(evidence_id, ()):
            findings[finding.id] = finding
    return tuple(findings[finding_id] for finding_id in sorted(findings))


def _finding_supports_risk_claim(finding: FindingRecord) -> bool:
    intelligence = finding.risk.vulnerability_intelligence
    has_vulnerability_score = (
        intelligence.cvss_score is not None
        or intelligence.epss_probability is not None
        or intelligence.kev_listed
    )
    has_reviewed_risk_factors = (
        finding.risk.exploit_likelihood is not ExploitLikelihood.UNKNOWN
        and finding.risk.business_impact is not BusinessImpact.UNKNOWN
        and finding.risk.asset_criticality is not AssetCriticality.UNKNOWN
    )
    return has_vulnerability_score and has_reviewed_risk_factors


def _is_risk_claim(value: str) -> bool:
    normalized = value.strip().lower()
    return any(term in normalized for term in RISK_CLAIM_TERMS)


def _package_evidence_trace_ids(package: reporting.ReportPackage) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                evidence_id
                for section in package.sections
                for claim in section.claims
                for evidence_id in claim.evidence_ids
            }
        )
    )


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
