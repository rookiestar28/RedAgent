"""Deterministic report generation from reviewed findings and locked evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.evidence_chain import AuditAction, EvidenceChain, EvidenceRecord, verify_evidence_record
from redagent_platform.findings import FindingRecord, export_sanitized_finding
from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output


class ReportAudience(str, Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"


class RedactionReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    BLOCKED = "blocked"


class ReportSectionKind(str, Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_FINDINGS = "technical_findings"
    ATTACK_COVERAGE = "attack_coverage"
    OWASP_COVERAGE = "owasp_coverage"
    RISK_TRENDS = "risk_trends"
    SCOPE = "scope"
    METHODOLOGY = "methodology"
    LIMITATIONS = "limitations"
    APPENDIX = "appendix"


REQUIRED_REPORT_SECTIONS: tuple[ReportSectionKind, ...] = (
    ReportSectionKind.EXECUTIVE_SUMMARY,
    ReportSectionKind.TECHNICAL_FINDINGS,
    ReportSectionKind.ATTACK_COVERAGE,
    ReportSectionKind.OWASP_COVERAGE,
    ReportSectionKind.RISK_TRENDS,
    ReportSectionKind.SCOPE,
    ReportSectionKind.METHODOLOGY,
    ReportSectionKind.LIMITATIONS,
    ReportSectionKind.APPENDIX,
)


@dataclass(frozen=True, kw_only=True)
class ReportScope:
    engagement_id: str
    target_summary: str
    testing_window: str
    allowed_modes: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class RedactionReview:
    review_id: str
    status: RedactionReviewStatus
    reviewer_user_id: str | None
    reviewed_at: datetime | None
    notes: str


@dataclass(frozen=True, kw_only=True)
class ReportClaim:
    text: str
    evidence_ids: tuple[str, ...] = ()
    assumption: str | None = None


@dataclass(frozen=True, kw_only=True)
class ReportSection:
    kind: ReportSectionKind
    title: str
    claims: tuple[ReportClaim, ...]


@dataclass(frozen=True, kw_only=True)
class ReportInput:
    report_id: str
    organization_id: str
    title: str
    audience: ReportAudience
    generated_by_user_id: str
    generated_at: datetime
    scope: ReportScope
    findings: tuple[FindingRecord, ...]
    evidence_records: tuple[EvidenceRecord, ...]
    methodology: tuple[str, ...]
    limitations: tuple[str, ...]
    redaction_review: RedactionReview
    canary_markers: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ReportPackage:
    report_id: str
    organization_id: str
    title: str
    audience: ReportAudience
    generated_at: datetime
    generated_by_user_id: str
    scope: ReportScope
    sections: tuple[ReportSection, ...]
    redaction_review: RedactionReview
    evidence_lock_hash: str
    report_hash: str


@dataclass(frozen=True, kw_only=True)
class ReportGenerationResult:
    package: ReportPackage
    audit_chain: EvidenceChain


def generate_report_package(report_input: ReportInput, audit_chain: EvidenceChain) -> ReportGenerationResult:
    _validate_report_input(report_input)
    sections = _build_sections(report_input)
    package_without_hash = {
        "report_id": report_input.report_id.strip(),
        "organization_id": report_input.organization_id.strip(),
        "title": report_input.title.strip(),
        "audience": report_input.audience.value,
        "generated_at": report_input.generated_at.isoformat(),
        "generated_by_user_id": report_input.generated_by_user_id.strip(),
        "scope": _scope_to_dict(report_input.scope),
        "sections": tuple(_section_to_dict(section) for section in sections),
        "redaction_review": _review_to_dict(report_input.redaction_review),
        "evidence_lock_hash": _evidence_lock_hash(report_input.evidence_records),
    }
    report_hash = _canonical_sha256(package_without_hash)
    package = ReportPackage(
        report_id=report_input.report_id.strip(),
        organization_id=report_input.organization_id.strip(),
        title=report_input.title.strip(),
        audience=report_input.audience,
        generated_at=report_input.generated_at,
        generated_by_user_id=report_input.generated_by_user_id.strip(),
        scope=report_input.scope,
        sections=sections,
        redaction_review=report_input.redaction_review,
        evidence_lock_hash=str(package_without_hash["evidence_lock_hash"]),
        report_hash=report_hash,
    )
    validate_report_package(package)
    rendered = render_report_markdown(package, external_share=False)
    _assert_no_canary_markers(rendered, report_input.canary_markers)
    next_chain = audit_chain.append_audit_event(
        event_id=f"{package.report_id}:report-generation",
        organization_id=package.organization_id,
        actor_user_id=package.generated_by_user_id,
        action=AuditAction.REPORT_GENERATION,
        subject_type="report",
        subject_id=package.report_id,
        occurred_at=package.generated_at,
        details={
            "audience": package.audience.value,
            "section_count": len(package.sections),
            "evidence_lock_hash": package.evidence_lock_hash,
            "report_hash": package.report_hash,
            "redaction_review_status": package.redaction_review.status.value,
        },
    )
    return ReportGenerationResult(package=package, audit_chain=next_chain)


def validate_report_package(package: ReportPackage) -> None:
    present = tuple(section.kind for section in package.sections)
    if present != REQUIRED_REPORT_SECTIONS:
        raise ValueError("missing_required_report_sections")
    for section in package.sections:
        if not section.claims:
            raise ValueError(f"missing_claims:{section.kind.value}")
        for claim in section.claims:
            _validate_claim(claim)
    if package.generated_at.tzinfo is None or package.generated_at.utcoffset() is None:
        raise ValueError("timezone_required")
    _ensure_secret_free_text(render_report_markdown(package, external_share=False))


def render_report_markdown(package: ReportPackage, *, external_share: bool) -> str:
    if external_share and package.redaction_review.status is not RedactionReviewStatus.APPROVED:
        raise ValueError("redaction_review_required")
    lines = [
        f"# {package.title}",
        "",
        f"- Report ID: {package.report_id}",
        f"- Audience: {package.audience.value}",
        f"- Evidence lock: {package.evidence_lock_hash}",
        f"- Report hash: {package.report_hash}",
        f"- Redaction review: {package.redaction_review.status.value}",
        "",
    ]
    for section in package.sections:
        lines.append(f"## {section.title}")
        for claim in section.claims:
            suffix = _claim_suffix(claim)
            lines.append(f"- {claim.text} {suffix}".rstrip())
        lines.append("")
    rendered = "\n".join(lines).strip() + "\n"
    _ensure_secret_free_text(rendered)
    return rendered


def _build_sections(report_input: ReportInput) -> tuple[ReportSection, ...]:
    exported_findings = tuple(
        sorted((export_sanitized_finding(finding) for finding in report_input.findings), key=lambda item: str(item["id"]))
    )
    all_finding_evidence = _finding_evidence_ids(report_input.findings)
    technical_claims = tuple(
        ReportClaim(
            text=(
                f"{finding['title']} is rated {finding['severity']} with remediation: "
                f"{finding['remediation']}"
            ),
            evidence_ids=tuple(str(evidence["evidence_id"]) for evidence in finding["evidence"]),  # type: ignore[index]
        )
        for finding in exported_findings
    ) or (
        ReportClaim(
            text="No confirmed findings are present in this report package.",
            assumption="Current reviewed finding set is empty.",
        ),
    )
    owasp_claims = _owasp_claims(exported_findings)
    return (
        ReportSection(
            kind=ReportSectionKind.EXECUTIVE_SUMMARY,
            title="Executive Summary",
            claims=(
                ReportClaim(
                    text=f"Report covers {len(exported_findings)} confirmed finding(s) for {report_input.scope.target_summary}.",
                    evidence_ids=all_finding_evidence,
                )
                if all_finding_evidence
                else ReportClaim(
                    text=f"Report covers {len(exported_findings)} confirmed finding(s) for {report_input.scope.target_summary}.",
                    assumption="No evidence-linked confirmed findings are present.",
                ),
            ),
        ),
        ReportSection(kind=ReportSectionKind.TECHNICAL_FINDINGS, title="Technical Findings", claims=technical_claims),
        ReportSection(
            kind=ReportSectionKind.ATTACK_COVERAGE,
            title="ATT&CK Coverage",
            claims=(
                ReportClaim(
                    text="ATT&CK coverage is limited to mapped evidence available in this report package.",
                    assumption="No ATT&CK campaign planner output is available until R022 is accepted.",
                ),
            ),
        ),
        ReportSection(kind=ReportSectionKind.OWASP_COVERAGE, title="OWASP Coverage", claims=owasp_claims),
        ReportSection(
            kind=ReportSectionKind.RISK_TRENDS,
            title="Risk Trends",
            claims=(
                ReportClaim(
                    text="Risk trend is generated from the current locked evidence snapshot.",
                    assumption="Historical trend storage is not implemented in R028.",
                ),
            ),
        ),
        ReportSection(
            kind=ReportSectionKind.SCOPE,
            title="Scope",
            claims=(
                ReportClaim(
                    text=(
                        f"Scope target summary: {report_input.scope.target_summary}; "
                        f"window: {report_input.scope.testing_window}; "
                        f"allowed modes: {', '.join(report_input.scope.allowed_modes)}."
                    ),
                    assumption="Scope metadata is supplied by the engagement record.",
                ),
            ),
        ),
        ReportSection(
            kind=ReportSectionKind.METHODOLOGY,
            title="Methodology",
            claims=tuple(
                ReportClaim(text=entry, assumption="Methodology entry supplied by approved test plan.")
                for entry in report_input.methodology
            ),
        ),
        ReportSection(
            kind=ReportSectionKind.LIMITATIONS,
            title="Limitations",
            claims=tuple(
                ReportClaim(text=entry, assumption="Limitation entry supplied by report author.")
                for entry in report_input.limitations
            ),
        ),
        ReportSection(
            kind=ReportSectionKind.APPENDIX,
            title="Appendix",
            claims=(
                ReportClaim(
                    text=f"Evidence appendix contains {len(report_input.evidence_records)} locked evidence record(s).",
                    evidence_ids=tuple(record.id for record in sorted(report_input.evidence_records, key=lambda item: item.id)),
                ),
            ),
        ),
    )


def _owasp_claims(exported_findings: tuple[dict[str, object], ...]) -> tuple[ReportClaim, ...]:
    claims: list[ReportClaim] = []
    for finding in exported_findings:
        intelligence = finding["vulnerability_intelligence"]  # type: ignore[index]
        cwe_ids = tuple(str(cwe_id) for cwe_id in intelligence["cwe_ids"])  # type: ignore[index]
        if cwe_ids:
            claims.append(
                ReportClaim(
                    text=f"OWASP-relevant weakness references observed: {', '.join(cwe_ids)}.",
                    evidence_ids=tuple(str(evidence["evidence_id"]) for evidence in finding["evidence"]),  # type: ignore[index]
                )
            )
    if not claims:
        return (
            ReportClaim(
                text="No OWASP/CWE coverage mapping is available in the current finding set.",
                assumption="No CWE identifiers were present in sanitized findings.",
            ),
        )
    return tuple(claims)


def _validate_report_input(report_input: ReportInput) -> None:
    for field_name, value in (
        ("report_id", report_input.report_id),
        ("organization_id", report_input.organization_id),
        ("title", report_input.title),
        ("generated_by_user_id", report_input.generated_by_user_id),
        ("engagement_id", report_input.scope.engagement_id),
        ("target_summary", report_input.scope.target_summary),
        ("testing_window", report_input.scope.testing_window),
    ):
        _require_non_empty(field_name, value)
    if report_input.generated_at.tzinfo is None or report_input.generated_at.utcoffset() is None:
        raise ValueError("timezone_required")
    if not report_input.evidence_records:
        raise ValueError("missing_locked_evidence")
    if not report_input.methodology:
        raise ValueError("missing_methodology")
    if not report_input.limitations:
        raise ValueError("missing_limitations")
    for record in report_input.evidence_records:
        if not verify_evidence_record(record):
            raise ValueError("invalid_evidence_integrity")
    evidence_ids = {record.id for record in report_input.evidence_records}
    for evidence_id in _finding_evidence_ids(report_input.findings):
        if evidence_id not in evidence_ids:
            raise ValueError("finding_evidence_not_locked")


def _validate_claim(claim: ReportClaim) -> None:
    _require_non_empty("claim_text", claim.text)
    if not claim.evidence_ids and not claim.assumption:
        raise ValueError("claim_requires_evidence_or_assumption")
    if claim.assumption is not None:
        _require_non_empty("claim_assumption", claim.assumption)


def _finding_evidence_ids(findings: tuple[FindingRecord, ...]) -> tuple[str, ...]:
    return tuple(
        sorted({evidence.evidence_id for finding in findings for evidence in finding.evidence_links})
    )


def _claim_suffix(claim: ReportClaim) -> str:
    if claim.evidence_ids:
        return f"[evidence: {', '.join(sorted(claim.evidence_ids))}]"
    return f"[assumption: {claim.assumption}]"


def _evidence_lock_hash(evidence_records: tuple[EvidenceRecord, ...]) -> str:
    payload = {
        "evidence": tuple(
            {
                "id": record.id,
                "integrity_hash": record.integrity_hash,
                "metadata_hash": record.metadata_hash,
                "content_hash": record.content_hash,
            }
            for record in sorted(evidence_records, key=lambda item: item.id)
        )
    }
    return _canonical_sha256(payload)


def _section_to_dict(section: ReportSection) -> dict[str, object]:
    return {
        "kind": section.kind.value,
        "title": section.title,
        "claims": tuple(
            {
                "text": claim.text,
                "evidence_ids": tuple(sorted(claim.evidence_ids)),
                "assumption": claim.assumption,
            }
            for claim in section.claims
        ),
    }


def _scope_to_dict(scope: ReportScope) -> dict[str, object]:
    return {
        "engagement_id": scope.engagement_id,
        "target_summary": scope.target_summary,
        "testing_window": scope.testing_window,
        "allowed_modes": scope.allowed_modes,
    }


def _review_to_dict(review: RedactionReview) -> dict[str, object]:
    return {
        "review_id": review.review_id,
        "status": review.status.value,
        "reviewer_user_id": review.reviewer_user_id,
        "reviewed_at": review.reviewed_at.isoformat() if review.reviewed_at else None,
        "notes": review.notes,
    }


def _assert_no_canary_markers(value: str, canary_markers: tuple[str, ...]) -> None:
    for marker in canary_markers:
        if marker and marker in value:
            raise ValueError("canary_marker_leaked")


def _ensure_secret_free_text(value: str) -> None:
    try:
        assert_no_sensitive_output(value, RedactionArtifactClass.REPORT)
    except ValueError as exc:
        raise ValueError("secret_like_text_forbidden") from exc


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
