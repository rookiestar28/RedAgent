"""Report publication and vulnerability-management workflow contracts.

This module never publishes externally and never calls issue tracker APIs. It
builds deterministic, sanitized workflow outputs that a later UI/API layer can
present or hand to a certified connector.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import finding_review, issue_connectors, reporting
from redagent_platform.domain import FindingStatus
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.findings import FindingRecord, duplicate_correlation_key
from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output


class PublicationApprovalStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    BLOCKED = "blocked"
    CLOSED = "closed"


class PublicationExportState(str, Enum):
    NOT_REQUESTED = "not_requested"
    PLANNED = "planned"
    BLOCKED = "blocked"
    COMPLETE = "complete"


class ReportVariantKind(str, Enum):
    INTERNAL = "internal"
    CUSTOMER = "customer"


@dataclass(frozen=True, kw_only=True)
class PublicationReviewState:
    evidence_reviewed: bool
    claim_reviewed: bool
    redaction_reviewed: bool
    internal_variant_ready: bool
    customer_variant_ready: bool
    approval_status: PublicationApprovalStatus
    approved_by_user_id: str | None
    approved_at: datetime | None
    closeout_ready: bool


@dataclass(frozen=True, kw_only=True)
class ReportPublicationProfile:
    profile_id: str
    allow_customer_variant: bool
    allow_issue_export: bool
    require_approved_redaction: bool
    require_confirmed_findings: bool


@dataclass(frozen=True, kw_only=True)
class ReportPublicationRequest:
    publication_id: str
    report_input: reporting.ReportInput
    review_state: PublicationReviewState
    profile: ReportPublicationProfile
    requested_at: datetime
    actor_user_id: str
    issue_connection: issue_connectors.IssueTrackerConnection | None = None
    existing_issue_exports: tuple[issue_connectors.ExistingIssueExport, ...] = ()
    canary_markers: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class RenderedReportVariant:
    kind: ReportVariantKind
    markdown: str
    content_hash: str
    external_share_ready: bool


@dataclass(frozen=True, kw_only=True)
class VulnerabilityManagementExportPlan:
    finding_id: str
    deduplication_key: str
    issue_key: str
    action: issue_connectors.IssueExportAction
    remediation_owner_user_id: str | None
    retest_state: str
    payload_hash: str
    audit_event_hash: str


@dataclass(frozen=True, kw_only=True)
class PublicationWorkflowPackage:
    publication_id: str
    report_id: str
    report_hash: str
    evidence_lock_hash: str
    review_state: PublicationReviewState
    finding_metrics: finding_review.FindingWorkflowMetrics
    variants: tuple[RenderedReportVariant, ...]
    issue_exports: tuple[VulnerabilityManagementExportPlan, ...]
    export_state: PublicationExportState
    closeout_ready: bool


@dataclass(frozen=True, kw_only=True)
class PublicationWorkflowResult:
    package: PublicationWorkflowPackage
    report_package: reporting.ReportPackage
    audit_chain: EvidenceChain


def build_publication_workflow(
    request: ReportPublicationRequest,
    audit_chain: EvidenceChain,
) -> PublicationWorkflowResult:
    _validate_request(request)
    _validate_review_state(request.review_state, request.profile)
    _validate_findings(request.report_input.findings, request.profile)
    report_result = reporting.generate_report_package(request.report_input, audit_chain)
    variants = render_publication_variants(
        report_result.package,
        allow_customer_variant=request.profile.allow_customer_variant,
        require_approved_redaction=request.profile.require_approved_redaction,
    )
    _assert_no_canary_markers(variants, request.canary_markers)
    export_plans, export_chain, export_state = _plan_issue_exports(
        request=request,
        audit_chain=report_result.audit_chain,
    )
    final_chain = export_chain.append_audit_event(
        event_id=f"{request.publication_id}:publication",
        organization_id=request.report_input.organization_id,
        actor_user_id=request.actor_user_id,
        action=AuditAction.EXPORT,
        subject_type="report_publication",
        subject_id=request.publication_id,
        occurred_at=request.requested_at,
        details={
            "report_id": report_result.package.report_id,
            "report_hash": report_result.package.report_hash,
            "variant_count": len(variants),
            "issue_export_count": len(export_plans),
            "export_state": export_state.value,
            "approval_status": request.review_state.approval_status.value,
        },
    )
    package = PublicationWorkflowPackage(
        publication_id=request.publication_id.strip(),
        report_id=report_result.package.report_id,
        report_hash=report_result.package.report_hash,
        evidence_lock_hash=report_result.package.evidence_lock_hash,
        review_state=request.review_state,
        finding_metrics=finding_review.summarize_finding_metrics(request.report_input.findings),
        variants=variants,
        issue_exports=export_plans,
        export_state=export_state,
        closeout_ready=request.review_state.closeout_ready and export_state in {
            PublicationExportState.NOT_REQUESTED,
            PublicationExportState.COMPLETE,
        },
    )
    return PublicationWorkflowResult(package=package, report_package=report_result.package, audit_chain=final_chain)


def render_publication_variants(
    package: reporting.ReportPackage,
    *,
    allow_customer_variant: bool,
    require_approved_redaction: bool,
) -> tuple[RenderedReportVariant, ...]:
    reporting.validate_report_package(package)
    if require_approved_redaction and package.redaction_review.status is not reporting.RedactionReviewStatus.APPROVED:
        raise ValueError("redaction_review_required")
    internal = _variant(
        ReportVariantKind.INTERNAL,
        reporting.render_report_markdown(package, external_share=False),
        external_share_ready=False,
    )
    variants = [internal]
    if allow_customer_variant:
        customer = _variant(
            ReportVariantKind.CUSTOMER,
            reporting.render_report_markdown(package, external_share=True),
            external_share_ready=True,
        )
        variants.append(customer)
    return tuple(variants)


def workflow_state_for_ui(package: PublicationWorkflowPackage) -> dict[str, object]:
    """Return a compact state projection for a future report-review UI."""
    return {
        "publication_id": package.publication_id,
        "report_id": package.report_id,
        "review": {
            "evidence_reviewed": package.review_state.evidence_reviewed,
            "claim_reviewed": package.review_state.claim_reviewed,
            "redaction_reviewed": package.review_state.redaction_reviewed,
            "approval_status": package.review_state.approval_status.value,
        },
        "variants": tuple(variant.kind.value for variant in package.variants),
        "export_state": package.export_state.value,
        "closeout_ready": package.closeout_ready,
        "issue_export_count": len(package.issue_exports),
    }


def _validate_request(request: ReportPublicationRequest) -> None:
    for field_name, value in (
        ("publication_id", request.publication_id),
        ("actor_user_id", request.actor_user_id),
        ("profile_id", request.profile.profile_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    if request.issue_connection is not None and not request.profile.allow_issue_export:
        raise ValueError("issue_export_not_allowed_by_profile")
    if request.profile.require_approved_redaction and request.report_input.redaction_review.status is not reporting.RedactionReviewStatus.APPROVED:
        raise ValueError("redaction_review_required")


def _validate_review_state(state: PublicationReviewState, profile: ReportPublicationProfile) -> None:
    required = {
        "evidence_review_required": state.evidence_reviewed,
        "claim_review_required": state.claim_reviewed,
        "redaction_review_required": state.redaction_reviewed,
        "internal_variant_required": state.internal_variant_ready,
    }
    if profile.allow_customer_variant:
        required["customer_variant_required"] = state.customer_variant_ready
    for reason, passed in required.items():
        if not passed:
            raise ValueError(reason)
    if state.approval_status is not PublicationApprovalStatus.APPROVED:
        raise ValueError("publication_approval_required")
    _require_non_empty("approved_by_user_id", state.approved_by_user_id or "")
    if state.approved_at is None:
        raise ValueError("approval_timestamp_required")
    _require_timezone(state.approved_at)


def _validate_findings(findings: tuple[FindingRecord, ...], profile: ReportPublicationProfile) -> None:
    if profile.require_confirmed_findings:
        for finding in findings:
            if finding.status not in {
                FindingStatus.CONFIRMED,
                FindingStatus.RISK_ACCEPTED,
                FindingStatus.FIXED,
                FindingStatus.RETEST_PASSED,
                FindingStatus.RETEST_FAILED,
            }:
                raise ValueError("finding_not_publication_ready")


def _plan_issue_exports(
    *,
    request: ReportPublicationRequest,
    audit_chain: EvidenceChain,
) -> tuple[tuple[VulnerabilityManagementExportPlan, ...], EvidenceChain, PublicationExportState]:
    if request.issue_connection is None:
        return (), audit_chain, PublicationExportState.NOT_REQUESTED
    connector = issue_connectors.GenericIssueTrackerConnector()
    plans: list[VulnerabilityManagementExportPlan] = []
    chain = audit_chain
    existing_exports = request.existing_issue_exports
    for index, finding in enumerate(request.report_input.findings, start=1):
        if finding.status is not FindingStatus.CONFIRMED:
            continue
        export_request = issue_connectors.IssueExportRequest(
            export_id=f"{request.publication_id}:issue-export:{index}",
            organization_id=request.report_input.organization_id,
            actor_user_id=request.actor_user_id,
            connection=request.issue_connection,
            finding=finding,
            requested_at=request.requested_at,
            audit_chain=chain,
            existing_exports=existing_exports,
            canary_markers=request.canary_markers,
        )
        result = connector.export_finding(export_request)
        chain = result.audit_chain
        existing_exports = existing_exports + (
            issue_connectors.ExistingIssueExport(
                external_key=result.payload.external_key,
                issue_key=result.issue_key,
                finding_id=finding.id,
                connector_id=request.issue_connection.connector_id,
            ),
        )
        plans.append(
            VulnerabilityManagementExportPlan(
                finding_id=finding.id,
                deduplication_key=duplicate_correlation_key(finding),
                issue_key=result.issue_key,
                action=result.action,
                remediation_owner_user_id=finding.owner_user_id,
                retest_state=finding.status.value,
                payload_hash=_payload_hash(result.payload),
                audit_event_hash=chain.audit_events[-1].event_hash,
            )
        )
    return tuple(plans), chain, PublicationExportState.COMPLETE


def _variant(kind: ReportVariantKind, markdown: str, *, external_share_ready: bool) -> RenderedReportVariant:
    decorated = f"Variant: {kind.value}\n\n{markdown}"
    _ensure_secret_free_text(decorated)
    return RenderedReportVariant(
        kind=kind,
        markdown=decorated,
        content_hash=_sha256_text(decorated),
        external_share_ready=external_share_ready,
    )


def _assert_no_canary_markers(variants: tuple[RenderedReportVariant, ...], canary_markers: tuple[str, ...]) -> None:
    for variant in variants:
        for marker in canary_markers:
            if marker and marker in variant.markdown:
                raise ValueError("canary_marker_leaked")


def _payload_hash(payload: issue_connectors.IssueExportPayload) -> str:
    encoded = json.dumps(
        {
            "external_key": payload.external_key,
            "summary": payload.summary,
            "severity": payload.severity,
            "owner_user_id": payload.owner_user_id,
            "evidence_links": tuple(
                {
                    "evidence_id": evidence.evidence_id,
                    "integrity_hash": evidence.integrity_hash,
                    "redaction_status": evidence.redaction_status,
                }
                for evidence in payload.evidence_links
            ),
            "remediation": payload.remediation,
            "taxonomy": {
                "source": payload.taxonomy.source,
                "source_rule_id": payload.taxonomy.source_rule_id,
                "cve_ids": payload.taxonomy.cve_ids,
                "cwe_ids": payload.taxonomy.cwe_ids,
                "correlation_key": payload.taxonomy.correlation_key,
            },
            "labels": payload.labels,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return _sha256_text(encoded)


def _ensure_secret_free_text(value: str) -> None:
    try:
        assert_no_sensitive_output(value, RedactionArtifactClass.REPORT)
    except ValueError as exc:
        raise ValueError("secret_like_text_forbidden") from exc


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
