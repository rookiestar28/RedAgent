"""Trusted-repository supply-chain assessment planning contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.evidence_chain import RedactionStatus
from redagent_platform.findings import Severity


class SupplyChainCheckKind(str, Enum):
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY_INVENTORY = "dependency_inventory"
    SBOM_IMPORT = "sbom_import"
    SENSITIVE_VALUE_SCAN = "sensitive_value_scan"
    PROVENANCE_CHECK = "provenance_check"


class SupplyChainLocationType(str, Enum):
    SOURCE_FILE = "source_file"
    PIPELINE_OBJECT = "pipeline_object"


class SupplyChainControlCategory(str, Enum):
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY_RISK = "dependency_risk"
    SBOM_COVERAGE = "sbom_coverage"
    SENSITIVE_VALUE_EXPOSURE = "sensitive_value_exposure"
    BUILD_PROVENANCE = "build_provenance"
    ARTIFACT_INTEGRITY = "artifact_integrity"


@dataclass(frozen=True, kw_only=True)
class RepositoryAllowlistEntry:
    repository_id: str
    repository_path: str
    owner_user_id: str
    trusted: bool


@dataclass(frozen=True, kw_only=True)
class PipelineAllowlistEntry:
    pipeline_id: str
    repository_id: str
    owner_user_id: str


@dataclass(frozen=True, kw_only=True)
class SupplyChainScope:
    organization_id: str
    engagement_id: str
    approved_by_user_id: str
    repositories: tuple[RepositoryAllowlistEntry, ...]
    pipelines: tuple[PipelineAllowlistEntry, ...]
    external_verification_approved: bool = False


@dataclass(frozen=True, kw_only=True)
class SupplyChainAssessmentRequest:
    job_id: str
    organization_id: str
    engagement_id: str
    repository_id: str
    pipeline_id: str | None
    check_kinds: tuple[SupplyChainCheckKind, ...]
    requested_at: datetime
    external_verification_requested: bool = False


@dataclass(frozen=True, kw_only=True)
class SupplyChainDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class SupplyChainCheckPlan:
    job_id: str
    repository_id: str
    pipeline_id: str | None
    check_kinds: tuple[SupplyChainCheckKind, ...]
    local_only: bool


@dataclass(frozen=True, kw_only=True)
class RedactedSensitiveEvidence:
    evidence_id: str
    redaction_status: RedactionStatus
    redacted_locations: tuple[str, ...]
    raw_value_recorded: bool
    canary_markers: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class SupplyChainFindingMapping:
    finding_id: str
    location_type: SupplyChainLocationType
    location: str
    control_category: SupplyChainControlCategory
    severity: Severity
    remediation_guidance: str
    false_positive_workflow: str


def evaluate_supply_chain_assessment(
    *,
    scope: SupplyChainScope,
    request: SupplyChainAssessmentRequest,
) -> SupplyChainDecision:
    try:
        validate_supply_chain_scope(scope)
    except ValueError as exc:
        return SupplyChainDecision(allowed=False, reason=str(exc))
    _validate_request_shape(request)
    if request.organization_id != scope.organization_id:
        return SupplyChainDecision(allowed=False, reason="organization_mismatch")
    if request.engagement_id != scope.engagement_id:
        return SupplyChainDecision(allowed=False, reason="engagement_mismatch")
    repository = _repository_by_id(scope, request.repository_id)
    if repository is None:
        return SupplyChainDecision(allowed=False, reason="repository_not_allowlisted")
    if not repository.trusted:
        return SupplyChainDecision(allowed=False, reason="trusted_repository_required")
    if request.pipeline_id and _pipeline_by_id(scope, request.repository_id, request.pipeline_id) is None:
        return SupplyChainDecision(allowed=False, reason="pipeline_not_allowlisted")
    if request.external_verification_requested and not scope.external_verification_approved:
        return SupplyChainDecision(allowed=False, reason="external_verification_not_approved")
    return SupplyChainDecision(allowed=True, reason="supply_chain_local_checks_allowed")


def build_supply_chain_check_plan(
    *,
    scope: SupplyChainScope,
    request: SupplyChainAssessmentRequest,
) -> SupplyChainCheckPlan:
    decision = evaluate_supply_chain_assessment(scope=scope, request=request)
    if not decision.allowed:
        raise ValueError(decision.reason)
    return SupplyChainCheckPlan(
        job_id=request.job_id,
        repository_id=request.repository_id,
        pipeline_id=request.pipeline_id,
        check_kinds=tuple(request.check_kinds),
        local_only=not request.external_verification_requested,
    )


def validate_redacted_sensitive_evidence(evidence: RedactedSensitiveEvidence) -> None:
    _require_non_empty("evidence_id", evidence.evidence_id)
    if evidence.redaction_status is not RedactionStatus.REDACTED:
        raise ValueError("sensitive_evidence_requires_redaction")
    if not evidence.redacted_locations:
        raise ValueError("sensitive_evidence_locations_required")
    if evidence.raw_value_recorded:
        raise ValueError("raw_sensitive_value_forbidden")
    for marker in evidence.canary_markers:
        for location in evidence.redacted_locations:
            if marker and marker in location:
                raise ValueError("canary_marker_leaked")


def build_supply_chain_finding_mapping(
    *,
    finding_id: str,
    location_type: SupplyChainLocationType,
    location: str,
    control_category: SupplyChainControlCategory,
    severity: Severity,
    remediation_guidance: str,
    false_positive_workflow: str,
) -> SupplyChainFindingMapping:
    for field_name, value in (
        ("finding_id", finding_id),
        ("location", location),
        ("remediation_guidance", remediation_guidance),
        ("false_positive_workflow", false_positive_workflow),
    ):
        _require_non_empty(field_name, value)
    return SupplyChainFindingMapping(
        finding_id=finding_id.strip(),
        location_type=location_type,
        location=location.strip(),
        control_category=control_category,
        severity=severity,
        remediation_guidance=remediation_guidance.strip(),
        false_positive_workflow=false_positive_workflow.strip(),
    )


def validate_supply_chain_scope(scope: SupplyChainScope) -> None:
    for field_name, value in (
        ("organization_id", scope.organization_id),
        ("engagement_id", scope.engagement_id),
        ("approved_by_user_id", scope.approved_by_user_id),
    ):
        _require_non_empty(field_name, value)
    if not scope.repositories:
        raise ValueError("repository_allowlist_required")
    for repository in scope.repositories:
        _validate_repository(repository)
    for pipeline in scope.pipelines:
        _validate_pipeline(scope, pipeline)


def _validate_repository(repository: RepositoryAllowlistEntry) -> None:
    for field_name, value in (
        ("repository_id", repository.repository_id),
        ("repository_path", repository.repository_path),
        ("repository_owner_user_id", repository.owner_user_id),
    ):
        _require_non_empty(field_name, value)


def _validate_pipeline(scope: SupplyChainScope, pipeline: PipelineAllowlistEntry) -> None:
    for field_name, value in (
        ("pipeline_id", pipeline.pipeline_id),
        ("pipeline_repository_id", pipeline.repository_id),
        ("pipeline_owner_user_id", pipeline.owner_user_id),
    ):
        _require_non_empty(field_name, value)
    if _repository_by_id(scope, pipeline.repository_id) is None:
        raise ValueError("pipeline_repository_not_allowlisted")


def _validate_request_shape(request: SupplyChainAssessmentRequest) -> None:
    for field_name, value in (
        ("job_id", request.job_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("repository_id", request.repository_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    if not request.check_kinds:
        raise ValueError("supply_chain_check_required")


def _repository_by_id(scope: SupplyChainScope, repository_id: str) -> RepositoryAllowlistEntry | None:
    for repository in scope.repositories:
        if repository.repository_id == repository_id:
            return repository
    return None


def _pipeline_by_id(
    scope: SupplyChainScope,
    repository_id: str,
    pipeline_id: str,
) -> PipelineAllowlistEntry | None:
    for pipeline in scope.pipelines:
        if pipeline.repository_id == repository_id and pipeline.pipeline_id == pipeline_id:
            return pipeline
    return None


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
