"""Static-first mobile application assessment contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from redagent_platform.evidence_chain import RedactionStatus
from redagent_platform.findings import Severity


class MobilePlatform(str, Enum):
    ANDROID = "android"
    IOS = "ios"


class MobileAssessmentMode(str, Enum):
    STATIC_PACKAGE_REVIEW = "static_package_review"
    MANIFEST_CONFIGURATION_REVIEW = "manifest_configuration_review"
    DYNAMIC_INSTRUMENTATION = "dynamic_instrumentation"
    TRAFFIC_INTERCEPTION = "traffic_interception"


class MobileForbiddenActivity(str, Enum):
    THIRD_PARTY_APP_TESTING = "third_party_app_testing"
    PRIVACY_CONTROL_BYPASS = "privacy_control_bypass"
    REAL_USER_DATA_CAPTURE = "real_user_data_capture"
    PUBLIC_STORE_SCRAPING = "public_store_scraping"


class MobileEvidenceCategory(str, Enum):
    STATIC_PACKAGE_FINDING = "static_package_finding"
    RUNTIME_LAB_FINDING = "runtime_lab_finding"
    API_BACKEND_FINDING = "api_backend_finding"
    DEVICE_ENVIRONMENT_METADATA = "device_environment_metadata"


@dataclass(frozen=True, kw_only=True)
class MobilePackageAllowlistEntry:
    package_id: str
    platform: MobilePlatform
    version: str
    owner_user_id: str
    approved: bool


@dataclass(frozen=True, kw_only=True)
class MobileLabBoundary:
    lab_id: str
    device_label: str
    emulator_or_test_device: bool
    production_account_forbidden: bool
    real_user_data_forbidden: bool


@dataclass(frozen=True, kw_only=True)
class MobilePrivacyRules:
    allow_personal_data_capture: bool
    require_redaction: bool
    public_store_scraping_allowed: bool


@dataclass(frozen=True, kw_only=True)
class MobileAssessmentScope:
    organization_id: str
    engagement_id: str
    approved_by_user_id: str
    package_allowlist: tuple[MobilePackageAllowlistEntry, ...]
    lab_boundary: MobileLabBoundary
    privacy_rules: MobilePrivacyRules


@dataclass(frozen=True, kw_only=True)
class MobileAssessmentRequest:
    job_id: str
    organization_id: str
    engagement_id: str
    package_id: str
    mode: MobileAssessmentMode
    requested_activities: tuple[MobileForbiddenActivity, ...]


@dataclass(frozen=True, kw_only=True)
class MobileAssessmentDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class MobileReviewStep:
    step_id: str
    mode: MobileAssessmentMode
    static_only: bool


@dataclass(frozen=True, kw_only=True)
class MobileReviewPlan:
    job_id: str
    package_id: str
    steps: tuple[MobileReviewStep, ...]


@dataclass(frozen=True, kw_only=True)
class MobileEvidenceClassification:
    evidence_id: str
    category: MobileEvidenceCategory
    redaction_status: RedactionStatus
    lab_only: bool


@dataclass(frozen=True, kw_only=True)
class MobileFindingMapping:
    finding_id: str
    masvs_control: str
    mastg_test: str
    package_id: str
    severity: Severity
    lab_reproduction_steps: tuple[str, ...]
    remediation_guidance: str


STATIC_MOBILE_MODES = frozenset(
    {
        MobileAssessmentMode.STATIC_PACKAGE_REVIEW,
        MobileAssessmentMode.MANIFEST_CONFIGURATION_REVIEW,
    }
)


def evaluate_mobile_assessment(
    *,
    scope: MobileAssessmentScope,
    request: MobileAssessmentRequest,
) -> MobileAssessmentDecision:
    try:
        validate_mobile_scope(scope)
    except ValueError as exc:
        return MobileAssessmentDecision(allowed=False, reason=str(exc))
    _validate_request_shape(request)
    if request.organization_id != scope.organization_id:
        return MobileAssessmentDecision(allowed=False, reason="organization_mismatch")
    if request.engagement_id != scope.engagement_id:
        return MobileAssessmentDecision(allowed=False, reason="engagement_mismatch")
    package = _package_by_id(scope, request.package_id)
    if package is None:
        return MobileAssessmentDecision(allowed=False, reason="mobile_package_not_allowlisted")
    if not package.approved:
        return MobileAssessmentDecision(allowed=False, reason="mobile_package_owner_approval_required")
    if request.mode not in STATIC_MOBILE_MODES:
        return MobileAssessmentDecision(allowed=False, reason="mobile_dynamic_mode_not_implemented")
    if request.requested_activities:
        return MobileAssessmentDecision(allowed=False, reason="mobile_forbidden_activity_requested")
    return MobileAssessmentDecision(allowed=True, reason="mobile_static_review_allowed")


def build_mobile_static_review_plan(
    *,
    scope: MobileAssessmentScope,
    request: MobileAssessmentRequest,
) -> MobileReviewPlan:
    decision = evaluate_mobile_assessment(scope=scope, request=request)
    if not decision.allowed:
        raise ValueError(decision.reason)
    return MobileReviewPlan(
        job_id=request.job_id,
        package_id=request.package_id,
        steps=(
            MobileReviewStep(
                step_id="static-package-metadata",
                mode=MobileAssessmentMode.STATIC_PACKAGE_REVIEW,
                static_only=True,
            ),
            MobileReviewStep(
                step_id="manifest-configuration",
                mode=MobileAssessmentMode.MANIFEST_CONFIGURATION_REVIEW,
                static_only=True,
            ),
        ),
    )


def classify_mobile_evidence(classification: MobileEvidenceClassification) -> MobileEvidenceClassification:
    _require_non_empty("evidence_id", classification.evidence_id)
    if not classification.lab_only and classification.category is MobileEvidenceCategory.RUNTIME_LAB_FINDING:
        raise ValueError("runtime_mobile_evidence_requires_lab")
    if classification.redaction_status is RedactionStatus.RAW_ALLOWED:
        raise ValueError("mobile_raw_evidence_forbidden")
    return classification


def build_mobile_finding_mapping(
    *,
    finding_id: str,
    masvs_control: str,
    mastg_test: str,
    package_id: str,
    severity: Severity,
    lab_reproduction_steps: tuple[str, ...],
    remediation_guidance: str,
) -> MobileFindingMapping:
    for field_name, value in (
        ("finding_id", finding_id),
        ("masvs_control", masvs_control),
        ("mastg_test", mastg_test),
        ("package_id", package_id),
        ("remediation_guidance", remediation_guidance),
    ):
        _require_non_empty(field_name, value)
    if not lab_reproduction_steps:
        raise ValueError("mobile_lab_reproduction_steps_required")
    for step in lab_reproduction_steps:
        _require_non_empty("lab_reproduction_step", step)
    return MobileFindingMapping(
        finding_id=finding_id.strip(),
        masvs_control=masvs_control.strip(),
        mastg_test=mastg_test.strip(),
        package_id=package_id.strip(),
        severity=severity,
        lab_reproduction_steps=tuple(lab_reproduction_steps),
        remediation_guidance=remediation_guidance.strip(),
    )


def validate_mobile_scope(scope: MobileAssessmentScope) -> None:
    for field_name, value in (
        ("organization_id", scope.organization_id),
        ("engagement_id", scope.engagement_id),
        ("approved_by_user_id", scope.approved_by_user_id),
    ):
        _require_non_empty(field_name, value)
    if not scope.package_allowlist:
        raise ValueError("mobile_package_allowlist_required")
    for package in scope.package_allowlist:
        _validate_package(package)
    _validate_lab_boundary(scope.lab_boundary)
    _validate_privacy_rules(scope.privacy_rules)


def _validate_package(package: MobilePackageAllowlistEntry) -> None:
    for field_name, value in (
        ("package_id", package.package_id),
        ("package_version", package.version),
        ("package_owner_user_id", package.owner_user_id),
    ):
        _require_non_empty(field_name, value)


def _validate_lab_boundary(boundary: MobileLabBoundary) -> None:
    for field_name, value in (("lab_id", boundary.lab_id), ("device_label", boundary.device_label)):
        _require_non_empty(field_name, value)
    if not boundary.emulator_or_test_device:
        raise ValueError("mobile_test_device_required")
    if not boundary.production_account_forbidden:
        raise ValueError("mobile_production_account_must_be_forbidden")
    if not boundary.real_user_data_forbidden:
        raise ValueError("mobile_real_user_data_must_be_forbidden")


def _validate_privacy_rules(rules: MobilePrivacyRules) -> None:
    if rules.allow_personal_data_capture:
        raise ValueError("mobile_personal_data_capture_forbidden")
    if not rules.require_redaction:
        raise ValueError("mobile_redaction_required")
    if rules.public_store_scraping_allowed:
        raise ValueError("mobile_public_store_scraping_forbidden")


def _validate_request_shape(request: MobileAssessmentRequest) -> None:
    for field_name, value in (
        ("job_id", request.job_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("package_id", request.package_id),
    ):
        _require_non_empty(field_name, value)


def _package_by_id(scope: MobileAssessmentScope, package_id: str) -> MobilePackageAllowlistEntry | None:
    for package in scope.package_allowlist:
        if package.package_id == package_id:
            return package
    return None


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
