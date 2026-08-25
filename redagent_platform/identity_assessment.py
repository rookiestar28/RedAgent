"""Read-only enterprise identity assessment policy contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.evidence_chain import RedactionStatus


class IdentityAssessmentMode(str, Enum):
    READ_ONLY_CONFIGURATION = "read_only_configuration"
    ACTIVE_IDENTITY_TEST = "active_identity_test"


class IdentityForbiddenActivity(str, Enum):
    AUTH_SPRAYING = "auth_spraying"
    BRUTE_FORCE = "brute_force"
    SESSION_ARTIFACT_THEFT = "session_artifact_theft"
    AUTH_MATERIAL_DUMPING = "auth_material_dumping"
    PHISHING = "phishing"
    LIVE_PRIVILEGE_ESCALATION = "live_privilege_escalation"


class IdentityControlArea(str, Enum):
    SSO_CONFIGURATION = "sso_configuration"
    OAUTH_APPLICATIONS = "oauth_applications"
    MFA_POLICY = "mfa_policy"
    PRIVILEGED_ACCESS = "privileged_access"
    CONDITIONAL_ACCESS = "conditional_access"


@dataclass(frozen=True, kw_only=True)
class IdentityTenantScope:
    organization_id: str
    engagement_id: str
    tenant_id: str
    tenant_owner_user_id: str
    approved_by_user_id: str | None
    window_start: datetime
    window_end: datetime
    allowed_principal_ids: tuple[str, ...]
    allowed_resource_ids: tuple[str, ...]
    allowed_read_permissions: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class IdentityCredentialBoundary:
    credential_reference_id: str
    lease_id: str
    permissions: tuple[str, ...]
    read_only: bool
    expires_at: datetime
    redaction_label: str

    @property
    def contains_secret_value(self) -> bool:
        return False


@dataclass(frozen=True, kw_only=True)
class IdentityAssessmentRequest:
    job_id: str
    organization_id: str
    engagement_id: str
    tenant_id: str
    mode: IdentityAssessmentMode
    requested_at: datetime
    requested_permissions: tuple[str, ...]
    requested_activities: tuple[IdentityForbiddenActivity, ...]
    operator_user_id: str
    credential_boundary: IdentityCredentialBoundary | None


@dataclass(frozen=True, kw_only=True)
class IdentityAssessmentDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class IdentityCollectionStep:
    step_id: str
    control_area: IdentityControlArea
    resource_label: str
    read_only: bool


@dataclass(frozen=True, kw_only=True)
class IdentityCollectionPlan:
    job_id: str
    tenant_id: str
    mode: IdentityAssessmentMode
    steps: tuple[IdentityCollectionStep, ...]


@dataclass(frozen=True, kw_only=True)
class IdentityFindingMapping:
    finding_id: str
    control_area: IdentityControlArea
    affected_principal_ids: tuple[str, ...]
    affected_resource_ids: tuple[str, ...]
    evidence_redaction_class: RedactionStatus
    remediation_guidance: str


def evaluate_identity_assessment(
    *,
    scope: IdentityTenantScope | None,
    request: IdentityAssessmentRequest,
) -> IdentityAssessmentDecision:
    _validate_request_shape(request)
    if scope is None:
        return IdentityAssessmentDecision(allowed=False, reason="tenant_scope_required")
    try:
        validate_tenant_scope(scope)
    except ValueError as exc:
        return IdentityAssessmentDecision(allowed=False, reason=str(exc))
    if request.organization_id != scope.organization_id:
        return IdentityAssessmentDecision(allowed=False, reason="organization_mismatch")
    if request.engagement_id != scope.engagement_id:
        return IdentityAssessmentDecision(allowed=False, reason="engagement_mismatch")
    if request.tenant_id != scope.tenant_id:
        return IdentityAssessmentDecision(allowed=False, reason="tenant_mismatch")
    if not (scope.window_start <= request.requested_at < scope.window_end):
        return IdentityAssessmentDecision(allowed=False, reason="outside_identity_testing_window")
    if request.mode is not IdentityAssessmentMode.READ_ONLY_CONFIGURATION:
        return IdentityAssessmentDecision(allowed=False, reason="active_identity_test_not_implemented")
    if request.requested_activities:
        return IdentityAssessmentDecision(allowed=False, reason="forbidden_identity_activity_requested")
    boundary = request.credential_boundary
    if boundary is None:
        return IdentityAssessmentDecision(allowed=False, reason="credential_boundary_required")
    boundary_denial = _credential_boundary_denial(scope, request, boundary)
    if boundary_denial:
        return IdentityAssessmentDecision(allowed=False, reason=boundary_denial)
    return IdentityAssessmentDecision(allowed=True, reason="identity_read_only_collection_allowed")


def build_read_only_collection_plan(
    *,
    scope: IdentityTenantScope,
    request: IdentityAssessmentRequest,
) -> IdentityCollectionPlan:
    decision = evaluate_identity_assessment(scope=scope, request=request)
    if not decision.allowed:
        raise ValueError(decision.reason)
    return IdentityCollectionPlan(
        job_id=request.job_id,
        tenant_id=scope.tenant_id,
        mode=IdentityAssessmentMode.READ_ONLY_CONFIGURATION,
        steps=(
            IdentityCollectionStep(
                step_id="sso-configuration",
                control_area=IdentityControlArea.SSO_CONFIGURATION,
                resource_label="tenant_sso_configuration",
                read_only=True,
            ),
            IdentityCollectionStep(
                step_id="oauth-applications",
                control_area=IdentityControlArea.OAUTH_APPLICATIONS,
                resource_label="registered_applications",
                read_only=True,
            ),
            IdentityCollectionStep(
                step_id="mfa-policy",
                control_area=IdentityControlArea.MFA_POLICY,
                resource_label="authentication_methods_policy",
                read_only=True,
            ),
            IdentityCollectionStep(
                step_id="privileged-access",
                control_area=IdentityControlArea.PRIVILEGED_ACCESS,
                resource_label="privileged_role_assignments",
                read_only=True,
            ),
            IdentityCollectionStep(
                step_id="conditional-access",
                control_area=IdentityControlArea.CONDITIONAL_ACCESS,
                resource_label="conditional_access_policies",
                read_only=True,
            ),
        ),
    )


def build_identity_finding_mapping(
    *,
    finding_id: str,
    control_area: IdentityControlArea,
    affected_principal_ids: tuple[str, ...],
    affected_resource_ids: tuple[str, ...],
    evidence_redaction_class: RedactionStatus,
    remediation_guidance: str,
) -> IdentityFindingMapping:
    _require_non_empty("finding_id", finding_id)
    _require_non_empty("remediation_guidance", remediation_guidance)
    if not affected_principal_ids and not affected_resource_ids:
        raise ValueError("identity_finding_requires_affected_entity")
    for principal_id in affected_principal_ids:
        _require_non_empty("affected_principal_id", principal_id)
    for resource_id in affected_resource_ids:
        _require_non_empty("affected_resource_id", resource_id)
    return IdentityFindingMapping(
        finding_id=finding_id.strip(),
        control_area=control_area,
        affected_principal_ids=tuple(affected_principal_ids),
        affected_resource_ids=tuple(affected_resource_ids),
        evidence_redaction_class=evidence_redaction_class,
        remediation_guidance=remediation_guidance.strip(),
    )


def validate_tenant_scope(scope: IdentityTenantScope) -> None:
    for field_name, value in (
        ("organization_id", scope.organization_id),
        ("engagement_id", scope.engagement_id),
        ("tenant_id", scope.tenant_id),
        ("tenant_owner_user_id", scope.tenant_owner_user_id),
    ):
        _require_non_empty(field_name, value)
    if not scope.approved_by_user_id or not scope.approved_by_user_id.strip():
        raise ValueError("tenant_owner_approval_required")
    _require_timezone(scope.window_start)
    _require_timezone(scope.window_end)
    if scope.window_start >= scope.window_end:
        raise ValueError("invalid_identity_testing_window")
    if not scope.allowed_principal_ids:
        raise ValueError("identity_principal_scope_required")
    if not scope.allowed_resource_ids:
        raise ValueError("identity_resource_scope_required")
    if not scope.allowed_read_permissions:
        raise ValueError("identity_read_permissions_required")


def _credential_boundary_denial(
    scope: IdentityTenantScope,
    request: IdentityAssessmentRequest,
    boundary: IdentityCredentialBoundary,
) -> str | None:
    for field_name, value in (
        ("credential_reference_id", boundary.credential_reference_id),
        ("lease_id", boundary.lease_id),
        ("redaction_label", boundary.redaction_label),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(boundary.expires_at)
    if request.requested_at >= boundary.expires_at:
        return "credential_boundary_expired"
    if not boundary.read_only:
        return "least_privilege_read_only_required"
    if not request.requested_permissions:
        return "requested_identity_permissions_required"
    allowed = set(scope.allowed_read_permissions)
    if not set(request.requested_permissions).issubset(allowed):
        return "identity_permission_not_allowed"
    if not set(request.requested_permissions).issubset(set(boundary.permissions)):
        return "credential_boundary_permission_missing"
    return None


def _validate_request_shape(request: IdentityAssessmentRequest) -> None:
    for field_name, value in (
        ("job_id", request.job_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("tenant_id", request.tenant_id),
        ("operator_user_id", request.operator_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
