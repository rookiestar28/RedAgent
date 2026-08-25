"""Read-only cloud, Kubernetes, container, and IaC posture contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.evidence_chain import RedactionStatus
from redagent_platform.target_inventory import EnvironmentType


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"


class CloudPostureMode(str, Enum):
    READ_ONLY_POSTURE = "read_only_posture"
    CLOUD_DETONATION = "cloud_detonation"
    RESOURCE_MUTATION = "resource_mutation"
    PERSISTENCE_TEST = "persistence_test"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CLEANUP_DEPENDENT_TEST = "cleanup_dependent_test"


class CloudControlDomain(str, Enum):
    IDENTITY_ACCESS = "identity_access"
    LOGGING_MONITORING = "logging_monitoring"
    NETWORK_SECURITY = "network_security"
    ENCRYPTION = "encryption"
    KUBERNETES_RBAC = "kubernetes_rbac"
    KUBERNETES_NETWORK_POLICY = "kubernetes_network_policy"
    CONTAINER_IMAGE = "container_image"
    IAC_CONFIGURATION = "iac_configuration"


class KubernetesFindingArea(str, Enum):
    CONTROL_PLANE = "control_plane"
    WORKER_NODE = "worker_node"
    NAMESPACE = "namespace"
    WORKLOAD = "workload"
    RBAC = "rbac"
    NETWORK_POLICY = "network_policy"
    SENSITIVE_CONFIGURATION = "sensitive_configuration"


@dataclass(frozen=True, kw_only=True)
class CloudScope:
    organization_id: str
    engagement_id: str
    provider: CloudProvider
    environment: EnvironmentType
    account_ids: tuple[str, ...]
    project_ids: tuple[str, ...]
    cluster_ids: tuple[str, ...]
    regions: tuple[str, ...]
    owner_approved_by_user_id: str
    credential_reference_id: str
    allowed_read_permissions: tuple[str, ...]
    monthly_cost_estimate_usd: float
    blast_radius_reviewed: bool
    subscription_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class CloudCredentialBoundary:
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
class CloudPostureRequest:
    job_id: str
    organization_id: str
    engagement_id: str
    provider: CloudProvider
    mode: CloudPostureMode
    requested_at: datetime
    target_id: str
    requested_permissions: tuple[str, ...]
    credential_boundary: CloudCredentialBoundary | None


@dataclass(frozen=True, kw_only=True)
class CloudPostureDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class CloudCollectionStep:
    step_id: str
    control_domain: CloudControlDomain
    read_only: bool


@dataclass(frozen=True, kw_only=True)
class CloudCollectionPlan:
    job_id: str
    provider: CloudProvider
    mode: CloudPostureMode
    steps: tuple[CloudCollectionStep, ...]


@dataclass(frozen=True, kw_only=True)
class KubernetesCheckMapping:
    area: KubernetesFindingArea
    control_domain: CloudControlDomain
    resource_label: str


@dataclass(frozen=True, kw_only=True)
class ArtifactEvidencePolicy:
    artifact_id: str
    artifact_kind: str
    private_artifact: bool
    upload_to_external_service: bool
    redaction_status: RedactionStatus
    contains_sensitive_material: bool


@dataclass(frozen=True, kw_only=True)
class CloudFindingMapping:
    finding_id: str
    control_domain: CloudControlDomain
    affected_resource_id: str
    region: str | None
    cluster_id: str | None
    severity: str
    remediation_guidance: str
    evidence_redaction_class: RedactionStatus


def evaluate_cloud_posture(scope: CloudScope, request: CloudPostureRequest) -> CloudPostureDecision:
    try:
        validate_cloud_scope(scope)
    except ValueError as exc:
        return CloudPostureDecision(allowed=False, reason=str(exc))
    _validate_request_shape(request)
    if request.organization_id != scope.organization_id:
        return CloudPostureDecision(allowed=False, reason="organization_mismatch")
    if request.engagement_id != scope.engagement_id:
        return CloudPostureDecision(allowed=False, reason="engagement_mismatch")
    if request.provider is not scope.provider:
        return CloudPostureDecision(allowed=False, reason="provider_mismatch")
    if request.mode is not CloudPostureMode.READ_ONLY_POSTURE:
        return CloudPostureDecision(allowed=False, reason="cloud_mutating_mode_blocked")
    if request.target_id not in _allowed_target_ids(scope):
        return CloudPostureDecision(allowed=False, reason="cloud_target_not_allowlisted")
    boundary = request.credential_boundary
    if boundary is None:
        return CloudPostureDecision(allowed=False, reason="cloud_credential_boundary_required")
    boundary_denial = _credential_boundary_denial(scope, request, boundary)
    if boundary_denial:
        return CloudPostureDecision(allowed=False, reason=boundary_denial)
    return CloudPostureDecision(allowed=True, reason="cloud_read_only_posture_allowed")


def build_cloud_collection_plan(scope: CloudScope, request: CloudPostureRequest) -> CloudCollectionPlan:
    decision = evaluate_cloud_posture(scope, request)
    if not decision.allowed:
        raise ValueError(decision.reason)
    return CloudCollectionPlan(
        job_id=request.job_id,
        provider=request.provider,
        mode=CloudPostureMode.READ_ONLY_POSTURE,
        steps=(
            CloudCollectionStep(step_id="identity-access", control_domain=CloudControlDomain.IDENTITY_ACCESS, read_only=True),
            CloudCollectionStep(step_id="logging-monitoring", control_domain=CloudControlDomain.LOGGING_MONITORING, read_only=True),
            CloudCollectionStep(step_id="network-security", control_domain=CloudControlDomain.NETWORK_SECURITY, read_only=True),
            CloudCollectionStep(step_id="encryption", control_domain=CloudControlDomain.ENCRYPTION, read_only=True),
            CloudCollectionStep(step_id="iac-configuration", control_domain=CloudControlDomain.IAC_CONFIGURATION, read_only=True),
        ),
    )


def kubernetes_check_mappings() -> tuple[KubernetesCheckMapping, ...]:
    return (
        KubernetesCheckMapping(
            area=KubernetesFindingArea.CONTROL_PLANE,
            control_domain=CloudControlDomain.LOGGING_MONITORING,
            resource_label="api_server",
        ),
        KubernetesCheckMapping(
            area=KubernetesFindingArea.WORKER_NODE,
            control_domain=CloudControlDomain.CONTAINER_IMAGE,
            resource_label="node",
        ),
        KubernetesCheckMapping(
            area=KubernetesFindingArea.NAMESPACE,
            control_domain=CloudControlDomain.KUBERNETES_RBAC,
            resource_label="namespace",
        ),
        KubernetesCheckMapping(
            area=KubernetesFindingArea.WORKLOAD,
            control_domain=CloudControlDomain.CONTAINER_IMAGE,
            resource_label="workload",
        ),
        KubernetesCheckMapping(
            area=KubernetesFindingArea.RBAC,
            control_domain=CloudControlDomain.KUBERNETES_RBAC,
            resource_label="role_binding",
        ),
        KubernetesCheckMapping(
            area=KubernetesFindingArea.NETWORK_POLICY,
            control_domain=CloudControlDomain.KUBERNETES_NETWORK_POLICY,
            resource_label="network_policy",
        ),
        KubernetesCheckMapping(
            area=KubernetesFindingArea.SENSITIVE_CONFIGURATION,
            control_domain=CloudControlDomain.ENCRYPTION,
            resource_label="configuration_object",
        ),
    )


def validate_artifact_evidence_policy(policy: ArtifactEvidencePolicy) -> None:
    _require_non_empty("artifact_id", policy.artifact_id)
    _require_non_empty("artifact_kind", policy.artifact_kind)
    if policy.private_artifact and policy.upload_to_external_service:
        raise ValueError("private_artifact_external_upload_forbidden")
    if policy.contains_sensitive_material and policy.redaction_status is not RedactionStatus.REDACTED:
        raise ValueError("sensitive_artifact_requires_redaction")


def build_cloud_finding_mapping(
    *,
    finding_id: str,
    control_domain: CloudControlDomain,
    affected_resource_id: str,
    region: str | None,
    cluster_id: str | None,
    severity: str,
    remediation_guidance: str,
    evidence_redaction_class: RedactionStatus,
) -> CloudFindingMapping:
    for field_name, value in (
        ("finding_id", finding_id),
        ("affected_resource_id", affected_resource_id),
        ("severity", severity),
        ("remediation_guidance", remediation_guidance),
    ):
        _require_non_empty(field_name, value)
    return CloudFindingMapping(
        finding_id=finding_id.strip(),
        control_domain=control_domain,
        affected_resource_id=affected_resource_id.strip(),
        region=region.strip() if region else None,
        cluster_id=cluster_id.strip() if cluster_id else None,
        severity=severity.strip(),
        remediation_guidance=remediation_guidance.strip(),
        evidence_redaction_class=evidence_redaction_class,
    )


def validate_cloud_scope(scope: CloudScope) -> None:
    for field_name, value in (
        ("organization_id", scope.organization_id),
        ("engagement_id", scope.engagement_id),
        ("owner_approved_by_user_id", scope.owner_approved_by_user_id),
        ("credential_reference_id", scope.credential_reference_id),
    ):
        _require_non_empty(field_name, value)
    if scope.environment is EnvironmentType.UNKNOWN:
        raise ValueError("cloud_environment_classification_required")
    if not _allowed_target_ids(scope):
        raise ValueError("cloud_target_allowlist_required")
    if not scope.regions and scope.provider is not CloudProvider.KUBERNETES:
        raise ValueError("cloud_region_required")
    if not scope.allowed_read_permissions:
        raise ValueError("cloud_read_permissions_required")
    if scope.monthly_cost_estimate_usd < 0:
        raise ValueError("cloud_cost_estimate_invalid")
    if not scope.blast_radius_reviewed:
        raise ValueError("cloud_blast_radius_review_required")


def _credential_boundary_denial(
    scope: CloudScope,
    request: CloudPostureRequest,
    boundary: CloudCredentialBoundary,
) -> str | None:
    for field_name, value in (
        ("credential_reference_id", boundary.credential_reference_id),
        ("lease_id", boundary.lease_id),
        ("redaction_label", boundary.redaction_label),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(boundary.expires_at)
    if boundary.credential_reference_id != scope.credential_reference_id:
        return "cloud_credential_reference_mismatch"
    if request.requested_at >= boundary.expires_at:
        return "cloud_credential_boundary_expired"
    if not boundary.read_only:
        return "cloud_read_only_credential_required"
    if not request.requested_permissions:
        return "cloud_requested_permissions_required"
    allowed = set(scope.allowed_read_permissions)
    if not set(request.requested_permissions).issubset(allowed):
        return "cloud_permission_not_allowed"
    if not set(request.requested_permissions).issubset(set(boundary.permissions)):
        return "cloud_credential_permission_missing"
    return None


def _validate_request_shape(request: CloudPostureRequest) -> None:
    for field_name, value in (
        ("job_id", request.job_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("target_id", request.target_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)


def _allowed_target_ids(scope: CloudScope) -> frozenset[str]:
    return frozenset(
        item for item in scope.account_ids + scope.project_ids + scope.subscription_ids + scope.cluster_ids if item.strip()
    )


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
