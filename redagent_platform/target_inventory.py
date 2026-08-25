"""Authorized target inventory contracts and local import validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

from redagent_platform.domain import (
    AuditEvent,
    AuthorizationStatus,
    PolicyDecisionOutcome,
    PolicyDecision,
    TargetType,
    TestMode,
)
from redagent_platform.scope_authorization import ScopeTarget


class EnvironmentType(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    LAB = "lab"
    UNKNOWN = "unknown"


class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    REGULATED = "regulated"
    UNKNOWN = "unknown"


class InventoryAuditAction(str, Enum):
    CREATE = "target_inventory.create"
    UPDATE = "target_inventory.update"
    DELETE = "target_inventory.delete"


@dataclass(frozen=True, kw_only=True)
class TargetImportCandidate:
    id: str
    organization_id: str
    engagement_id: str
    owner_label: str
    target_type: TargetType
    value: str
    environment: EnvironmentType
    data_sensitivity: DataSensitivity
    authorization_status: AuthorizationStatus
    allowed_modes: tuple[TestMode, ...]
    explicit_review: bool = False
    review_reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class InventoryTarget:
    id: str
    organization_id: str
    engagement_id: str
    owner_label: str
    target_type: TargetType
    value: str
    environment: EnvironmentType
    data_sensitivity: DataSensitivity
    authorization_status: AuthorizationStatus
    allowed_modes: tuple[TestMode, ...]
    explicit_review: bool
    review_reason: str | None

    def to_scope_target(self) -> ScopeTarget:
        return ScopeTarget(target_type=self.target_type, value=self.value)


@dataclass(frozen=True, kw_only=True)
class TargetValidationResult:
    normalized_value: str | None
    errors: tuple[str, ...]
    review_required: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return not self.errors and not self.review_required


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SAFE_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,127}$")
_AWS_ACCOUNT_ID = re.compile(r"^\d{12}$")
_GCP_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def validate_import_candidate(candidate: TargetImportCandidate) -> TargetValidationResult:
    """Validate an inventory import without touching networks or external systems."""
    errors: list[str] = []
    review_required: list[str] = []

    _require_non_empty("id", candidate.id, errors)
    _require_non_empty("organization_id", candidate.organization_id, errors)
    _require_non_empty("engagement_id", candidate.engagement_id, errors)
    _require_non_empty("owner_label", candidate.owner_label, errors)
    if not candidate.allowed_modes:
        errors.append("missing_allowed_modes")
    if candidate.explicit_review and not candidate.review_reason:
        errors.append("missing_review_reason")

    normalized_value = _normalize_by_type(candidate.target_type, candidate.value, errors, review_required)
    if candidate.environment is EnvironmentType.UNKNOWN:
        review_required.append("unknown_environment")
    if candidate.data_sensitivity is DataSensitivity.UNKNOWN:
        review_required.append("unknown_data_sensitivity")
    if candidate.target_type is TargetType.LAB_TARGET and candidate.environment is not EnvironmentType.LAB:
        review_required.append("lab_target_environment_mismatch")

    blocking_review = tuple(sorted(set(review_required))) if not candidate.explicit_review else ()
    return TargetValidationResult(
        normalized_value=normalized_value,
        errors=tuple(sorted(set(errors))),
        review_required=blocking_review,
    )


def build_inventory_target(candidate: TargetImportCandidate) -> InventoryTarget:
    result = validate_import_candidate(candidate)
    if not result.accepted or result.normalized_value is None:
        reasons = ", ".join(result.errors + result.review_required)
        raise ValueError(f"target_import_rejected:{reasons}")
    return InventoryTarget(
        id=candidate.id.strip(),
        organization_id=candidate.organization_id.strip(),
        engagement_id=candidate.engagement_id.strip(),
        owner_label=candidate.owner_label.strip(),
        target_type=candidate.target_type,
        value=result.normalized_value,
        environment=candidate.environment,
        data_sensitivity=candidate.data_sensitivity,
        authorization_status=candidate.authorization_status,
        allowed_modes=tuple(candidate.allowed_modes),
        explicit_review=candidate.explicit_review,
        review_reason=candidate.review_reason,
    )


def audit_inventory_change(
    *,
    event_id: str,
    action: InventoryAuditAction,
    target: InventoryTarget,
    actor_user_id: str | None,
) -> AuditEvent:
    _require_audit_action(action)
    return AuditEvent(
        id=event_id,
        organization_id=target.organization_id,
        actor_user_id=actor_user_id,
        action=action.value,
        subject_type="target_inventory",
        subject_id=target.id,
    )


def policy_decision_for_import(
    *,
    decision_id: str,
    organization_id: str,
    candidate: TargetImportCandidate,
) -> PolicyDecision:
    result = validate_import_candidate(candidate)
    if result.accepted:
        outcome = PolicyDecisionOutcome.ALLOW
        reason = "target_import_allowed"
    elif result.errors:
        outcome = PolicyDecisionOutcome.DENY
        reason = "target_import_invalid:" + ",".join(result.errors)
    else:
        outcome = PolicyDecisionOutcome.REQUIRE_REVIEW
        reason = "target_import_requires_review:" + ",".join(result.review_required)
    return PolicyDecision(
        id=decision_id,
        organization_id=organization_id,
        outcome=outcome,
        reason=reason,
        subject_type="target_import",
        subject_id=candidate.id,
    )


def _require_non_empty(field_name: str, value: str, errors: list[str]) -> None:
    if not value or not value.strip():
        errors.append(f"missing_{field_name}")


def _normalize_by_type(
    target_type: TargetType,
    value: str,
    errors: list[str],
    review_required: list[str],
) -> str | None:
    if not value or not value.strip():
        errors.append("missing_target_value")
        return None

    if target_type is TargetType.WEB_ORIGIN:
        return _normalize_web_origin(value, errors, review_required)
    if target_type is TargetType.API_SPEC:
        return _normalize_api_spec(value, errors)
    if target_type is TargetType.DOMAIN:
        return _normalize_domain(value, errors, review_required)
    if target_type is TargetType.CIDR:
        return _normalize_cidr(value, errors, review_required)
    if target_type is TargetType.CLOUD_ACCOUNT:
        return _normalize_cloud_account(value, errors)
    if target_type is TargetType.CLOUD_PROJECT:
        return _normalize_cloud_project(value, errors)
    if target_type is TargetType.CLOUD_SUBSCRIPTION:
        return _normalize_cloud_subscription(value, errors)
    if target_type is TargetType.KUBERNETES_CLUSTER:
        return _normalize_safe_identifier(value, "invalid_kubernetes_cluster", errors)
    if target_type is TargetType.LAB_TARGET:
        return _normalize_safe_identifier(value, "invalid_lab_target", errors)

    errors.append("unsupported_target_type")
    return None


def _normalize_web_origin(value: str, errors: list[str], review_required: list[str]) -> str | None:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        errors.append("invalid_web_origin")
        return None
    if parsed.username or parsed.password:
        errors.append("web_origin_credentials_forbidden")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        errors.append("web_origin_must_be_origin_only")
    host = parsed.hostname.lower()
    if _is_ip_review_required(host):
        review_required.append("private_public_ambiguous_origin")
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port}"


def _normalize_api_spec(value: str, errors: list[str]) -> str | None:
    stripped = value.strip()
    parsed = urlparse(stripped)
    if parsed.scheme:
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            errors.append("invalid_api_spec_url")
            return None
        if parsed.username or parsed.password:
            errors.append("api_spec_credentials_forbidden")
        if parsed.query or parsed.fragment:
            errors.append("api_spec_query_fragment_forbidden")
        if not parsed.path.lower().endswith((".json", ".yaml", ".yml")):
            errors.append("api_spec_extension_required")
        return stripped.lower()
    if not stripped.lower().endswith((".json", ".yaml", ".yml")) or any(ch.isspace() for ch in stripped):
        errors.append("invalid_api_spec_reference")
        return None
    return stripped


def _normalize_domain(value: str, errors: list[str], review_required: list[str]) -> str | None:
    stripped = value.strip().lower().rstrip(".")
    wildcard = stripped.startswith("*.")
    domain = stripped[2:] if wildcard else stripped
    if "*" in domain:
        errors.append("invalid_domain_wildcard")
        return None
    if domain in {"localhost", "local"}:
        errors.append("invalid_domain")
        return None
    labels = domain.split(".")
    if not labels or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        errors.append("invalid_domain")
        return None
    if wildcard:
        review_required.append("wildcard_domain")
    if len(labels) == 1 or domain.endswith(".local") or domain.endswith(".internal"):
        review_required.append("private_public_ambiguous_domain")
    return f"*.{domain}" if wildcard else domain


def _normalize_cidr(value: str, errors: list[str], review_required: list[str]) -> str | None:
    stripped = value.strip()
    if "/" not in stripped:
        errors.append("cidr_prefix_required")
        return None
    try:
        network = ipaddress.ip_network(stripped, strict=False)
    except ValueError:
        errors.append("invalid_cidr")
        return None
    if network.version == 4 and network.prefixlen < 24:
        review_required.append("over_broad_ipv4_cidr")
    if network.version == 6 and network.prefixlen < 64:
        review_required.append("over_broad_ipv6_cidr")
    if network.is_private or network.is_loopback or network.is_link_local or network.is_reserved:
        review_required.append("private_public_ambiguous_cidr")
    return network.with_prefixlen


def _normalize_cloud_account(value: str, errors: list[str]) -> str | None:
    stripped = value.strip().lower()
    if stripped.startswith("aws:"):
        account_id = stripped.removeprefix("aws:")
        if not _AWS_ACCOUNT_ID.fullmatch(account_id):
            errors.append("invalid_cloud_account")
            return None
        return stripped
    if stripped.startswith(("azure:", "gcp:", "cloud:")):
        return _normalize_safe_identifier(stripped, "invalid_cloud_account", errors)
    errors.append("invalid_cloud_account")
    return None


def _normalize_cloud_project(value: str, errors: list[str]) -> str | None:
    stripped = value.strip().lower()
    if stripped.startswith("gcp:"):
        project_id = stripped.removeprefix("gcp:")
        if not _GCP_PROJECT_ID.fullmatch(project_id):
            errors.append("invalid_cloud_project")
            return None
        return stripped
    if stripped.startswith(("aws:", "azure:", "cloud:")):
        return _normalize_safe_identifier(stripped, "invalid_cloud_project", errors)
    errors.append("invalid_cloud_project")
    return None


def _normalize_cloud_subscription(value: str, errors: list[str]) -> str | None:
    stripped = value.strip().lower()
    if stripped.startswith("azure:"):
        subscription_id = stripped.removeprefix("azure:")
        if not _UUID.fullmatch(subscription_id):
            errors.append("invalid_cloud_subscription")
            return None
        return stripped
    if stripped.startswith(("aws:", "gcp:", "cloud:")):
        return _normalize_safe_identifier(stripped, "invalid_cloud_subscription", errors)
    errors.append("invalid_cloud_subscription")
    return None


def _normalize_safe_identifier(value: str, error_code: str, errors: list[str]) -> str | None:
    stripped = value.strip().lower()
    if "://" in stripped or not _SAFE_IDENTIFIER.fullmatch(stripped):
        errors.append(error_code)
        return None
    return stripped


def _is_ip_review_required(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved


def _require_audit_action(action: InventoryAuditAction) -> None:
    if action not in InventoryAuditAction:
        raise ValueError("invalid_inventory_audit_action")
