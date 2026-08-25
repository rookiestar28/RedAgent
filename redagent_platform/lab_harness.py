"""Local lab target harness contracts.

compat_012 is intentionally non-executing: it validates local lab target metadata and
builds request/procedure specifications, but never starts services or sends
network traffic.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse

from redagent_platform.domain import AuthorizationStatus, TargetType, TestMode
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget
from redagent_platform.target_inventory import (
    DataSensitivity,
    EnvironmentType,
    InventoryTarget,
    TargetImportCandidate,
    build_inventory_target,
)


class LabTargetKind(str, Enum):
    JUICE_SHOP = "juice_shop"
    CRAPI = "crapi"


class LabHarnessAction(str, Enum):
    CONNECT_EXISTING = "connect_existing"
    RUN_LOCAL = "run_local"


class LabProcedureKind(str, Enum):
    HEALTH_CHECK = "health_check"
    RESET = "reset"
    TEARDOWN = "teardown"


LAB_ONLY_LABEL = "lab-only"
PUBLIC_DEMO_HOSTS = frozenset(
    {
        "demo.owasp-juice.shop",
        "juice-shop.herokuapp.com",
        "preview.owasp-juice.shop",
        "crapi.apisec.ai",
    }
)


@dataclass(frozen=True, kw_only=True)
class SandboxApproval:
    approval_id: str
    organization_id: str
    approved_by_user_id: str
    approved_at: datetime
    expires_at: datetime
    allowed_kinds: tuple[LabTargetKind, ...]
    allowed_actions: tuple[LabHarnessAction, ...]
    plan_reference: str
    emergency_contact_method: str


@dataclass(frozen=True, kw_only=True)
class LabProcedureStep:
    order: int
    description: str
    manual_confirmation_required: bool = True


@dataclass(frozen=True, kw_only=True)
class LabProcedure:
    kind: LabProcedureKind
    steps: tuple[LabProcedureStep, ...]
    destructive: bool


@dataclass(frozen=True, kw_only=True)
class LabHealthCheckRequest:
    method: str
    url: str
    expected_statuses: tuple[int, ...]
    timeout_seconds: int


@dataclass(frozen=True, kw_only=True)
class LabTargetRequest:
    target_id: str
    organization_id: str
    engagement_id: str
    owner_label: str
    kind: LabTargetKind
    action: LabHarnessAction
    base_url: str
    requested_at: datetime
    health_path: str = "/"
    health_expected_statuses: tuple[int, ...] = (200,)
    health_timeout_seconds: int = 5


@dataclass(frozen=True, kw_only=True)
class LabTargetRegistration:
    target_id: str
    kind: LabTargetKind
    action: LabHarnessAction
    base_url: str
    labels: tuple[str, ...]
    inventory_target: InventoryTarget
    scope_target: ScopeTarget
    health_check: LabHealthCheckRequest
    reset_procedure: LabProcedure
    teardown_procedure: LabProcedure
    sandbox_approval_id: str


def register_lab_target(request: LabTargetRequest, approval: SandboxApproval) -> LabTargetRegistration:
    """Validate and register a lab target without starting or contacting it."""
    _validate_request(request)
    _validate_approval(approval, request)
    base_url = _normalize_local_origin(request.base_url)
    inventory_target = build_inventory_target(
        TargetImportCandidate(
            id=request.target_id.strip(),
            organization_id=request.organization_id.strip(),
            engagement_id=request.engagement_id.strip(),
            owner_label=request.owner_label.strip(),
            target_type=TargetType.LAB_TARGET,
            value=_lab_inventory_value(request.kind, request.target_id),
            environment=EnvironmentType.LAB,
            data_sensitivity=DataSensitivity.PUBLIC,
            authorization_status=AuthorizationStatus.APPROVED,
            allowed_modes=(TestMode.LAB_ONLY_RUN,),
            explicit_review=True,
            review_reason=f"sandbox approval {approval.approval_id}: {approval.plan_reference}",
        )
    )
    scope_target = inventory_target.to_scope_target()
    return LabTargetRegistration(
        target_id=inventory_target.id,
        kind=request.kind,
        action=request.action,
        base_url=base_url,
        labels=(LAB_ONLY_LABEL,),
        inventory_target=inventory_target,
        scope_target=scope_target,
        health_check=build_health_check_request(
            base_url=base_url,
            path=request.health_path,
            expected_statuses=request.health_expected_statuses,
            timeout_seconds=request.health_timeout_seconds,
        ),
        reset_procedure=default_reset_procedure(request.kind),
        teardown_procedure=default_teardown_procedure(request.kind),
        sandbox_approval_id=approval.approval_id,
    )


def build_health_check_request(
    *,
    base_url: str,
    path: str,
    expected_statuses: tuple[int, ...],
    timeout_seconds: int,
) -> LabHealthCheckRequest:
    """Build health-check request metadata; callers must execute it elsewhere."""
    normalized_origin = _normalize_local_origin(base_url)
    normalized_path = _normalize_path(path)
    if not expected_statuses or any(status < 100 or status > 599 for status in expected_statuses):
        raise ValueError("invalid_health_expected_status")
    if timeout_seconds <= 0:
        raise ValueError("invalid_health_timeout")
    return LabHealthCheckRequest(
        method="GET",
        url=f"{normalized_origin}{normalized_path}",
        expected_statuses=tuple(expected_statuses),
        timeout_seconds=timeout_seconds,
    )


def default_reset_procedure(kind: LabTargetKind) -> LabProcedure:
    _require_supported_kind(kind)
    return LabProcedure(
        kind=LabProcedureKind.RESET,
        destructive=True,
        steps=(
            LabProcedureStep(order=1, description=f"Stop the local {kind.value} lab instance."),
            LabProcedureStep(order=2, description="Reset local lab data volumes or fixtures per the sandbox plan."),
            LabProcedureStep(order=3, description=f"Restart the local {kind.value} lab instance."),
            LabProcedureStep(order=4, description="Generate a new approved health-check request and review the result."),
        ),
    )


def default_teardown_procedure(kind: LabTargetKind) -> LabProcedure:
    _require_supported_kind(kind)
    return LabProcedure(
        kind=LabProcedureKind.TEARDOWN,
        destructive=True,
        steps=(
            LabProcedureStep(order=1, description=f"Stop the local {kind.value} lab instance."),
            LabProcedureStep(order=2, description="Remove local disposable lab data created for the sandbox plan."),
            LabProcedureStep(order=3, description="Record teardown evidence in the engagement command log."),
        ),
    )


def build_lab_only_scope(
    *,
    registration: LabTargetRegistration,
    window_start: datetime,
    window_end: datetime,
    max_interactions: int,
    max_rate_per_second: float,
    emergency_contact_method: str,
    approved_by_user_id: str,
) -> EngagementScope:
    """Build an R006-compatible scope limited to the registered lab target."""
    return EngagementScope(
        engagement_id=registration.inventory_target.engagement_id,
        organization_id=registration.inventory_target.organization_id,
        authorization_status=AuthorizationStatus.APPROVED,
        approved_by_user_id=approved_by_user_id,
        allowed_targets=(registration.scope_target,),
        forbidden_targets=(),
        allowed_modes=(TestMode.LAB_ONLY_RUN,),
        window_start=window_start,
        window_end=window_end,
        max_interactions=max_interactions,
        max_rate_per_second=max_rate_per_second,
        emergency_contact_method=emergency_contact_method,
    )


def _validate_request(request: LabTargetRequest) -> None:
    for field_name, value in (
        ("target_id", request.target_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("owner_label", request.owner_label),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _require_supported_kind(request.kind)
    if request.health_timeout_seconds <= 0:
        raise ValueError("invalid_health_timeout")


def _validate_approval(approval: SandboxApproval, request: LabTargetRequest) -> None:
    for field_name, value in (
        ("approval_id", approval.approval_id),
        ("organization_id", approval.organization_id),
        ("approved_by_user_id", approval.approved_by_user_id),
        ("plan_reference", approval.plan_reference),
        ("emergency_contact_method", approval.emergency_contact_method),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(approval.approved_at)
    _require_timezone(approval.expires_at)
    if approval.organization_id != request.organization_id:
        raise ValueError("sandbox_organization_mismatch")
    if not (approval.approved_at <= request.requested_at < approval.expires_at):
        raise ValueError("sandbox_approval_not_current")
    if request.kind not in approval.allowed_kinds:
        raise ValueError("lab_kind_not_approved")
    if request.action not in approval.allowed_actions:
        raise ValueError("lab_action_not_approved")


def _normalize_local_origin(value: str) -> str:
    _require_non_empty("base_url", value)
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("invalid_lab_origin")
    host = parsed.hostname.lower()
    if host in PUBLIC_DEMO_HOSTS:
        raise ValueError("public_demo_forbidden")
    if not _is_loopback_host(host):
        raise ValueError("local_loopback_required")
    if parsed.username or parsed.password:
        raise ValueError("lab_origin_credentials_forbidden")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("lab_origin_must_be_origin_only")
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port}"


def _normalize_path(path: str) -> str:
    _require_non_empty("health_path", path)
    if "://" in path or "?" in path or "#" in path:
        raise ValueError("invalid_health_path")
    stripped = path.strip()
    return stripped if stripped.startswith("/") else f"/{stripped}"


def _lab_inventory_value(kind: LabTargetKind, target_id: str) -> str:
    safe_id = target_id.strip().lower()
    if "://" in safe_id or not safe_id:
        raise ValueError("invalid_lab_target_id")
    return f"lab:{kind.value}/{safe_id}"


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _require_supported_kind(kind: LabTargetKind) -> None:
    if kind not in LabTargetKind:
        raise ValueError("unsupported_lab_target_kind")


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
