"""DLP canary validation policy and sanitized evidence contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.attack_campaigns import TelemetrySource
from redagent_platform.telemetry_feedback import TelemetryObservationStatus


class CanaryDataClass(str, Enum):
    SYNTHETIC = "synthetic"
    CANARY = "canary"
    REAL_SENSITIVE_VALUE = "real_sensitive_value"
    PERSONAL_DATA = "personal_data"
    CUSTOMER_DATA = "customer_data"
    PRODUCTION_CREDENTIAL = "production_credential"
    REGULATED_DATA = "regulated_data"


class DlpProtocol(str, Enum):
    HTTPS = "https"
    SFTP = "sftp"
    EMAIL = "email"
    CLOUD_STORAGE = "cloud_storage"


class DlpDecisionReason(str, Enum):
    APPROVED_FOR_REVIEW_QUEUE = "approved_for_review_queue"
    MISSING_CANARY_DATASET = "missing_canary_dataset"
    SENSITIVE_DATA_FORBIDDEN = "sensitive_data_forbidden"
    MISSING_ROE = "missing_roe"
    MISSING_APPROVAL = "missing_approval"
    MISSING_TARGET_SCOPE = "missing_target_scope"
    MISSING_MONITORING_OWNER = "missing_monitoring_owner"
    MISSING_STOP_CONDITION = "missing_stop_condition"
    MONITORING_NOT_READY = "monitoring_not_ready"
    INVALID_REQUEST = "invalid_request"


FORBIDDEN_DATA_CLASSES: frozenset[CanaryDataClass] = frozenset(
    {
        CanaryDataClass.REAL_SENSITIVE_VALUE,
        CanaryDataClass.PERSONAL_DATA,
        CanaryDataClass.CUSTOMER_DATA,
        CanaryDataClass.PRODUCTION_CREDENTIAL,
        CanaryDataClass.REGULATED_DATA,
    }
)


@dataclass(frozen=True, kw_only=True)
class CanaryDataset:
    dataset_id: str
    data_classes: tuple[CanaryDataClass, ...]
    canary_markers: tuple[str, ...]
    synthetic_generation_note: str


@dataclass(frozen=True, kw_only=True)
class DlpRulesOfEngagement:
    roe_id: str
    source_systems: tuple[str, ...]
    destination_systems: tuple[str, ...]
    data_labels: tuple[str, ...]
    max_volume_bytes: int
    max_record_count: int
    allowed_protocols: tuple[DlpProtocol, ...]
    window_start: datetime
    window_end: datetime
    timezone_label: str
    detection_stakeholders: tuple[str, ...]
    emergency_stop_conditions: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class PurpleTeamApproval:
    approved_by_user_id: str | None
    approval_ticket_id: str | None
    monitoring_owner_user_id: str | None
    approved_at: datetime | None


@dataclass(frozen=True, kw_only=True)
class MonitoringReadiness:
    monitoring_owner_user_id: str | None
    telemetry_sources: tuple[TelemetrySource, ...]
    alert_route_id: str | None
    control_owner_user_id: str | None
    ready: bool


@dataclass(frozen=True, kw_only=True)
class DlpTargetScope:
    source_system_id: str | None
    destination_system_id: str | None
    protocol: DlpProtocol | None
    volume_bytes: int
    record_count: int


@dataclass(frozen=True, kw_only=True)
class DlpValidationRequest:
    validation_id: str
    organization_id: str
    engagement_id: str
    dataset: CanaryDataset | None
    roe: DlpRulesOfEngagement | None
    approval: PurpleTeamApproval | None
    monitoring: MonitoringReadiness | None
    target_scope: DlpTargetScope | None
    requested_at: datetime


@dataclass(frozen=True, kw_only=True)
class DlpValidationDecision:
    allowed: bool
    reason: DlpDecisionReason
    details: tuple[str, ...] = ()
    execution_enabled: bool = False


@dataclass(frozen=True, kw_only=True)
class DlpDetectionEvidence:
    evidence_id: str
    validation_id: str
    detection_outcome: TelemetryObservationStatus
    telemetry_source: TelemetrySource
    alert_latency_seconds: int | None
    control_owner_user_id: str
    remediation_follow_up: str
    contains_sensitive_data: bool = False
    raw_canary_value_present: bool = False


def validate_canary_dataset(dataset: CanaryDataset) -> None:
    _require_non_empty("dataset_id", dataset.dataset_id)
    _require_non_empty("synthetic_generation_note", dataset.synthetic_generation_note)
    if not dataset.data_classes:
        raise ValueError("canary_data_classes_required")
    if not dataset.canary_markers:
        raise ValueError("canary_markers_required")
    forbidden = tuple(data_class.value for data_class in dataset.data_classes if data_class in FORBIDDEN_DATA_CLASSES)
    if forbidden:
        raise ValueError("sensitive_data_forbidden:" + ",".join(sorted(forbidden)))
    if not set(dataset.data_classes).issubset({CanaryDataClass.SYNTHETIC, CanaryDataClass.CANARY}):
        raise ValueError("canary_dataset_must_be_synthetic")
    for marker in dataset.canary_markers:
        _require_non_empty("canary_marker", marker)


def validate_roe(roe: DlpRulesOfEngagement) -> None:
    _require_non_empty("roe_id", roe.roe_id)
    _require_non_empty("timezone_label", roe.timezone_label)
    _require_timezone(roe.window_start)
    _require_timezone(roe.window_end)
    if roe.window_start >= roe.window_end:
        raise ValueError("invalid_roe_time_window")
    for field_name, values in (
        ("source_systems", roe.source_systems),
        ("destination_systems", roe.destination_systems),
        ("data_labels", roe.data_labels),
        ("detection_stakeholders", roe.detection_stakeholders),
        ("emergency_stop_conditions", roe.emergency_stop_conditions),
    ):
        _require_non_empty_sequence(field_name, values)
    if roe.max_volume_bytes <= 0:
        raise ValueError("invalid_volume_cap")
    if roe.max_record_count <= 0:
        raise ValueError("invalid_record_count_cap")
    if not roe.allowed_protocols:
        raise ValueError("protocol_limits_required")


def evaluate_dlp_validation_request(request: DlpValidationRequest) -> DlpValidationDecision:
    try:
        _validate_request_identity(request)
    except ValueError as exc:
        return DlpValidationDecision(allowed=False, reason=DlpDecisionReason.INVALID_REQUEST, details=(str(exc),))
    if request.dataset is None:
        return DlpValidationDecision(allowed=False, reason=DlpDecisionReason.MISSING_CANARY_DATASET)
    try:
        validate_canary_dataset(request.dataset)
    except ValueError as exc:
        reason = DlpDecisionReason.SENSITIVE_DATA_FORBIDDEN if str(exc).startswith("sensitive_data_forbidden") else DlpDecisionReason.MISSING_CANARY_DATASET
        return DlpValidationDecision(allowed=False, reason=reason, details=(str(exc),))
    if request.roe is None:
        return DlpValidationDecision(allowed=False, reason=DlpDecisionReason.MISSING_ROE)
    try:
        validate_roe(request.roe)
    except ValueError as exc:
        if "emergency_stop_conditions" in str(exc):
            return DlpValidationDecision(allowed=False, reason=DlpDecisionReason.MISSING_STOP_CONDITION, details=(str(exc),))
        return DlpValidationDecision(allowed=False, reason=DlpDecisionReason.MISSING_ROE, details=(str(exc),))
    approval_gaps = _approval_gaps(request.approval)
    if approval_gaps:
        return DlpValidationDecision(allowed=False, reason=DlpDecisionReason.MISSING_APPROVAL, details=approval_gaps)
    monitoring_gaps = _monitoring_gaps(request.monitoring)
    if monitoring_gaps:
        reason = DlpDecisionReason.MISSING_MONITORING_OWNER if "monitoring_owner_user_id" in monitoring_gaps else DlpDecisionReason.MONITORING_NOT_READY
        return DlpValidationDecision(allowed=False, reason=reason, details=monitoring_gaps)
    stop_gaps = _stop_condition_gaps(request.roe)
    if stop_gaps:
        return DlpValidationDecision(allowed=False, reason=DlpDecisionReason.MISSING_STOP_CONDITION, details=stop_gaps)
    target_gaps = _target_scope_gaps(request.target_scope, request.roe)
    if target_gaps:
        return DlpValidationDecision(allowed=False, reason=DlpDecisionReason.MISSING_TARGET_SCOPE, details=target_gaps)
    return DlpValidationDecision(
        allowed=True,
        reason=DlpDecisionReason.APPROVED_FOR_REVIEW_QUEUE,
        details=("simulation_disabled_until_runner_policy_approved",),
        execution_enabled=False,
    )


def export_dlp_detection_evidence(evidence: DlpDetectionEvidence) -> dict[str, object]:
    for field_name, value in (
        ("evidence_id", evidence.evidence_id),
        ("validation_id", evidence.validation_id),
        ("control_owner_user_id", evidence.control_owner_user_id),
        ("remediation_follow_up", evidence.remediation_follow_up),
    ):
        _require_non_empty(field_name, value)
    if evidence.contains_sensitive_data:
        raise ValueError("sensitive_dlp_evidence_forbidden")
    if evidence.raw_canary_value_present:
        raise ValueError("raw_canary_value_forbidden")
    if evidence.alert_latency_seconds is not None and evidence.alert_latency_seconds < 0:
        raise ValueError("invalid_alert_latency")
    return {
        "evidence_id": evidence.evidence_id,
        "validation_id": evidence.validation_id,
        "detection_outcome": evidence.detection_outcome.value,
        "telemetry_source": evidence.telemetry_source.value,
        "alert_latency_seconds": evidence.alert_latency_seconds,
        "control_owner_user_id": evidence.control_owner_user_id,
        "remediation_follow_up": evidence.remediation_follow_up,
        "contains_sensitive_data": False,
        "raw_canary_value_present": False,
    }


def _validate_request_identity(request: DlpValidationRequest) -> None:
    for field_name, value in (
        ("validation_id", request.validation_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)


def _approval_gaps(approval: PurpleTeamApproval | None) -> tuple[str, ...]:
    if approval is None:
        return ("approval",)
    gaps = []
    for field_name, value in (
        ("approved_by_user_id", approval.approved_by_user_id),
        ("approval_ticket_id", approval.approval_ticket_id),
        ("monitoring_owner_user_id", approval.monitoring_owner_user_id),
    ):
        if not value or not value.strip():
            gaps.append(field_name)
    if approval.approved_at is None:
        gaps.append("approved_at")
    else:
        _require_timezone(approval.approved_at)
    return tuple(gaps)


def _monitoring_gaps(monitoring: MonitoringReadiness | None) -> tuple[str, ...]:
    if monitoring is None:
        return ("monitoring_readiness",)
    gaps = []
    for field_name, value in (
        ("monitoring_owner_user_id", monitoring.monitoring_owner_user_id),
        ("alert_route_id", monitoring.alert_route_id),
        ("control_owner_user_id", monitoring.control_owner_user_id),
    ):
        if not value or not value.strip():
            gaps.append(field_name)
    if not monitoring.telemetry_sources:
        gaps.append("telemetry_sources")
    if not monitoring.ready:
        gaps.append("monitoring_ready")
    return tuple(gaps)


def _stop_condition_gaps(roe: DlpRulesOfEngagement) -> tuple[str, ...]:
    if not roe.emergency_stop_conditions:
        return ("emergency_stop_conditions",)
    return tuple("emergency_stop_conditions" for condition in roe.emergency_stop_conditions if not condition.strip())


def _target_scope_gaps(scope: DlpTargetScope | None, roe: DlpRulesOfEngagement) -> tuple[str, ...]:
    if scope is None:
        return ("target_scope",)
    gaps = []
    if not scope.source_system_id or not scope.source_system_id.strip():
        gaps.append("source_system_id")
    elif scope.source_system_id not in roe.source_systems:
        gaps.append("source_system_outside_roe")
    if not scope.destination_system_id or not scope.destination_system_id.strip():
        gaps.append("destination_system_id")
    elif scope.destination_system_id not in roe.destination_systems:
        gaps.append("destination_system_outside_roe")
    if scope.protocol is None:
        gaps.append("protocol")
    elif scope.protocol not in roe.allowed_protocols:
        gaps.append("protocol_outside_roe")
    if scope.volume_bytes <= 0 or scope.volume_bytes > roe.max_volume_bytes:
        gaps.append("volume_cap")
    if scope.record_count <= 0 or scope.record_count > roe.max_record_count:
        gaps.append("record_count_cap")
    return tuple(gaps)


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty_sequence(field_name: str, values: tuple[str, ...]) -> None:
    if not values:
        raise ValueError(f"{field_name}_required")
    for value in values:
        _require_non_empty(field_name, value)


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
