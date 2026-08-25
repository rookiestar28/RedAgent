"""Network assessment ROE and passive/inventory evidence contracts."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.domain import EvidenceKind
from redagent_platform.evidence_chain import (
    EvidenceAccessPolicy,
    EvidenceChain,
    EvidenceRecord,
    RedactionStatus,
    RetentionClass,
)


class NetworkAssessmentMode(str, Enum):
    INVENTORY_ONLY = "inventory_only"
    PASSIVE_METADATA = "passive_metadata"
    ACTIVE_PROBE = "active_probe"


class NetworkForbiddenActivity(str, Enum):
    INTERNET_WIDE_SCAN = "internet_wide_scan"
    DOS_TEST = "dos_test"
    CREDENTIAL_ATTACK = "credential_attack"
    EXPLOIT_VALIDATION = "exploit_validation"


@dataclass(frozen=True, kw_only=True)
class NetworkRange:
    cidr: str
    ownership_attested: bool
    description: str


@dataclass(frozen=True, kw_only=True)
class HostAllowlistEntry:
    value: str
    ownership_attested: bool
    description: str


@dataclass(frozen=True, kw_only=True)
class NetworkROE:
    organization_id: str
    engagement_id: str
    approved_by_user_id: str
    network_ranges: tuple[NetworkRange, ...]
    host_allowlist: tuple[HostAllowlistEntry, ...]
    window_start: datetime
    window_end: datetime
    max_rate_per_second: float
    max_connection_count: int
    max_concurrent_jobs: int
    emergency_stop_contact: str
    local_lab_validated: bool
    allowed_modes: tuple[NetworkAssessmentMode, ...]


@dataclass(frozen=True, kw_only=True)
class NetworkAssessmentRequest:
    job_id: str
    organization_id: str
    engagement_id: str
    target: str
    mode: NetworkAssessmentMode
    requested_at: datetime
    projected_connection_count: int
    requested_rate_per_second: float
    requested_activities: tuple[NetworkForbiddenActivity, ...]
    operator_user_id: str
    runner_id: str


@dataclass(frozen=True, kw_only=True)
class NetworkAssessmentDecision:
    allowed: bool
    reason: str
    normalized_target: str | None
    projected_connection_count: int


@dataclass(frozen=True, kw_only=True)
class NetworkEvidenceObservation:
    job_id: str
    organization_id: str
    scope_summary: str
    method: NetworkAssessmentMode
    request_count: int
    connection_count: int
    started_at: datetime
    ended_at: datetime
    operator_user_id: str
    runner_id: str
    redaction_status: RedactionStatus
    notes: str


@dataclass(frozen=True, kw_only=True)
class NetworkEvidenceResult:
    chain: EvidenceChain
    record: EvidenceRecord
    content: dict[str, object]


PASSIVE_NETWORK_MODES = frozenset({NetworkAssessmentMode.INVENTORY_ONLY, NetworkAssessmentMode.PASSIVE_METADATA})


def evaluate_network_assessment(roe: NetworkROE, request: NetworkAssessmentRequest) -> NetworkAssessmentDecision:
    validate_network_roe(roe)
    _validate_request(request)
    if request.organization_id != roe.organization_id:
        return _deny("organization_mismatch", request)
    if request.engagement_id != roe.engagement_id:
        return _deny("engagement_mismatch", request)
    if request.mode not in roe.allowed_modes:
        return _deny("network_mode_not_allowed", request)
    if request.mode not in PASSIVE_NETWORK_MODES:
        return _deny("active_network_probe_not_implemented", request)
    if request.requested_activities:
        return _deny("forbidden_network_activity_requested", request)
    if not (roe.window_start <= request.requested_at < roe.window_end):
        return _deny("outside_testing_window", request)
    if request.projected_connection_count > roe.max_connection_count:
        return _deny("connection_count_exceeded", request)
    if request.requested_rate_per_second > roe.max_rate_per_second:
        return _deny("rate_limit_exceeded", request)
    normalized_target = _normalize_target(request.target)
    if normalized_target not in _normalized_hosts(roe.host_allowlist) and not _target_in_attested_range(normalized_target, roe.network_ranges):
        return _deny("target_not_allowlisted", request, normalized_target)
    return NetworkAssessmentDecision(
        allowed=True,
        reason="network_passive_inventory_allowed",
        normalized_target=normalized_target,
        projected_connection_count=request.projected_connection_count,
    )


def validate_network_roe(roe: NetworkROE) -> None:
    for field_name, value in (
        ("organization_id", roe.organization_id),
        ("engagement_id", roe.engagement_id),
        ("approved_by_user_id", roe.approved_by_user_id),
        ("emergency_stop_contact", roe.emergency_stop_contact),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(roe.window_start)
    _require_timezone(roe.window_end)
    if roe.window_start >= roe.window_end:
        raise ValueError("invalid_network_testing_window")
    if not roe.network_ranges:
        raise ValueError("network_ranges_required")
    if not roe.host_allowlist:
        raise ValueError("host_allowlist_required")
    if roe.max_rate_per_second <= 0:
        raise ValueError("invalid_network_rate_limit")
    if roe.max_connection_count <= 0:
        raise ValueError("invalid_network_connection_limit")
    if roe.max_concurrent_jobs <= 0:
        raise ValueError("invalid_network_concurrency_limit")
    if not roe.local_lab_validated:
        raise ValueError("local_lab_validation_required")
    if not roe.allowed_modes:
        raise ValueError("network_allowed_modes_required")
    for network_range in roe.network_ranges:
        _validate_network_range(network_range)
    for host in roe.host_allowlist:
        _validate_host_allowlist_entry(host)


def append_network_evidence(
    *,
    chain: EvidenceChain,
    observation: NetworkEvidenceObservation,
    evidence_id: str,
) -> NetworkEvidenceResult:
    _validate_observation(observation)
    content: dict[str, object] = {
        "scope": observation.scope_summary,
        "method": observation.method.value,
        "request_count": observation.request_count,
        "connection_count": observation.connection_count,
        "started_at": observation.started_at.isoformat(),
        "ended_at": observation.ended_at.isoformat(),
        "operator_user_id": observation.operator_user_id,
        "runner_id": observation.runner_id,
        "redaction_status": observation.redaction_status.value,
        "notes": observation.notes,
    }
    next_chain = chain.append_evidence_record(
        evidence_id=evidence_id,
        organization_id=observation.organization_id,
        source_job_id=observation.job_id,
        kind=EvidenceKind.SCANNER_OUTPUT,
        created_at=observation.ended_at,
        redaction_status=observation.redaction_status,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=json.dumps(content, sort_keys=True, default=str).encode("utf-8"),
        contains_sensitive_capture=observation.redaction_status is RedactionStatus.REDACTED,
        metadata={
            "module": "network_assessment",
            "method": observation.method.value,
            "connection_count": observation.connection_count,
            "operator_user_id": observation.operator_user_id,
            "runner_id": observation.runner_id,
        },
    )
    return NetworkEvidenceResult(chain=next_chain, record=next_chain.evidence_records[-1], content=content)


def _validate_network_range(network_range: NetworkRange) -> None:
    _require_non_empty("network_range_description", network_range.description)
    try:
        network = ipaddress.ip_network(network_range.cidr, strict=False)
    except ValueError as exc:
        raise ValueError("invalid_network_range") from exc
    if network.prefixlen == 0:
        raise ValueError("internet_wide_scanning_forbidden")
    if not network_range.ownership_attested:
        raise ValueError("third_party_network_range_forbidden")


def _validate_host_allowlist_entry(host: HostAllowlistEntry) -> None:
    _require_non_empty("host_allowlist_value", host.value)
    _require_non_empty("host_allowlist_description", host.description)
    if "*" in host.value or "/" in host.value:
        raise ValueError("explicit_host_allowlist_required")
    if not host.ownership_attested:
        raise ValueError("third_party_host_forbidden")


def _validate_request(request: NetworkAssessmentRequest) -> None:
    for field_name, value in (
        ("job_id", request.job_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("target", request.target),
        ("operator_user_id", request.operator_user_id),
        ("runner_id", request.runner_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    if request.projected_connection_count <= 0:
        raise ValueError("invalid_projected_connection_count")
    if request.requested_rate_per_second <= 0:
        raise ValueError("invalid_requested_network_rate")


def _validate_observation(observation: NetworkEvidenceObservation) -> None:
    for field_name, value in (
        ("job_id", observation.job_id),
        ("organization_id", observation.organization_id),
        ("scope_summary", observation.scope_summary),
        ("operator_user_id", observation.operator_user_id),
        ("runner_id", observation.runner_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(observation.started_at)
    _require_timezone(observation.ended_at)
    if observation.started_at > observation.ended_at:
        raise ValueError("invalid_network_observation_window")
    if observation.request_count < 0 or observation.connection_count < 0:
        raise ValueError("invalid_network_counts")


def _target_in_attested_range(target: str, ranges: tuple[NetworkRange, ...]) -> bool:
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network_range.cidr, strict=False) for network_range in ranges)


def _normalized_hosts(hosts: tuple[HostAllowlistEntry, ...]) -> frozenset[str]:
    return frozenset(_normalize_target(host.value) for host in hosts)


def _normalize_target(target: str) -> str:
    stripped = target.strip().lower().rstrip(".")
    _require_non_empty("target", stripped)
    return stripped


def _deny(
    reason: str,
    request: NetworkAssessmentRequest,
    normalized_target: str | None = None,
) -> NetworkAssessmentDecision:
    return NetworkAssessmentDecision(
        allowed=False,
        reason=reason,
        normalized_target=normalized_target,
        projected_connection_count=request.projected_connection_count,
    )


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
