"""Closed, metadata-only compat_102 telemetry contracts independent of OTel SDK types."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re


TELEMETRY_SCHEMA = "redagent.telemetry/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CODE = re.compile(r"^[a-z][a-z0-9_]{0,99}$")
_OPERATION = re.compile(r"^[a-z][a-z0-9_.]{2,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,31}$")
_TRACE = re.compile(r"^[0-9a-f]{32}$")
_SPAN = re.compile(r"^[0-9a-f]{16}$")
_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
MEASUREMENT_NAMES = frozenset({
    "api_availability", "api_request_duration_ms", "emergency_stop_ack_ms",
    "evidence_failure", "idle_cpu_millipercent", "idle_ram_mib", "lease_failure",
    "policy_failure", "queue_depth", "request_count", "runner_heartbeat_age_ms",
    "security_denial", "telemetry_export_backlog", "telemetry_export_failure",
    "workflow_activity_duration_ms",
})


class SignalKind(str, Enum):
    SPAN = "span"
    METRIC = "metric"
    EVENT = "event"


class SignalOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ServiceName(str, Enum):
    API = "api"
    IDENTITY = "identity"
    DATABASE = "database"
    TEMPORAL = "temporal"
    POLICY = "policy"
    SECRET = "secret"  # pragma: allowlist secret - closed telemetry service enum
    EVIDENCE = "evidence"
    RUNNER = "runner"
    QUOTA = "quota"
    CONTAINMENT = "containment"
    TELEMETRY = "telemetry"
    SIEM = "siem"
    ZAP = "zap"
    NUCLEI = "nuclei"
    API_DIFFERENTIAL = "api_differential"
    NETWORK_ASSESSMENT = "network_assessment"
    CLOUD_POSTURE = "cloud_posture"


class ResourceType(str, Enum):
    API_REQUEST = "api_request"
    JOB = "job"
    CAMPAIGN = "campaign"
    WORKFLOW = "workflow"
    POLICY_DECISION = "policy_decision"
    SECRET_LEASE = "secret_lease"  # pragma: allowlist secret - closed resource enum
    EVIDENCE_ARTIFACT = "evidence_artifact"
    RUNNER = "runner"
    QUOTA = "quota"
    CONTAINMENT_CONTROL = "containment_control"
    INCIDENT = "incident"
    SLO = "slo"
    EXPORT = "export"
    ZAP_RUN = "zap_run"
    NUCLEI_RUN = "nuclei_run"
    API_DIFFERENTIAL_RUN = "api_differential_run"
    NETWORK_RUN = "network_run"
    CLOUD_RUN = "cloud_run"


@dataclass(frozen=True, kw_only=True)
class TraceContext:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    remote_sampled: bool
    sampled: bool

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{'01' if self.sampled else '00'}"


@dataclass(frozen=True, kw_only=True)
class TelemetryEnvelope:
    schema: str
    event_id: str
    tenant_id: str
    correlation_id: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    sampled: bool
    kind: SignalKind
    service_name: ServiceName
    service_version: str
    service_instance_id: str
    resource_type: ResourceType
    resource_id: str
    operation: str
    outcome: SignalOutcome
    reason_code: str
    occurred_at: datetime
    duration_ms: int | None
    measurement_name: str | None
    measurement_value: int | None

    def __post_init__(self) -> None:
        if self.schema != TELEMETRY_SCHEMA:
            raise ValueError("telemetry_schema_invalid")
        for field_name, value in (
            ("event_id", self.event_id), ("tenant_id", self.tenant_id),
            ("correlation_id", self.correlation_id),
            ("service_instance_id", self.service_instance_id),
        ):
            _require_id(field_name, value)
        _require_hex("trace_id", self.trace_id, _TRACE)
        _require_hex("span_id", self.span_id, _SPAN)
        if self.parent_span_id is not None:
            _require_hex("parent_span_id", self.parent_span_id, _SPAN)
        if not isinstance(self.sampled, bool) or not isinstance(self.kind, SignalKind):
            raise ValueError("signal_kind_invalid")
        if not isinstance(self.service_name, ServiceName) or not isinstance(self.resource_type, ResourceType):
            raise ValueError("service_resource_type_invalid")
        if not isinstance(self.service_version, str) or _VERSION.fullmatch(self.service_version) is None:
            raise ValueError("service_version_invalid")
        _require_id("resource_id", self.resource_id)
        if not isinstance(self.operation, str) or _OPERATION.fullmatch(self.operation) is None:
            raise ValueError("operation_invalid")
        if not isinstance(self.outcome, SignalOutcome):
            raise ValueError("outcome_invalid")
        if not isinstance(self.reason_code, str) or _CODE.fullmatch(self.reason_code) is None:
            raise ValueError("reason_code_invalid")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at_invalid")
        if self.duration_ms is not None and not _nonnegative_int(self.duration_ms):
            raise ValueError("duration_ms_invalid")
        if self.measurement_name is None:
            if self.measurement_value is not None:
                raise ValueError("measurement_name_invalid")
        elif self.measurement_name not in MEASUREMENT_NAMES:
            raise ValueError("measurement_name_invalid")
        elif not _nonnegative_int(self.measurement_value):
            raise ValueError("measurement_value_invalid")

    @property
    def canonical_hash(self) -> str:
        payload = asdict(self)
        payload.update({
            "kind": self.kind.value,
            "service_name": self.service_name.value,
            "resource_type": self.resource_type.value,
            "outcome": self.outcome.value,
            "occurred_at": self.occurred_at.isoformat(),
        })
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_otlp_attributes(self) -> dict[str, str]:
        return {
            "redagent.schema": self.schema,
            "redagent.event.id": self.event_id,
            "redagent.tenant.id": self.tenant_id,
            "redagent.correlation.id": self.correlation_id,
            "redagent.resource.type": self.resource_type.value,
            "redagent.resource.id": self.resource_id,
            "redagent.operation": self.operation,
            "redagent.outcome": self.outcome.value,
            "redagent.reason_code": self.reason_code,
        }


def continue_trace_context(
    incoming_traceparent: str | None,
    *,
    generated_trace_id: str,
    generated_span_id: str,
    locally_sampled: bool,
    baggage: str | None = None,
) -> TraceContext:
    if baggage is not None and baggage.strip():
        # CRITICAL: baggage is caller-controlled content and cannot carry RedAgent authority.
        raise ValueError("telemetry_baggage_forbidden")
    _require_hex("generated_trace_id", generated_trace_id, _TRACE)
    _require_hex("generated_span_id", generated_span_id, _SPAN)
    matched = _TRACEPARENT.fullmatch(incoming_traceparent.strip()) if isinstance(incoming_traceparent, str) else None
    if matched is None or set(matched.group(1)) == {"0"} or set(matched.group(2)) == {"0"}:
        return TraceContext(
            trace_id=generated_trace_id, span_id=generated_span_id,
            parent_span_id=None, remote_sampled=False, sampled=locally_sampled,
        )
    trace_id, parent_id, flags = matched.groups()
    return TraceContext(
        trace_id=trace_id, span_id=generated_span_id, parent_span_id=parent_id,
        remote_sampled=(int(flags, 16) & 1) == 1, sampled=locally_sampled,
    )


def _require_id(field_name: str, value: object) -> None:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{field_name}_invalid")


def _require_hex(field_name: str, value: object, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None or set(value) == {"0"}:
        raise ValueError(f"{field_name}_invalid")


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
