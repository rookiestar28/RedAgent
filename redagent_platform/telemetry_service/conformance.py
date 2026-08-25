"""Reusable cross-service telemetry correlation and leak conformance kit."""

from __future__ import annotations

from dataclasses import dataclass
import json

from redagent_platform.telemetry_service.contracts import ServiceName, SignalKind, TelemetryEnvelope


FOUNDATION_SERVICES = frozenset({
    ServiceName.API, ServiceName.IDENTITY, ServiceName.DATABASE, ServiceName.TEMPORAL,
    ServiceName.POLICY, ServiceName.SECRET, ServiceName.EVIDENCE, ServiceName.RUNNER,
    ServiceName.QUOTA, ServiceName.CONTAINMENT, ServiceName.TELEMETRY, ServiceName.SIEM,
})
_FORBIDDEN = (
    "authorization", "bearer ", "cookie", "password", "private_key", "secret=",
    "token=", "prompt", "tool_arguments", "tool_result", "db.statement", "http.url",
)


@dataclass(frozen=True, kw_only=True)
class ConformanceReport:
    accepted: bool
    reason_code: str
    service_count: int
    signal_kinds: tuple[str, ...]
    correlation_id: str | None
    trace_id: str | None
    errors: tuple[str, ...]


def validate_foundation_chain(envelopes: tuple[TelemetryEnvelope, ...]) -> ConformanceReport:
    errors: list[str] = []
    if not envelopes:
        errors.append("telemetry_chain_required")
    services = {item.service_name for item in envelopes}
    missing = FOUNDATION_SERVICES - services
    errors.extend(f"telemetry_service_missing:{item.value}" for item in sorted(missing, key=lambda item: item.value))
    kinds = {item.kind for item in envelopes}
    for kind in SignalKind:
        if kind not in kinds:
            errors.append(f"telemetry_signal_kind_missing:{kind.value}")
    correlations = {item.correlation_id for item in envelopes}
    traces = {item.trace_id for item in envelopes}
    if len(correlations) != 1:
        errors.append("telemetry_correlation_chain_broken")
    if len(traces) != 1:
        errors.append("telemetry_trace_chain_broken")
    if len({item.event_id for item in envelopes}) != len(envelopes):
        errors.append("telemetry_event_id_duplicate")
    for envelope in envelopes:
        serialized = json.dumps(
            envelope.to_otlp_attributes(), sort_keys=True, separators=(",", ":"),
        ).lower()
        if any(marker in serialized for marker in _FORBIDDEN):
            errors.append(f"telemetry_sensitive_value_detected:{envelope.event_id}")
    return ConformanceReport(
        accepted=not errors,
        reason_code="telemetry_foundation_chain_accepted" if not errors else "telemetry_foundation_chain_rejected",
        service_count=len(services), signal_kinds=tuple(sorted(item.value for item in kinds)),
        correlation_id=next(iter(correlations)) if len(correlations) == 1 else None,
        trace_id=next(iter(traces)) if len(traces) == 1 else None,
        errors=tuple(errors),
    )
