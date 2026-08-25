from __future__ import annotations

from datetime import datetime, timezone

from redagent_platform.telemetry_service.catalog import (
    foundation_alert_rules, foundation_objectives, foundation_runbooks,
    validate_foundation_catalog,
)
from redagent_platform.telemetry_service.conformance import (
    FOUNDATION_SERVICES, validate_foundation_chain,
)
from redagent_platform.telemetry_service.contracts import (
    MEASUREMENT_NAMES, TELEMETRY_SCHEMA, ResourceType, ServiceName,
    SignalKind, SignalOutcome, TelemetryEnvelope,
)


NOW = datetime(2026, 7, 11, 9, 0, tzinfo=timezone.utc)


def test_foundation_objectives_alerts_and_runbooks_are_complete_and_closed() -> None:
    assert validate_foundation_catalog() == ()
    assert {item.measurement_name for item in foundation_objectives()} == MEASUREMENT_NAMES
    runbooks = {item.runbook_id for item in foundation_runbooks()}
    assert runbooks == {item.runbook_id for item in foundation_alert_rules()}
    assert len(foundation_alert_rules()) >= 14


def test_single_foundation_chain_covers_every_service_and_signal_kind() -> None:
    services = sorted(FOUNDATION_SERVICES, key=lambda item: item.value)
    envelopes = tuple(_envelope(service, index) for index, service in enumerate(services))
    report = validate_foundation_chain(envelopes)
    assert report.accepted
    assert report.service_count == len(FOUNDATION_SERVICES)
    assert report.signal_kinds == ("event", "metric", "span")
    assert report.correlation_id == "r102-foundation-chain"
    assert report.trace_id == "c" * 32


def test_chain_rejects_missing_service_and_correlation_drift() -> None:
    services = sorted(FOUNDATION_SERVICES, key=lambda item: item.value)
    envelopes = tuple(_envelope(service, index) for index, service in enumerate(services[:-1]))
    drifted = TelemetryEnvelope(
        **{
            **_envelope(services[-1], len(services)).__dict__,
            "correlation_id": "drifted-correlation",
        }
    )
    report = validate_foundation_chain((*envelopes, drifted))
    assert not report.accepted
    assert "telemetry_correlation_chain_broken" in report.errors


def _envelope(service: ServiceName, index: int) -> TelemetryEnvelope:
    kind = (SignalKind.SPAN, SignalKind.METRIC, SignalKind.EVENT)[index % 3]
    return TelemetryEnvelope(
        schema=TELEMETRY_SCHEMA, event_id=f"event-{service.value}", tenant_id="tenant-r102",
        correlation_id="r102-foundation-chain", trace_id="c" * 32,
        span_id=f"{index + 1:016x}", parent_span_id=None, sampled=True, kind=kind,
        service_name=service, service_version="0.1.0",
        service_instance_id=f"{service.value}-local-1", resource_type=ResourceType.API_REQUEST,
        resource_id=f"resource-{service.value}", operation=f"{service.value}.conformance.checked",
        outcome=SignalOutcome.SUCCESS, reason_code="conformance_passed", occurred_at=NOW,
        duration_ms=1 if kind is SignalKind.SPAN else None,
        measurement_name="request_count" if kind is SignalKind.METRIC else None,
        measurement_value=1 if kind is SignalKind.METRIC else None,
    )
