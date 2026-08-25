from __future__ import annotations

from datetime import datetime, timezone

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from redagent_platform.telemetry_service.contracts import (
    TELEMETRY_SCHEMA, ResourceType, ServiceName, SignalKind, SignalOutcome, TelemetryEnvelope,
)
from redagent_platform.telemetry_service.sdk import OpenTelemetrySink


NOW = datetime(2026, 7, 11, 6, 0, tzinfo=timezone.utc)


def test_closed_envelope_is_emitted_as_resource_identified_content_free_span() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    sink = OpenTelemetrySink(provider=provider)
    envelope = TelemetryEnvelope(
        schema=TELEMETRY_SCHEMA, event_id="event-r102-sdk", tenant_id="tenant-r102",
        correlation_id="correlation-r102", trace_id="1" * 32, span_id="2" * 16,
        parent_span_id=None, sampled=True, kind=SignalKind.EVENT,
        service_name=ServiceName.POLICY, service_version="0.1.0",
        service_instance_id="policy-local-1", resource_type=ResourceType.POLICY_DECISION,
        resource_id="decision-r102", operation="policy.decision.denied",
        outcome=SignalOutcome.DENIED, reason_code="scope_denied", occurred_at=NOW,
        duration_ms=12, measurement_name=None, measurement_value=None,
    )
    sink.emit(envelope)
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "policy.decision.denied"
    assert span.attributes["redagent.schema"] == TELEMETRY_SCHEMA
    assert span.attributes["service.name"] == "policy"
    assert span.attributes["redagent.reason_code"] == "scope_denied"
    assert tuple(event.name for event in span.events) == ("redagent.security_event",)
    serialized = repr(span.attributes).lower()
    for forbidden in ("authorization", "cookie", "password", "prompt", "db.statement", "http.url"):
        assert forbidden not in serialized


def test_metric_envelope_records_only_allowlisted_integer_measurement() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    sink = OpenTelemetrySink(provider=provider, meter_provider=MeterProvider(metric_readers=[reader]))
    sink.emit(TelemetryEnvelope(
        schema=TELEMETRY_SCHEMA, event_id="event-r102-metric", tenant_id="tenant-r102",
        correlation_id="correlation-r102", trace_id="3" * 32, span_id="4" * 16,
        parent_span_id=None, sampled=True, kind=SignalKind.METRIC,
        service_name=ServiceName.TELEMETRY, service_version="0.1.0",
        service_instance_id="telemetry-local-1", resource_type=ResourceType.EXPORT,
        resource_id="export-r102", operation="telemetry.export.backlog",
        outcome=SignalOutcome.DEGRADED, reason_code="export_backlog", occurred_at=NOW,
        duration_ms=None, measurement_name="telemetry_export_backlog", measurement_value=7,
    ))
    attributes = exporter.get_finished_spans()[0].attributes
    assert attributes["redagent.measurement.name"] == "telemetry_export_backlog"
    assert attributes["redagent.measurement.value"] == 7
    metrics = reader.get_metrics_data().resource_metrics[0].scope_metrics[0].metrics
    assert [metric.name for metric in metrics] == ["redagent.telemetry_export_backlog"]
    assert metrics[0].data.data_points[0].sum == 7


def test_metric_envelope_fails_closed_without_a_metrics_provider() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    envelope = TelemetryEnvelope(
        schema=TELEMETRY_SCHEMA, event_id="event-r102-no-meter", tenant_id="tenant-r102",
        correlation_id="correlation-r102", trace_id="9" * 32, span_id="a" * 16,
        parent_span_id=None, sampled=True, kind=SignalKind.METRIC,
        service_name=ServiceName.TELEMETRY, service_version="0.1.0",
        service_instance_id="telemetry-local-1", resource_type=ResourceType.EXPORT,
        resource_id="export-r102", operation="telemetry.export.backlog",
        outcome=SignalOutcome.DEGRADED, reason_code="export_backlog", occurred_at=NOW,
        duration_ms=None, measurement_name="telemetry_export_backlog", measurement_value=7,
    )
    import pytest
    with pytest.raises(ValueError, match="telemetry_meter_provider_required"):
        OpenTelemetrySink(provider=provider).emit(envelope)
