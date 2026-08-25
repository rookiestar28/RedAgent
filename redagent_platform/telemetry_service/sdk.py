"""Narrow OpenTelemetry SDK adapter for closed RedAgent envelopes."""

from __future__ import annotations

from opentelemetry import context as otel_context
from opentelemetry.trace import (
    NonRecordingSpan, SpanContext, SpanKind, Status, StatusCode, TraceFlags,
    set_span_in_context,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.metrics import MeterProvider

from redagent_platform.telemetry_service.contracts import (
    SignalKind, SignalOutcome, TelemetryEnvelope,
)


class OpenTelemetrySink:
    """Translate only the reviewed envelope; never accept caller attribute maps."""

    def __init__(self, *, provider: TracerProvider, meter_provider: MeterProvider | None = None) -> None:
        if not isinstance(provider, TracerProvider):
            raise ValueError("telemetry_tracer_provider_required")
        self._provider = provider
        self._meter_provider = meter_provider

    def emit(self, envelope: TelemetryEnvelope) -> None:
        if not isinstance(envelope, TelemetryEnvelope):
            raise ValueError("telemetry_envelope_required")
        tracer = self._provider.get_tracer(
            "redagent.telemetry", instrumenting_library_version=envelope.service_version,
        )
        parent_span_id = envelope.parent_span_id or envelope.span_id
        parent = SpanContext(
            trace_id=int(envelope.trace_id, 16), span_id=int(parent_span_id, 16),
            is_remote=envelope.parent_span_id is not None,
            trace_flags=TraceFlags(
                TraceFlags.SAMPLED if envelope.sampled else TraceFlags.DEFAULT
            ),
            trace_state=None,
        )
        parent_context = set_span_in_context(NonRecordingSpan(parent), otel_context.Context())
        started_ns = int(envelope.occurred_at.timestamp() * 1_000_000_000)
        duration_ns = int(envelope.duration_ms or 0) * 1_000_000
        span = tracer.start_span(
            envelope.operation, context=parent_context, kind=SpanKind.INTERNAL,
            start_time=started_ns,
        )
        try:
            attributes: dict[str, str | int | bool] = {
                **envelope.to_otlp_attributes(),
                "service.namespace": "redagent",
                "service.name": envelope.service_name.value,
                "service.version": envelope.service_version,
                "service.instance.id": envelope.service_instance_id,
                "deployment.environment.name": "local-conformance",
                "redagent.trace.id": envelope.trace_id,
                "redagent.span.id": envelope.span_id,
                "redagent.sampled": envelope.sampled,
            }
            if envelope.parent_span_id is not None:
                attributes["redagent.parent_span.id"] = envelope.parent_span_id
            if envelope.duration_ms is not None:
                attributes["redagent.duration_ms"] = envelope.duration_ms
            if envelope.measurement_name is not None:
                attributes["redagent.measurement.name"] = envelope.measurement_name
                attributes["redagent.measurement.value"] = int(envelope.measurement_value or 0)
            span.set_attributes(attributes)
            if envelope.kind is SignalKind.EVENT:
                span.add_event("redagent.security_event", attributes=envelope.to_otlp_attributes(), timestamp=started_ns)
            elif envelope.kind is SignalKind.METRIC:
                if self._meter_provider is None:
                    raise ValueError("telemetry_meter_provider_required")
                meter = self._meter_provider.get_meter(
                    "redagent.telemetry", version=envelope.service_version,
                )
                histogram = meter.create_histogram(
                    name=f"redagent.{envelope.measurement_name}",
                    unit="1", description="Closed RedAgent integer measurement",
                )
                histogram.record(
                    int(envelope.measurement_value or 0),
                    attributes=envelope.to_otlp_attributes(),
                )
                span.add_event("redagent.metric_measurement", timestamp=started_ns)
            status = StatusCode.OK if envelope.outcome is SignalOutcome.SUCCESS else StatusCode.ERROR
            span.set_status(Status(status, envelope.reason_code))
        finally:
            span.end(end_time=started_ns + duration_ns)
