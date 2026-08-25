from __future__ import annotations

from datetime import datetime, timezone

import pytest

from redagent_platform.telemetry_service.contracts import (
    TELEMETRY_SCHEMA,
    ResourceType,
    ServiceName,
    SignalKind,
    SignalOutcome,
    TelemetryEnvelope,
    continue_trace_context,
)
from redagent_platform.telemetry_service.siem import (
    build_ocsf_delivery,
    IncidentActivity,
    IncidentSeverity,
    IncidentStatus,
    map_incident_to_ocsf,
)


NOW = datetime(2026, 7, 11, 2, 0, tzinfo=timezone.utc)
TRACE_ID = "1" * 32
SPAN_ID = "2" * 16


def _envelope(**changes: object) -> TelemetryEnvelope:
    values: dict[str, object] = {
        "schema": TELEMETRY_SCHEMA,
        "event_id": "event-1",
        "tenant_id": "tenant-1",
        "correlation_id": "correlation-1",
        "trace_id": TRACE_ID,
        "span_id": SPAN_ID,
        "parent_span_id": None,
        "sampled": True,
        "kind": SignalKind.EVENT,
        "service_name": ServiceName.CONTAINMENT,
        "service_version": "0.1.0",
        "service_instance_id": "containment-1",
        "resource_type": ResourceType.INCIDENT,
        "resource_id": "incident-1",
        "operation": "containment.incident.opened",
        "outcome": SignalOutcome.FAILURE,
        "reason_code": "containment_incomplete",
        "occurred_at": NOW,
        "duration_ms": None,
        "measurement_name": None,
        "measurement_value": None,
    }
    values.update(changes)
    return TelemetryEnvelope(**values)


def test_closed_envelope_is_stable_metadata_only_and_hashable() -> None:
    envelope = _envelope()
    assert envelope.canonical_hash == _envelope().canonical_hash
    assert envelope.to_otlp_attributes() == {
        "redagent.schema": "redagent.telemetry/v1",
        "redagent.event.id": "event-1",
        "redagent.tenant.id": "tenant-1",
        "redagent.correlation.id": "correlation-1",
        "redagent.resource.type": "incident",
        "redagent.resource.id": "incident-1",
        "redagent.operation": "containment.incident.opened",
        "redagent.outcome": "failure",
        "redagent.reason_code": "containment_incomplete",
    }
    assert not set(TelemetryEnvelope.__dataclass_fields__).intersection(
        {
            "attributes", "body", "baggage", "command", "credential", "cookie",
            "db_statement", "evidence_body", "headers", "payload", "private_key",
            "prompt", "response", "target", "token", "tool_arguments", "tool_result", "url",
        }
    )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"schema": "redagent.telemetry/v2"}, "telemetry_schema_invalid"),
        ({"resource_id": "https://unsafe.example/path"}, "resource_id_invalid"),
        ({"operation": "arbitrary command --token value"}, "operation_invalid"),
        ({"reason_code": "password=secret"}, "reason_code_invalid"),
        ({"duration_ms": -1}, "duration_ms_invalid"),
        ({"measurement_name": "request.url"}, "measurement_name_invalid"),
        ({"measurement_name": "request_count", "measurement_value": 1.5}, "measurement_value_invalid"),
    ],
)
def test_envelope_rejects_content_and_unbounded_values(changes: dict[str, object], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        _envelope(**changes)


def test_traceparent_is_correlation_only_and_remote_sampling_is_not_authority() -> None:
    context = continue_trace_context(
        f"00-{TRACE_ID}-{SPAN_ID}-01",
        generated_trace_id="3" * 32,
        generated_span_id="4" * 16,
        locally_sampled=False,
    )
    assert context.trace_id == TRACE_ID
    assert context.parent_span_id == SPAN_ID
    assert context.span_id == "4" * 16
    assert context.remote_sampled is True
    assert context.sampled is False
    assert context.traceparent == f"00-{TRACE_ID}-{'4' * 16}-00"

    regenerated = continue_trace_context(
        "00-00000000000000000000000000000000-0000000000000000-01",
        generated_trace_id="5" * 32,
        generated_span_id="6" * 16,
        locally_sampled=True,
    )
    assert regenerated.trace_id == "5" * 32
    assert regenerated.parent_span_id is None
    assert regenerated.remote_sampled is False


def test_ocsf_180_incident_mapping_is_pinned_minimal_and_content_free() -> None:
    mapped = map_incident_to_ocsf(
        _envelope(),
        severity=IncidentSeverity.HIGH,
        activity=IncidentActivity.CREATE,
        status=IncidentStatus.NEW,
        assignee_id="operator-2",
    )
    assert mapped["category_uid"] == 2
    assert mapped["class_uid"] == 2005
    assert mapped["type_uid"] == 200501
    assert mapped["metadata"]["version"] == "1.8.0"
    assert mapped["metadata"]["profiles"] == ["incident"]
    assert mapped["finding_info_list"] == [{"uid": "event-1", "title": "containment_incomplete"}]
    assert mapped["assignee"] == {"uid": "operator-2"}
    assert mapped["metadata"]["original_event_uid"] == "event-1"
    assert mapped["metadata"]["correlation_uid"] == "correlation-1"
    assert mapped["organization"] == {"uid": "tenant-1"}
    assert mapped["trace"] == {"uid": TRACE_ID}
    assert not set(mapped).intersection({"comment", "desc", "message", "raw_data", "src_url", "vendor_attributes"})

    delivery = build_ocsf_delivery(
        _envelope(), destination_alias="local-siem", severity=IncidentSeverity.HIGH,
        activity=IncidentActivity.CREATE, status=IncidentStatus.NEW, assignee_id=None,
    )
    assert delivery.idempotency_key.startswith("ocsf:event-1:")
    assert len(delivery.payload_sha256) == 64
    assert set(delivery.__dataclass_fields__) == {
        "destination_alias", "event_id", "idempotency_key", "payload_sha256", "payload",
    }
    with pytest.raises(ValueError, match="siem_destination_alias_invalid"):
        build_ocsf_delivery(
            _envelope(), destination_alias="https://caller.invalid",
            severity=IncidentSeverity.HIGH, activity=IncidentActivity.CREATE,
            status=IncidentStatus.NEW, assignee_id=None,
        )


def test_ocsf_mapper_rejects_non_event_or_tenant_mismatched_assignment() -> None:
    with pytest.raises(ValueError, match="ocsf_incident_event_required"):
        map_incident_to_ocsf(
            _envelope(kind=SignalKind.METRIC),
            severity=IncidentSeverity.HIGH,
            activity=IncidentActivity.CREATE,
            status=IncidentStatus.NEW,
            assignee_id="operator-2",
        )
    with pytest.raises(ValueError, match="ocsf_assignee_invalid"):
        map_incident_to_ocsf(
            _envelope(),
            severity=IncidentSeverity.HIGH,
            activity=IncidentActivity.CREATE,
            status=IncidentStatus.NEW,
            assignee_id="operator@example.invalid",
        )
