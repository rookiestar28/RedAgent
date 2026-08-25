from datetime import datetime, timezone

from redagent_platform.telemetry_service.contracts import ResourceType, ServiceName, SignalOutcome
from redagent_platform.telemetry_service.projector import AuditProjection, FoundationTelemetryProjector


def test_zap_audit_namespace_projects_to_closed_r102_service_and_resource() -> None:
    envelope = FoundationTelemetryProjector(
        service_version="0.1.0", instance_id="zap-adapter-local-1",
    ).project(AuditProjection(
        audit_id="audit-r104", tenant_id="tenant-r104", correlation_id="correlation-r104",
        action="zap.run.accepted", subject_type="zap", subject_id="run-r104",
        outcome=SignalOutcome.SUCCESS, occurred_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
    ))
    assert envelope.service_name is ServiceName.ZAP
    assert envelope.resource_type is ResourceType.ZAP_RUN
    assert envelope.operation == "zap.run.accepted"
    assert envelope.to_otlp_attributes()["redagent.resource.id"] == "run-r104"
