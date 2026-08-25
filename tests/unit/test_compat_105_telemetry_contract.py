from datetime import datetime, timezone

from redagent_platform.telemetry_service.contracts import ResourceType, ServiceName, SignalOutcome
from redagent_platform.telemetry_service.projector import AuditProjection, FoundationTelemetryProjector


def test_nuclei_audit_namespace_projects_to_closed_r102_service_and_resource() -> None:
    envelope = FoundationTelemetryProjector(
        service_version="0.1.0", instance_id="nuclei-adapter-local-1",
    ).project(AuditProjection(
        audit_id="audit-r105", tenant_id="tenant-r105", correlation_id="correlation-r105",
        action="nuclei.run.accepted", subject_type="nuclei", subject_id="run-r105",
        outcome=SignalOutcome.SUCCESS, occurred_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
    ))
    assert envelope.service_name is ServiceName.NUCLEI
    assert envelope.resource_type is ResourceType.NUCLEI_RUN
    assert envelope.operation == "nuclei.run.accepted"
