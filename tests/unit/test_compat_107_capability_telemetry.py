from datetime import datetime, timezone

from redagent_platform.network_service.capability import build_network_capability_manifest
from redagent_platform.runner_service.contracts import CredentialClass, NetworkMode
from redagent_platform.telemetry_service.contracts import ResourceType, ServiceName, SignalOutcome
from redagent_platform.telemetry_service.projector import AuditProjection, FoundationTelemetryProjector


def test_network_capability_is_closed_unprivileged_and_gateway_only() -> None:
    manifest = build_network_capability_manifest(artifact_receipt_id="r107-engine-receipt-v1")
    assert manifest.capability_id == "network-assessment"
    assert manifest.supported_modes == ("tcp-connect-discovery-v1",)
    assert manifest.network_mode is NetworkMode.TARGET_ALLOWLIST
    assert manifest.credential_class is CredentialClass.NONE
    assert {"udp", "raw_socket", "script", "external_scanner", "public_target"} <= set(manifest.unsupported_features)
    assert manifest.limits.timeout_seconds == 30 and manifest.limits.evidence_bytes == 64 * 1024


def test_network_audit_namespace_projects_to_closed_r102_service_and_resource() -> None:
    envelope = FoundationTelemetryProjector(
        service_version="0.1.0", instance_id="network-local-1",
    ).project(AuditProjection(
        audit_id="audit-r107", tenant_id="tenant-r107", correlation_id="corr-r107",
        action="network.run.completed", subject_type="network_assessment", subject_id="run-r107",
        outcome=SignalOutcome.SUCCESS,
        occurred_at=datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc),
    ))
    assert envelope.service_name is ServiceName.NETWORK_ASSESSMENT
    assert envelope.resource_type is ResourceType.NETWORK_RUN
    assert envelope.operation == "network.run.completed"
