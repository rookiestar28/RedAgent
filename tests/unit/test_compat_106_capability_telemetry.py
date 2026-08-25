from datetime import datetime, timezone

from redagent_platform.api_differential_service.capability import build_api_differential_capability_manifest
from redagent_platform.runner_service.contracts import CredentialClass, NetworkMode
from redagent_platform.telemetry_service.contracts import ResourceType, ServiceName, SignalOutcome
from redagent_platform.telemetry_service.projector import AuditProjection, FoundationTelemetryProjector


def test_r100_capability_has_closed_schema_credential_gateway_and_unsupported_surfaces() -> None:
    manifest = build_api_differential_capability_manifest(artifact_receipt_id="r106-engine-receipt-v1")
    assert manifest.capability_id == "api-authorization-differential"
    assert manifest.adapter_id == "schemathesis" and manifest.adapter_version == "4.22.4-r106.1"
    assert manifest.network_mode is NetworkMode.TARGET_ALLOWLIST
    assert manifest.credential_class is CredentialClass.HTTP_HEADER
    assert "arbitrary_request" in manifest.unsupported_features
    assert "arbitrary_credential" in manifest.unsupported_features
    assert "restler" in manifest.unsupported_features and "production_target" in manifest.unsupported_features


def test_api_differential_audit_namespace_projects_to_closed_r102_service_and_resource() -> None:
    envelope = FoundationTelemetryProjector(
        service_version="0.1.0", instance_id="api-differential-local-1",
    ).project(AuditProjection(
        audit_id="audit-r106", tenant_id="tenant-r106", correlation_id="correlation-r106",
        action="api_diff.run.accepted", subject_type="api_differential", subject_id="run-r106",
        outcome=SignalOutcome.SUCCESS, occurred_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
    ))
    assert envelope.service_name is ServiceName.API_DIFFERENTIAL
    assert envelope.resource_type is ResourceType.API_DIFFERENTIAL_RUN
    assert envelope.operation == "api_diff.run.accepted"
