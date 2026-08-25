from datetime import datetime, timezone

from redagent_platform.cloud_connectors.checks import SnapshotCheck, evaluate_snapshot
from redagent_platform.cloud_connectors.evidence import project_snapshot_evidence
from redagent_platform.cloud_connectors.capability import build_cloud_connector_capability
from redagent_platform.runner_service.contracts import CredentialClass, NetworkMode
from redagent_platform.telemetry_service.contracts import ResourceType, ServiceName, SignalOutcome
from redagent_platform.telemetry_service.projector import AuditProjection, FoundationTelemetryProjector
from tests.unit.test_compat_108_snapshot_checks_lifecycle import NOW, snapshot


def test_evidence_is_bounded_redacted_and_preserves_identity_partial_and_hashes() -> None:
    source = snapshot(complete=False)
    evaluation = evaluate_snapshot(
        snapshot=source,
        control_pack_id="r108-cloud-baseline-v1",
        control_pack_sha256="3" * 64,
        checks=(SnapshotCheck(check_id="R108-AWS-001", operation_id="aws-iam-list-roles-v1", attribute="mfa_required", expected=True, severity="high"),),
        evaluated_at=NOW,
    )
    evidence = project_snapshot_evidence(snapshot=source, evaluation=evaluation)
    assert evidence.classification == "restricted"
    assert evidence.redaction_state == "minimized-hash-only"
    assert evidence.identity == "aws:123456789012"
    assert evidence.partial is True
    assert b"mfa_required" not in evidence.content
    assert b"iam_throttled" in evidence.content
    assert len(evidence.content) < 64 * 1024
    assert len(evidence.content_sha256) == 64


def test_capability_is_read_only_emulator_only_and_forbids_native_external_execution() -> None:
    manifest = build_cloud_connector_capability(
        artifact_receipt_id="r108-source-receipt-v1", source_digest="sha256:" + "a" * 64
    )
    assert manifest.capability_id == "cloud-posture"
    assert manifest.network_mode is NetworkMode.TARGET_ALLOWLIST
    assert manifest.credential_class is CredentialClass.CLOUD_READ_ONLY
    assert {"production_tenant", "mutation", "host_access", "external_scanner", "ambient_credentials"} <= set(manifest.unsupported_features)
    assert manifest.limits.timeout_seconds <= 60


def test_cloud_audit_namespace_projects_to_r102_cloud_service_and_run_resource() -> None:
    envelope = FoundationTelemetryProjector(service_version="0.1.0", instance_id="cloud-local-1").project(
        AuditProjection(
            audit_id="audit-r108", tenant_id="tenant-r108", correlation_id="corr-r108",
            action="cloud.run.completed", subject_type="cloud_assessment", subject_id="run-r108",
            outcome=SignalOutcome.SUCCESS, occurred_at=datetime(2026, 7, 11, 16, 0, tzinfo=timezone.utc),
        )
    )
    assert envelope.service_name is ServiceName.CLOUD_POSTURE
    assert envelope.resource_type is ResourceType.CLOUD_RUN
