from __future__ import annotations

from datetime import datetime, timezone

import pytest

from redagent_platform.telemetry_service.contracts import ServiceName, SignalOutcome
from redagent_platform.telemetry_service.projector import AuditProjection, FoundationTelemetryProjector


NOW = datetime(2026, 7, 11, 8, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(("action", "subject_type", "service"), (
    ("identity.session.created", "session", ServiceName.IDENTITY),
    ("engagement.created", "engagement", ServiceName.API),
    ("workflow.job.started", "job", ServiceName.TEMPORAL),
    ("policy.decision.denied", "policy_decision", ServiceName.POLICY),
    ("secret.lease.issued", "secret_lease", ServiceName.SECRET),
    ("evidence.artifact.verified", "evidence_artifact", ServiceName.EVIDENCE),
    ("runner.execution.completed", "runner", ServiceName.RUNNER),
    ("quota.hard_limit.exceeded", "quota", ServiceName.QUOTA),
    ("containment.stop.activated", "containment", ServiceName.CONTAINMENT),
    ("incident.opened", "incident", ServiceName.TELEMETRY),
    ("slo.window.evaluated", "slo", ServiceName.TELEMETRY),
))
def test_committed_foundation_metadata_projects_to_stable_closed_envelope(
    action: str, subject_type: str, service: ServiceName,
) -> None:
    projector = FoundationTelemetryProjector(service_version="0.1.0", instance_id="projector-local-1")
    projected = projector.project(AuditProjection(
        audit_id=f"audit-{subject_type}", tenant_id="tenant-1", correlation_id="correlation-1",
        action=action, subject_type=subject_type, subject_id=f"resource-{subject_type}",
        outcome=SignalOutcome.DENIED if action.endswith("denied") else SignalOutcome.SUCCESS,
        occurred_at=NOW,
    ))
    assert projected.service_name is service
    assert projected.operation == action
    assert projected.tenant_id == "tenant-1"
    assert projected.sampled is True
    assert projected.to_otlp_attributes()["redagent.correlation.id"] == "correlation-1"


def test_projector_has_no_content_or_authority_extension_channel() -> None:
    fields = set(AuditProjection.__dataclass_fields__)
    for forbidden in (
        "details", "body", "target", "command", "evidence", "credential", "prompt",
        "tool_arguments", "tool_result", "headers", "baggage", "url", "sql",
    ):
        assert forbidden not in fields
    with pytest.raises(ValueError, match="telemetry_action_namespace_unknown"):
        FoundationTelemetryProjector(service_version="0.1.0", instance_id="projector-local-1").project(
            AuditProjection(
                audit_id="audit-unknown", tenant_id="tenant-1", correlation_id="correlation-1",
                action="unknown.operation", subject_type="job", subject_id="job-1",
                outcome=SignalOutcome.SUCCESS, occurred_at=NOW,
            )
        )
