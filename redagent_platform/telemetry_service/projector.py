"""Project committed metadata-only audit rows into the closed telemetry contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib

from redagent_platform.telemetry_service.contracts import (
    TELEMETRY_SCHEMA, ResourceType, ServiceName, SignalKind, SignalOutcome, TelemetryEnvelope,
)


@dataclass(frozen=True, kw_only=True)
class AuditProjection:
    audit_id: str
    tenant_id: str
    correlation_id: str
    action: str
    subject_type: str
    subject_id: str
    outcome: SignalOutcome
    occurred_at: datetime


class FoundationTelemetryProjector:
    """Map committed action namespaces without reading audit details or business payloads."""

    def __init__(self, *, service_version: str, instance_id: str) -> None:
        self.service_version = service_version
        self.instance_id = instance_id

    def project(self, source: AuditProjection) -> TelemetryEnvelope:
        if not isinstance(source, AuditProjection):
            raise ValueError("telemetry_audit_projection_required")
        service = _service(source.action)
        resource = _resource(source.subject_type)
        trace_id = _digest(f"trace:{source.tenant_id}:{source.correlation_id}", 32)
        span_id = _digest(f"span:{source.audit_id}:{source.action}", 16)
        reason = {
            SignalOutcome.SUCCESS: "operation_succeeded",
            SignalOutcome.FAILURE: "operation_failed",
            SignalOutcome.DENIED: "operation_denied",
            SignalOutcome.DEGRADED: "operation_degraded",
            SignalOutcome.UNKNOWN: "operation_unknown",
        }[source.outcome]
        return TelemetryEnvelope(
            schema=TELEMETRY_SCHEMA, event_id=source.audit_id,
            tenant_id=source.tenant_id, correlation_id=source.correlation_id,
            trace_id=trace_id, span_id=span_id, parent_span_id=None,
            # Security/audit projections remain priority events; trace sampling cannot erase delivery truth.
            sampled=True, kind=SignalKind.EVENT, service_name=service,
            service_version=self.service_version, service_instance_id=self.instance_id,
            resource_type=resource, resource_id=source.subject_id,
            operation=source.action, outcome=source.outcome, reason_code=reason,
            occurred_at=source.occurred_at, duration_ms=None,
            measurement_name=None, measurement_value=None,
        )


def _service(action: str) -> ServiceName:
    namespace = action.partition(".")[0]
    mapping = {
        "identity": ServiceName.IDENTITY, "session": ServiceName.IDENTITY,
        "jit": ServiceName.IDENTITY, "engagement": ServiceName.API,
        "target": ServiceName.API, "roe": ServiceName.API, "job": ServiceName.API,
        "campaign": ServiceName.API, "workflow": ServiceName.TEMPORAL,
        "policy": ServiceName.POLICY, "secret": ServiceName.SECRET,
        "lease": ServiceName.SECRET, "evidence": ServiceName.EVIDENCE,
        "runner": ServiceName.RUNNER, "quota": ServiceName.QUOTA,
        "containment": ServiceName.CONTAINMENT, "incident": ServiceName.TELEMETRY,
        "slo": ServiceName.TELEMETRY, "telemetry": ServiceName.TELEMETRY,
        "zap": ServiceName.ZAP, "nuclei": ServiceName.NUCLEI,
        "api_diff": ServiceName.API_DIFFERENTIAL,
        "network": ServiceName.NETWORK_ASSESSMENT,
        "cloud": ServiceName.CLOUD_POSTURE,
    }
    try:
        return mapping[namespace]
    except KeyError as exc:
        raise ValueError("telemetry_action_namespace_unknown") from exc


def _resource(subject_type: str) -> ResourceType:
    mapping = {
        "job": ResourceType.JOB, "campaign": ResourceType.CAMPAIGN,
        "workflow": ResourceType.WORKFLOW, "policy_decision": ResourceType.POLICY_DECISION,
        "secret_lease": ResourceType.SECRET_LEASE,
        "evidence_artifact": ResourceType.EVIDENCE_ARTIFACT, "runner": ResourceType.RUNNER,
        "quota": ResourceType.QUOTA, "containment": ResourceType.CONTAINMENT_CONTROL,
        "incident": ResourceType.INCIDENT, "slo": ResourceType.SLO,
        "export": ResourceType.EXPORT,
        "zap": ResourceType.ZAP_RUN, "nuclei": ResourceType.NUCLEI_RUN,
        "api_differential": ResourceType.API_DIFFERENTIAL_RUN,
        "network_assessment": ResourceType.NETWORK_RUN,
        "cloud_assessment": ResourceType.CLOUD_RUN,
    }
    return mapping.get(subject_type, ResourceType.API_REQUEST)


def _digest(value: str, length: int) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]
