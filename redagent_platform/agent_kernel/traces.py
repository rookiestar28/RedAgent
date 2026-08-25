"""Stable minimized compat_113 trace envelope and replaceable OTLP projection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, kw_only=True)
class TraceEnvelope:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    tenant_id: str
    run_id: str
    event_type: str
    state: str
    input_sha256: str
    output_sha256: str
    policy_decision_id: str | None
    approval_id: str | None
    evidence_id: str | None
    error_code: str | None
    occurred_at: datetime


def to_otlp_attributes(envelope: TraceEnvelope) -> dict[str, str]:
    attributes = {
        "gen_ai.operation.name": envelope.event_type,
        "redagent.run.id": envelope.run_id,
        "redagent.trace.state": envelope.state,
        "redagent.input.sha256": envelope.input_sha256,
        "redagent.output.sha256": envelope.output_sha256,
    }
    if envelope.policy_decision_id is not None:
        attributes["redagent.policy.decision.id"] = envelope.policy_decision_id
    if envelope.approval_id is not None:
        attributes["redagent.approval.id"] = envelope.approval_id
    if envelope.evidence_id is not None:
        attributes["redagent.evidence.id"] = envelope.evidence_id
    if envelope.error_code is not None:
        attributes["error.type"] = envelope.error_code
    return attributes
