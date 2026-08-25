"""Canonical redacted compat_093 evidence projection for compat_107 execution results."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from redagent_platform.network_service.connector import NetworkExecutionResult


@dataclass(frozen=True, kw_only=True)
class NetworkEvidenceProjection:
    schema: str
    content: bytes
    content_sha256: str
    classification: str
    redaction_state: str
    tuple_count: int
    partial: bool


def project_execution_evidence(result: NetworkExecutionResult) -> NetworkEvidenceProjection:
    observations = [
        {
            "tuple_id": item.tuple_id,
            "literal_ip": item.ip,
            "port": item.port,
            "state": item.state.value,
            "latency_bucket": item.latency_bucket,
            "service_class": item.service_class,
            "sample_sha256": item.sample_sha256,
            "uncertainty": item.uncertainty,
            "reason": item.reason,
        }
        for item in result.observations
    ]
    document = {
        "schema": "redagent.network-evidence/v1",
        "run_id": result.run_id,
        "plan_sha256": result.plan_sha256,
        "coverage": {
            "completed": result.completed_count,
            "denied": result.denied_count,
            "total": result.total_count,
            "partial": result.partial,
        },
        "cancelled": result.cancelled,
        "cleanup": {
            "residual_resource_count": result.cleanup.residual_resource_count,
            "transient_data_erased": result.cleanup.transient_data_erased,
        },
        "observations": observations,
    }
    content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(content) > 64 * 1024:
        raise ValueError("network_evidence_size_exceeded")
    return NetworkEvidenceProjection(
        schema="redagent.network-evidence/v1",
        content=content,
        content_sha256=hashlib.sha256(content).hexdigest(),
        classification="confidential",
        redaction_state="redacted-hash-only",
        tuple_count=result.total_count,
        partial=result.partial,
    )
