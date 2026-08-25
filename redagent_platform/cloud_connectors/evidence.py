"""Minimized compat_093 evidence projection for compat_108 snapshots and checks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from redagent_platform.cloud_connectors.checks import SnapshotEvaluation
from redagent_platform.cloud_connectors.collector import CollectionSnapshot


@dataclass(frozen=True, kw_only=True)
class CloudEvidenceProjection:
    schema: str
    content: bytes
    content_sha256: str
    classification: str
    redaction_state: str
    identity: str
    partial: bool
    result_count: int


def project_snapshot_evidence(
    *, snapshot: CollectionSnapshot, evaluation: SnapshotEvaluation
) -> CloudEvidenceProjection:
    if snapshot.snapshot_sha256 != evaluation.snapshot_sha256:
        raise ValueError("cloud_evidence_snapshot_mismatch")
    identity = f"{snapshot.identity.provider.value}:{snapshot.identity.tenant}"
    document = {
        "schema": "redagent.cloud-evidence/v1",
        "identity": identity,
        "snapshot_time": snapshot.collected_at.isoformat(),
        "snapshot_sha256": snapshot.snapshot_sha256,
        "plan_sha256": snapshot.plan_sha256,
        "control_pack": {
            "id": evaluation.control_pack_id,
            "sha256": evaluation.control_pack_sha256,
        },
        "coverage": {
            "complete": snapshot.complete,
            "partial_reasons": list(snapshot.partial_reasons),
            "page_count": snapshot.page_count,
            "resource_count": snapshot.resource_count,
        },
        # Raw provider/config attributes are intentionally absent; only normalized result truth persists here.
        "results": [
            {
                "check_id": row.check_id,
                "resource_id": row.resource_id,
                "passed": row.passed,
                "severity": row.severity,
            }
            for row in evaluation.results
        ],
        "evaluation_sha256": evaluation.evaluation_sha256,
    }
    content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(content) > 64 * 1024:
        raise ValueError("cloud_evidence_size_exceeded")
    return CloudEvidenceProjection(
        schema="redagent.cloud-evidence/v1",
        content=content,
        content_sha256=hashlib.sha256(content).hexdigest(),
        classification="restricted",
        redaction_state="minimized-hash-only",
        identity=identity,
        partial=not snapshot.complete,
        result_count=len(evaluation.results),
    )
