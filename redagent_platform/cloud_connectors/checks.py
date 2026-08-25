"""Stateless compat_108 checks over immutable collection snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re

from redagent_platform.cloud_connectors.collector import CollectionSnapshot


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class SnapshotCheck:
    check_id: str
    operation_id: str
    attribute: str
    expected: object
    severity: str

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.check_id) or not _ID.fullmatch(self.operation_id):
            raise ValueError("cloud_check_identifier_invalid")
        if not self.attribute.strip() or self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("cloud_check_invalid")


@dataclass(frozen=True, kw_only=True)
class SnapshotCheckResult:
    check_id: str
    resource_id: str
    passed: bool
    severity: str


@dataclass(frozen=True, kw_only=True)
class SnapshotEvaluation:
    snapshot_sha256: str
    control_pack_id: str
    control_pack_sha256: str
    complete: bool
    partial_reasons: tuple[str, ...]
    evaluated_at: datetime
    results: tuple[SnapshotCheckResult, ...]
    evaluation_sha256: str


def evaluate_snapshot(
    *,
    snapshot: CollectionSnapshot,
    control_pack_id: str,
    control_pack_sha256: str,
    checks: tuple[SnapshotCheck, ...],
    evaluated_at: datetime,
) -> SnapshotEvaluation:
    if not _ID.fullmatch(control_pack_id) or not _SHA.fullmatch(control_pack_sha256):
        raise ValueError("cloud_control_pack_invalid")
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("cloud_time_invalid")
    rows = tuple(sorted(
        (
            SnapshotCheckResult(
                check_id=check.check_id,
                resource_id=resource.resource_id,
                passed=resource.attributes.get(check.attribute) == check.expected,
                severity=check.severity,
            )
            for check in checks
            for resource in snapshot.resources
            if resource.operation_id == check.operation_id
        ),
        key=lambda row: (row.resource_id, row.check_id),
    ))
    material = {
        "schema": "redagent.r108-snapshot-evaluation/v1",
        "snapshot_sha256": snapshot.snapshot_sha256,
        "control_pack_id": control_pack_id,
        "control_pack_sha256": control_pack_sha256,
        "complete": snapshot.complete,
        "partial_reasons": list(snapshot.partial_reasons),
        "evaluated_at": evaluated_at.isoformat(),
        "results": [[row.check_id, row.resource_id, row.passed, row.severity] for row in rows],
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return SnapshotEvaluation(
        snapshot_sha256=snapshot.snapshot_sha256,
        control_pack_id=control_pack_id,
        control_pack_sha256=control_pack_sha256,
        complete=snapshot.complete,
        partial_reasons=snapshot.partial_reasons,
        evaluated_at=evaluated_at,
        results=rows,
        evaluation_sha256=digest,
    )
