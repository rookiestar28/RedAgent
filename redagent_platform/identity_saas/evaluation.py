"""Deterministic compat_109 baseline evaluation preserving partial coverage truth."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re

from redagent_platform.identity_saas.collector import IdentitySnapshot


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class BaselineCheck:
    control_id: str; operation_id: str; attribute: str; expected: object; severity: str

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.control_id) or not _ID.fullmatch(self.operation_id) or not self.attribute.strip() or self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("identity_baseline_check_invalid")


@dataclass(frozen=True, kw_only=True)
class IdentityCheckResult:
    control_id: str; resource_id: str; passed: bool; severity: str


@dataclass(frozen=True, kw_only=True)
class IdentityBaselineEvaluation:
    snapshot_sha256: str; baseline_id: str; baseline_sha256: str; complete: bool; clean: bool
    partial_reasons: tuple[str, ...]; evaluated_at: datetime; results: tuple[IdentityCheckResult, ...]; evaluation_sha256: str


def evaluate_identity_snapshot(*, snapshot: IdentitySnapshot, baseline_id: str, baseline_sha256: str, checks: tuple[BaselineCheck, ...], evaluated_at: datetime) -> IdentityBaselineEvaluation:
    if not _ID.fullmatch(baseline_id) or not _SHA.fullmatch(baseline_sha256): raise ValueError("identity_baseline_invalid")
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None: raise ValueError("identity_time_invalid")
    results = tuple(sorted((IdentityCheckResult(control_id=check.control_id, resource_id=resource.resource_id,
        passed=resource.attributes.get(check.attribute) == check.expected, severity=check.severity)
        for check in checks for resource in snapshot.resources if resource.operation_id == check.operation_id), key=lambda item: (item.resource_id, item.control_id)))
    clean = snapshot.complete and all(item.passed for item in results)
    material = {"schema": "redagent.r109-identity-evaluation/v1", "snapshot": snapshot.snapshot_sha256,
        "baseline": [baseline_id, baseline_sha256], "complete": snapshot.complete, "clean": clean,
        "partial": list(snapshot.partial_reasons), "evaluated_at": evaluated_at.isoformat(),
        "results": [[item.control_id, item.resource_id, item.passed, item.severity] for item in results]}
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return IdentityBaselineEvaluation(snapshot_sha256=snapshot.snapshot_sha256, baseline_id=baseline_id,
        baseline_sha256=baseline_sha256, complete=snapshot.complete, clean=clean,
        partial_reasons=snapshot.partial_reasons, evaluated_at=evaluated_at, results=results, evaluation_sha256=digest)
