"""Deterministic, explainable, tenant-scoped compat_115 correlation."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json

from redagent_platform.finding_operations.contracts import (
    CorrelationOutcome,
    CoverageState,
    ImportBatch,
    ImportCorrelationResult,
    ReviewSnapshot,
)


FINGERPRINT_RECIPE_VERSION = "redagent-fingerprint-v1"


def correlate_import(batch: ImportBatch, *, existing: tuple[ReviewSnapshot, ...]) -> ImportCorrelationResult:
    _validate_batch(batch)
    if any(snapshot.tenant_id != batch.tenant_id for snapshot in existing):
        raise ValueError("finding_cross_tenant_snapshot_forbidden")
    outcomes = tuple(_outcome(batch.tenant_id, record) for record in batch.records)
    absence_state = (
        "unknown_partial_coverage"
        if not batch.records and batch.coverage_state is not CoverageState.COMPLETE
        else "comparable_absent"
        if not batch.records and batch.comparable_baseline_run_id
        else "observed"
    )
    # IMPORTANT: import absence never silently revokes a reviewed disposition.
    preserved = tuple(snapshot.disposition for snapshot in existing)
    payload = {
        "tenant_id": batch.tenant_id,
        "adapter_id": batch.adapter_id,
        "run_id": batch.run_id,
        "coverage_state": batch.coverage_state.value,
        "baseline": batch.comparable_baseline_run_id,
        "outcomes": [asdict(outcome) for outcome in outcomes],
    }
    return ImportCorrelationResult(
        import_sha256=_sha(payload), outcomes=outcomes, preserved_dispositions=preserved,
        absence_state=absence_state, reopen_issue_ids=(),
    )


def issue_fingerprint(record: object) -> str:
    payload = {
        "recipe": FINGERPRINT_RECIPE_VERSION,
        "tool": _norm(getattr(record, "tool")),
        "rule_id": _norm(getattr(record, "rule_id")),
        "resource_identity": _norm(getattr(record, "resource_identity")),
        "location": _norm(getattr(record, "location")),
        "taxonomy_ids": sorted(getattr(record, "taxonomy_ids")),
    }
    return _sha(payload)


def _outcome(tenant_id: str, record: object) -> CorrelationOutcome:
    return CorrelationOutcome(
        tenant_id=tenant_id, source_record_id=getattr(record, "source_record_id"),
        issue_fingerprint=issue_fingerprint(record), recipe_version=FINGERPRINT_RECIPE_VERSION,
        reason_codes=("no_existing_candidate", "create_issue"),
    )


def _validate_batch(batch: ImportBatch) -> None:
    for value in (batch.import_id, batch.tenant_id, batch.adapter_id, batch.run_id):
        if not value or not value.strip():
            raise ValueError("finding_import_identity_required")
    if batch.imported_at.tzinfo is None or batch.imported_at.utcoffset() is None:
        raise ValueError("finding_import_timezone_required")
    for record in batch.records:
        if len(record.evidence_sha256) != 64 or record.redaction_state not in {"report_safe", "export_safe"}:
            raise ValueError("finding_approved_evidence_required")


def _norm(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=_json).encode()).hexdigest()


def _json(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, CoverageState):
        return value.value
    raise TypeError(type(value).__name__)
