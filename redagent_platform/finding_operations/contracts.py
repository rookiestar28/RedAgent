"""Closed compat_115 contracts for canonical issues and immutable occurrences."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class CoverageState(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class Disposition(str, Enum):
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    DUPLICATE = "duplicate"
    MITIGATED = "mitigated"
    OUT_OF_SCOPE = "out_of_scope"
    CLOSED = "closed"


@dataclass(frozen=True, kw_only=True)
class FindingOccurrenceInput:
    source_record_id: str
    tool: str
    tool_version: str
    rule_id: str
    rule_version: str
    database_version: str
    title: str
    resource_identity: str
    location: str
    severity: str
    confidence: str
    taxonomy_ids: tuple[str, ...]
    control_ids: tuple[str, ...]
    evidence_id: str
    evidence_sha256: str
    redaction_state: str
    observed_at: datetime


@dataclass(frozen=True, kw_only=True)
class ImportBatch:
    import_id: str
    tenant_id: str
    adapter_id: str
    run_id: str
    coverage_state: CoverageState
    comparable_baseline_run_id: str | None
    records: tuple[FindingOccurrenceInput, ...]
    imported_at: datetime


@dataclass(frozen=True, kw_only=True)
class ReviewSnapshot:
    issue_id: str
    tenant_id: str
    issue_fingerprint: str
    disposition: Disposition
    disposition_revision: int
    reviewer_id: str
    rationale_sha256: str
    risk_acceptance_expires_at: datetime | None = None


@dataclass(frozen=True, kw_only=True)
class CorrelationOutcome:
    tenant_id: str
    source_record_id: str
    issue_fingerprint: str
    recipe_version: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class ImportCorrelationResult:
    import_sha256: str
    outcomes: tuple[CorrelationOutcome, ...]
    preserved_dispositions: tuple[Disposition, ...]
    absence_state: str
    reopen_issue_ids: tuple[str, ...]
