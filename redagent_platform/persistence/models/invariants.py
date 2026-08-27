"""Deterministic persistence invariants independent of table registration."""

from __future__ import annotations

import hashlib
import json
from enum import Enum


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


_JOB_TRANSITIONS = {
    JobStatus.PENDING: frozenset({JobStatus.RUNNING, JobStatus.CANCELLED}),
    JobStatus.RUNNING: frozenset({JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED}),
    JobStatus.SUCCEEDED: frozenset(),
    JobStatus.FAILED: frozenset(),
    JobStatus.CANCELLED: frozenset(),
}


def assert_job_transition(current: JobStatus, next_status: JobStatus) -> None:
    if next_status not in _JOB_TRANSITIONS[current]:
        raise ValueError(f"invalid_job_transition:{current.value}:{next_status.value}")


def compute_issue_fingerprint(*, tool: str, rule_id: str, database_version: str, title: str) -> str:
    values = {
        "database_version": database_version.strip(),
        "rule_id": rule_id.strip(),
        "title": " ".join(title.split()),
        "tool": tool.strip().lower(),
    }
    if any(not value for value in values.values()):
        raise ValueError("fingerprint_field_required")
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
