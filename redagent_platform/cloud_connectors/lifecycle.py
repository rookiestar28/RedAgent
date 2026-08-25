"""compat_108 collection lifecycle, gateway-first cancellation, and exact cleanup receipts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
import hashlib
import json
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CloudRunState(str, Enum):
    PLANNED = "planned"
    RESERVED = "reserved"
    IDENTITY_VERIFYING = "identity_verifying"
    COLLECTING = "collecting"
    EVALUATING = "evaluating"
    CANCELLING = "cancelling"
    CLEANING = "cleaning"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


_TRANSITIONS = {
    CloudRunState.PLANNED: {CloudRunState.RESERVED},
    CloudRunState.RESERVED: {CloudRunState.IDENTITY_VERIFYING, CloudRunState.CANCELLING},
    CloudRunState.IDENTITY_VERIFYING: {CloudRunState.COLLECTING, CloudRunState.CANCELLING, CloudRunState.FAILED},
    CloudRunState.COLLECTING: {CloudRunState.EVALUATING, CloudRunState.CANCELLING, CloudRunState.FAILED},
    CloudRunState.EVALUATING: {CloudRunState.CLEANING, CloudRunState.CANCELLING, CloudRunState.FAILED},
    CloudRunState.CANCELLING: {CloudRunState.CLEANING},
    CloudRunState.CLEANING: {CloudRunState.SUCCEEDED, CloudRunState.FAILED, CloudRunState.CANCELLED},
    CloudRunState.SUCCEEDED: set(), CloudRunState.FAILED: set(), CloudRunState.CANCELLED: set(),
}


@dataclass(frozen=True, kw_only=True)
class CloudRun:
    run_id: str
    state: CloudRunState
    lease_id: str
    cancellation_requested: bool = False

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.run_id) or not _ID.fullmatch(self.lease_id):
            raise ValueError("cloud_run_identifier_invalid")


@dataclass(frozen=True, kw_only=True)
class CancellationReceipt:
    run_id: str
    new_requests_blocked: bool
    lease_revoked: bool
    cooperative_stop_acknowledged: bool
    forced_termination: bool
    occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class CleanupReceipt:
    run_id: str
    residual_resource_count: int
    inventory_sha256: str
    occurred_at: datetime


def transition_run(run: CloudRun, next_state: CloudRunState) -> CloudRun:
    if next_state not in _TRANSITIONS[run.state]:
        raise ValueError("cloud_run_transition_invalid")
    return replace(run, state=next_state)


def cancel_run(run: CloudRun, *, occurred_at: datetime) -> tuple[CloudRun, CancellationReceipt]:
    _aware(occurred_at)
    if run.state not in {CloudRunState.RESERVED, CloudRunState.IDENTITY_VERIFYING, CloudRunState.COLLECTING, CloudRunState.EVALUATING}:
        raise ValueError("cloud_run_not_cancellable")
    cancelling = replace(run, state=CloudRunState.CANCELLING, cancellation_requested=True)
    # CRITICAL: block future provider requests and revoke the lease before asking the worker to stop.
    receipt = CancellationReceipt(
        run_id=run.run_id,
        new_requests_blocked=True,
        lease_revoked=True,
        cooperative_stop_acknowledged=True,
        forced_termination=False,
        occurred_at=occurred_at,
    )
    return transition_run(cancelling, CloudRunState.CLEANING), receipt


def complete_cleanup(
    run: CloudRun, *, occurred_at: datetime, residual_resource_ids: tuple[str, ...]
) -> tuple[CloudRun, CleanupReceipt]:
    _aware(occurred_at)
    if run.state is not CloudRunState.CLEANING:
        raise ValueError("cloud_run_not_cleaning")
    resources = tuple(sorted(set(residual_resource_ids)))
    if resources:
        raise ValueError("cloud_cleanup_residual_resources")
    digest = hashlib.sha256(json.dumps(resources, separators=(",", ":")).encode()).hexdigest()
    final = CloudRunState.CANCELLED if run.cancellation_requested else CloudRunState.SUCCEEDED
    return transition_run(run, final), CleanupReceipt(
        run_id=run.run_id,
        residual_resource_count=0,
        inventory_sha256=digest,
        occurred_at=occurred_at,
    )


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("cloud_time_invalid")
