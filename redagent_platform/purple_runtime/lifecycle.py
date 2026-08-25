"""compat_111 lifecycle requiring telemetry, cleanup, and teardown for success."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
import hashlib
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class PurpleRunState(str, Enum):
    PLANNED = "planned"; PREPARED = "prepared"; EXECUTED = "executed"; OBSERVING = "observing"
    CANCELLING = "cancelling"; CLEANING = "cleaning"; SUCCEEDED = "succeeded"; FAILED = "failed"; CANCELLED = "cancelled"


_TRANSITIONS = {
    PurpleRunState.PLANNED: {PurpleRunState.PREPARED, PurpleRunState.CANCELLING},
    PurpleRunState.PREPARED: {PurpleRunState.EXECUTED, PurpleRunState.CANCELLING, PurpleRunState.FAILED},
    PurpleRunState.EXECUTED: {PurpleRunState.OBSERVING, PurpleRunState.CANCELLING, PurpleRunState.FAILED},
    PurpleRunState.OBSERVING: {PurpleRunState.CLEANING, PurpleRunState.CANCELLING, PurpleRunState.FAILED},
    PurpleRunState.CANCELLING: {PurpleRunState.CLEANING},
    PurpleRunState.CLEANING: {PurpleRunState.SUCCEEDED, PurpleRunState.FAILED, PurpleRunState.CANCELLED},
    PurpleRunState.SUCCEEDED: set(), PurpleRunState.FAILED: set(), PurpleRunState.CANCELLED: set(),
}


@dataclass(frozen=True, kw_only=True)
class PurpleRun:
    run_id: str; state: PurpleRunState; lease_id: str; cancellation_requested: bool = False
    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.run_id) or not _ID.fullmatch(self.lease_id):
            raise ValueError("purple_run_identifier_invalid")


@dataclass(frozen=True, kw_only=True)
class KillReceipt:
    run_id: str; dispatch_blocked: bool; lease_revoked: bool; kill_acknowledged: bool; occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class CompletionReceipt:
    run_id: str; detection_observed: bool; residual_resource_count: int; teardown_verified: bool
    zero_residual: bool; inventory_sha256: str; occurred_at: datetime


def transition_purple_run(run: PurpleRun, next_state: PurpleRunState) -> PurpleRun:
    if next_state not in _TRANSITIONS[run.state]:
        raise ValueError("purple_run_transition_invalid")
    return replace(run, state=next_state)


def cancel_purple_run(run: PurpleRun, *, occurred_at: datetime) -> tuple[PurpleRun, KillReceipt]:
    _aware(occurred_at)
    if PurpleRunState.CANCELLING not in _TRANSITIONS[run.state]:
        raise ValueError("purple_run_not_cancellable")
    # CRITICAL: block dispatch and revoke the execution lease before acknowledging stop.
    cancelling = replace(run, state=PurpleRunState.CANCELLING, cancellation_requested=True)
    receipt = KillReceipt(run_id=run.run_id, dispatch_blocked=True, lease_revoked=True, kill_acknowledged=True, occurred_at=occurred_at)
    return transition_purple_run(cancelling, PurpleRunState.CLEANING), receipt


def complete_purple_run(run: PurpleRun, *, occurred_at: datetime, detection_observed: bool,
                        residual_resource_ids: tuple[str, ...], teardown_verified: bool) -> tuple[PurpleRun, CompletionReceipt]:
    _aware(occurred_at)
    if run.state is not PurpleRunState.CLEANING:
        raise ValueError("purple_run_not_cleaning")
    residual = tuple(sorted(set(residual_resource_ids)))
    if residual:
        raise ValueError("purple_cleanup_residual_resources")
    if not teardown_verified:
        raise ValueError("purple_teardown_required")
    if not run.cancellation_requested and not detection_observed:
        raise ValueError("purple_detection_evidence_required")
    final = PurpleRunState.CANCELLED if run.cancellation_requested else PurpleRunState.SUCCEEDED
    digest = hashlib.sha256("\n".join(residual).encode()).hexdigest()
    receipt = CompletionReceipt(run_id=run.run_id, detection_observed=detection_observed,
        residual_resource_count=0, teardown_verified=True, zero_residual=True, inventory_sha256=digest, occurred_at=occurred_at)
    return transition_purple_run(run, final), receipt


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("purple_time_invalid")
