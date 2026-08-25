"""compat_109 lifecycle with request-block and credential-lease revocation before stop."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
import hashlib
import json
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class IdentityRunState(str, Enum):
    PLANNED = "planned"; RESERVED = "reserved"; IDENTITY_VERIFYING = "identity_verifying"; COLLECTING = "collecting"
    EVALUATING = "evaluating"; ANNOTATING = "annotating"; GRAPHING = "graphing"; CANCELLING = "cancelling"
    CLEANING = "cleaning"; SUCCEEDED = "succeeded"; FAILED = "failed"; CANCELLED = "cancelled"


_TRANSITIONS = {
    IdentityRunState.PLANNED: {IdentityRunState.RESERVED}, IdentityRunState.RESERVED: {IdentityRunState.IDENTITY_VERIFYING, IdentityRunState.CANCELLING},
    IdentityRunState.IDENTITY_VERIFYING: {IdentityRunState.COLLECTING, IdentityRunState.CANCELLING, IdentityRunState.FAILED},
    IdentityRunState.COLLECTING: {IdentityRunState.EVALUATING, IdentityRunState.CANCELLING, IdentityRunState.FAILED},
    IdentityRunState.EVALUATING: {IdentityRunState.ANNOTATING, IdentityRunState.GRAPHING, IdentityRunState.CLEANING, IdentityRunState.CANCELLING, IdentityRunState.FAILED},
    IdentityRunState.ANNOTATING: {IdentityRunState.GRAPHING, IdentityRunState.CLEANING, IdentityRunState.CANCELLING, IdentityRunState.FAILED},
    IdentityRunState.GRAPHING: {IdentityRunState.CLEANING, IdentityRunState.CANCELLING, IdentityRunState.FAILED},
    IdentityRunState.CANCELLING: {IdentityRunState.CLEANING}, IdentityRunState.CLEANING: {IdentityRunState.SUCCEEDED, IdentityRunState.FAILED, IdentityRunState.CANCELLED},
    IdentityRunState.SUCCEEDED: set(), IdentityRunState.FAILED: set(), IdentityRunState.CANCELLED: set(),
}


@dataclass(frozen=True, kw_only=True)
class IdentityRun:
    run_id: str; state: IdentityRunState; lease_id: str; cancellation_requested: bool = False
    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.run_id) or not _ID.fullmatch(self.lease_id): raise ValueError("identity_run_identifier_invalid")


@dataclass(frozen=True, kw_only=True)
class IdentityCancellationReceipt:
    run_id: str; new_requests_blocked: bool; lease_revoked: bool; cooperative_stop_acknowledged: bool; forced_termination: bool; occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class IdentityCleanupReceipt:
    run_id: str; residual_resource_count: int; inventory_sha256: str; occurred_at: datetime


def transition_identity_run(run: IdentityRun, next_state: IdentityRunState) -> IdentityRun:
    if next_state not in _TRANSITIONS[run.state]: raise ValueError("identity_run_transition_invalid")
    return replace(run, state=next_state)


def cancel_identity_run(run: IdentityRun, *, occurred_at: datetime) -> tuple[IdentityRun, IdentityCancellationReceipt]:
    _aware(occurred_at)
    cancellable = {IdentityRunState.RESERVED, IdentityRunState.IDENTITY_VERIFYING, IdentityRunState.COLLECTING, IdentityRunState.EVALUATING, IdentityRunState.ANNOTATING, IdentityRunState.GRAPHING}
    if run.state not in cancellable: raise ValueError("identity_run_not_cancellable")
    cancelling = replace(run, state=IdentityRunState.CANCELLING, cancellation_requested=True)
    # CRITICAL: deny new directory requests and revoke the opaque lease before cooperative worker stop.
    receipt = IdentityCancellationReceipt(run_id=run.run_id, new_requests_blocked=True, lease_revoked=True, cooperative_stop_acknowledged=True, forced_termination=False, occurred_at=occurred_at)
    return transition_identity_run(cancelling, IdentityRunState.CLEANING), receipt


def complete_identity_cleanup(run: IdentityRun, *, occurred_at: datetime, residual_resource_ids: tuple[str, ...]) -> tuple[IdentityRun, IdentityCleanupReceipt]:
    _aware(occurred_at)
    if run.state is not IdentityRunState.CLEANING: raise ValueError("identity_run_not_cleaning")
    resources = tuple(sorted(set(residual_resource_ids)))
    if resources: raise ValueError("identity_cleanup_residual_resources")
    final = IdentityRunState.CANCELLED if run.cancellation_requested else IdentityRunState.SUCCEEDED
    digest = hashlib.sha256(json.dumps(resources, separators=(",", ":")).encode()).hexdigest()
    return transition_identity_run(run, final), IdentityCleanupReceipt(run_id=run.run_id, residual_resource_count=0, inventory_sha256=digest, occurred_at=occurred_at)


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError("identity_time_invalid")
