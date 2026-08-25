"""compat_110 lifecycle with artifact-read blocking and lease revocation before stop."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
import hashlib
import json
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ArtifactRunState(str, Enum):
    PLANNED = "planned"; RESERVED = "reserved"; VALIDATING = "validating"; INVENTORYING = "inventorying"
    CHECKING = "checking"; NORMALIZING = "normalizing"; CANCELLING = "cancelling"; CLEANING = "cleaning"
    SUCCEEDED = "succeeded"; FAILED = "failed"; CANCELLED = "cancelled"


_TRANSITIONS = {ArtifactRunState.PLANNED: {ArtifactRunState.RESERVED}, ArtifactRunState.RESERVED: {ArtifactRunState.VALIDATING, ArtifactRunState.CANCELLING},
    ArtifactRunState.VALIDATING: {ArtifactRunState.INVENTORYING, ArtifactRunState.CANCELLING, ArtifactRunState.FAILED},
    ArtifactRunState.INVENTORYING: {ArtifactRunState.CHECKING, ArtifactRunState.CANCELLING, ArtifactRunState.FAILED},
    ArtifactRunState.CHECKING: {ArtifactRunState.NORMALIZING, ArtifactRunState.CANCELLING, ArtifactRunState.FAILED},
    ArtifactRunState.NORMALIZING: {ArtifactRunState.CLEANING, ArtifactRunState.CANCELLING, ArtifactRunState.FAILED},
    ArtifactRunState.CANCELLING: {ArtifactRunState.CLEANING}, ArtifactRunState.CLEANING: {ArtifactRunState.SUCCEEDED, ArtifactRunState.FAILED, ArtifactRunState.CANCELLED},
    ArtifactRunState.SUCCEEDED: set(), ArtifactRunState.FAILED: set(), ArtifactRunState.CANCELLED: set()}


@dataclass(frozen=True, kw_only=True)
class ArtifactRun:
    run_id: str; state: ArtifactRunState; lease_id: str; cancellation_requested: bool = False
    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.run_id) or not _ID.fullmatch(self.lease_id): raise ValueError("artifact_run_identifier_invalid")


@dataclass(frozen=True, kw_only=True)
class ArtifactCancellationReceipt:
    run_id: str; new_reads_blocked: bool; lease_revoked: bool; cooperative_stop_acknowledged: bool; untrusted_execution_count: int; occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class ArtifactCleanupReceipt:
    run_id: str; residual_resource_count: int; untrusted_execution_count: int; inventory_sha256: str; occurred_at: datetime


def transition_artifact_run(run: ArtifactRun, next_state: ArtifactRunState) -> ArtifactRun:
    if next_state not in _TRANSITIONS[run.state]: raise ValueError("artifact_run_transition_invalid")
    return replace(run, state=next_state)


def cancel_artifact_run(run: ArtifactRun, *, occurred_at: datetime) -> tuple[ArtifactRun, ArtifactCancellationReceipt]:
    _aware(occurred_at)
    if run.state not in {ArtifactRunState.RESERVED, ArtifactRunState.VALIDATING, ArtifactRunState.INVENTORYING, ArtifactRunState.CHECKING, ArtifactRunState.NORMALIZING}: raise ValueError("artifact_run_not_cancellable")
    cancelling = replace(run, state=ArtifactRunState.CANCELLING, cancellation_requested=True)
    # CRITICAL: block further artifact reads and revoke the lease before cooperative stop.
    receipt = ArtifactCancellationReceipt(run_id=run.run_id, new_reads_blocked=True, lease_revoked=True, cooperative_stop_acknowledged=True, untrusted_execution_count=0, occurred_at=occurred_at)
    return transition_artifact_run(cancelling, ArtifactRunState.CLEANING), receipt


def complete_artifact_cleanup(run: ArtifactRun, *, occurred_at: datetime, residual_resource_ids: tuple[str, ...], untrusted_execution_count: int) -> tuple[ArtifactRun, ArtifactCleanupReceipt]:
    _aware(occurred_at)
    if run.state is not ArtifactRunState.CLEANING: raise ValueError("artifact_run_not_cleaning")
    if untrusted_execution_count != 0: raise ValueError("artifact_untrusted_execution_detected")
    resources = tuple(sorted(set(residual_resource_ids)))
    if resources: raise ValueError("artifact_cleanup_residual_resources")
    final = ArtifactRunState.CANCELLED if run.cancellation_requested else ArtifactRunState.SUCCEEDED
    digest = hashlib.sha256(json.dumps(resources, separators=(",", ":")).encode()).hexdigest()
    return transition_artifact_run(run, final), ArtifactCleanupReceipt(run_id=run.run_id, residual_resource_count=0, untrusted_execution_count=0, inventory_sha256=digest, occurred_at=occurred_at)


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError("artifact_time_invalid")
