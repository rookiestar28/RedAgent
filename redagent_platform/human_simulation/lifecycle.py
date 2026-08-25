"""compat_112 delivery lifecycle with lease-first stop and mandatory deletion."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum


class CampaignRunState(str, Enum):
    PLANNED = "planned"; RENDERED = "rendered"; PREVIEW_APPROVED = "preview_approved"
    TEST_SINK_DELIVERED = "test_sink_delivered"; SEND_APPROVED = "send_approved"; SINK_DELIVERED = "sink_delivered"
    OBSERVED = "observed"; STOPPING = "stopping"; DELETING = "deleting"; DELETED = "deleted"; FAILED = "failed"


_TRANSITIONS = {
    CampaignRunState.PLANNED: {CampaignRunState.RENDERED, CampaignRunState.STOPPING},
    CampaignRunState.RENDERED: {CampaignRunState.PREVIEW_APPROVED, CampaignRunState.STOPPING},
    CampaignRunState.PREVIEW_APPROVED: {CampaignRunState.TEST_SINK_DELIVERED, CampaignRunState.STOPPING},
    CampaignRunState.TEST_SINK_DELIVERED: {CampaignRunState.SEND_APPROVED, CampaignRunState.STOPPING},
    CampaignRunState.SEND_APPROVED: {CampaignRunState.SINK_DELIVERED, CampaignRunState.STOPPING},
    CampaignRunState.SINK_DELIVERED: {CampaignRunState.OBSERVED, CampaignRunState.STOPPING, CampaignRunState.DELETING},
    CampaignRunState.OBSERVED: {CampaignRunState.STOPPING, CampaignRunState.DELETING},
    CampaignRunState.STOPPING: {CampaignRunState.DELETING}, CampaignRunState.DELETING: {CampaignRunState.DELETED, CampaignRunState.FAILED},
    CampaignRunState.DELETED: set(), CampaignRunState.FAILED: set(),
}


@dataclass(frozen=True, kw_only=True)
class CampaignRun:
    run_id: str; state: CampaignRunState; delivery_lease_id: str; stop_requested: bool = False


@dataclass(frozen=True, kw_only=True)
class StopReceipt:
    run_id: str; new_delivery_blocked: bool; delivery_lease_revoked: bool; recall_claimed: bool; occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class DeletionCompletion:
    run_id: str; residual_count: int; zero_residual: bool; occurred_at: datetime


def transition_campaign_run(run: CampaignRun, next_state: CampaignRunState) -> CampaignRun:
    if next_state not in _TRANSITIONS[run.state]:
        raise ValueError("human_run_transition_invalid")
    return replace(run, state=next_state)


def request_stop(run: CampaignRun, *, occurred_at: datetime) -> tuple[CampaignRun, StopReceipt]:
    if CampaignRunState.STOPPING not in _TRANSITIONS[run.state]:
        raise ValueError("human_run_not_stoppable")
    # CRITICAL: block new delivery and revoke its lease before stop acknowledgement; never claim recall.
    stopping = replace(run, state=CampaignRunState.STOPPING, stop_requested=True)
    receipt = StopReceipt(run_id=run.run_id, new_delivery_blocked=True, delivery_lease_revoked=True,
        recall_claimed=False, occurred_at=occurred_at)
    return transition_campaign_run(stopping, CampaignRunState.DELETING), receipt


def complete_deletion(run: CampaignRun, *, occurred_at: datetime, residual_ids: tuple[str, ...]) -> tuple[CampaignRun, DeletionCompletion]:
    if run.state is not CampaignRunState.DELETING:
        raise ValueError("human_run_not_deleting")
    residual = tuple(sorted(set(residual_ids)))
    if residual:
        raise ValueError("human_deletion_residual")
    return transition_campaign_run(run, CampaignRunState.DELETED), DeletionCompletion(
        run_id=run.run_id, residual_count=0, zero_residual=True, occurred_at=occurred_at)
