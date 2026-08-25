from datetime import datetime, timezone

import pytest

from redagent_platform.human_simulation.events import MinimizedEvent, sign_event, verify_event
from redagent_platform.human_simulation.lifecycle import CampaignRun, CampaignRunState, complete_deletion, request_stop, transition_campaign_run


NOW = datetime(2026, 7, 11, 17, 0, tzinfo=timezone.utc)
KEY = b"r112-local-fixture-event-key-32b"


def test_signed_minimized_event_verifies_once_and_rejects_replay_tamper_and_late():
    event = MinimizedEvent(event_id="event-r112", campaign_id="r112-sink-email-canary-v1",
        message_id="message-r112", category="synthetic_accepted", occurred_at=NOW)
    envelope = sign_event(event=event, key=KEY); seen: set[str] = set()
    assert verify_event(envelope=envelope, key=KEY, now=NOW, seen_event_ids=seen) == event
    with pytest.raises(ValueError, match="human_event_replay"):
        verify_event(envelope=envelope, key=KEY, now=NOW, seen_event_ids=seen)
    with pytest.raises(ValueError, match="human_event_signature_invalid"):
        verify_event(envelope=envelope.__class__(**{**envelope.__dict__, "signature_sha256": "f" * 64}),
            key=KEY, now=NOW, seen_event_ids=set())


def test_stop_blocks_delivery_revokes_lease_and_deletion_requires_zero_residual():
    run = CampaignRun(run_id="run-r112", state=CampaignRunState.SINK_DELIVERED, delivery_lease_id="lease-r112")
    deleting, stop = request_stop(run, occurred_at=NOW)
    assert stop.new_delivery_blocked and stop.delivery_lease_revoked and stop.recall_claimed is False
    with pytest.raises(ValueError, match="human_deletion_residual"):
        complete_deletion(deleting, occurred_at=NOW, residual_ids=("message-r112",))
    final, receipt = complete_deletion(deleting, occurred_at=NOW, residual_ids=())
    assert final.state is CampaignRunState.DELETED and receipt.zero_residual


def test_normal_success_still_requires_delete_phase():
    run = CampaignRun(run_id="run-r112", state=CampaignRunState.PLANNED, delivery_lease_id="lease-r112")
    for state in (CampaignRunState.RENDERED, CampaignRunState.PREVIEW_APPROVED, CampaignRunState.TEST_SINK_DELIVERED,
                  CampaignRunState.SEND_APPROVED, CampaignRunState.SINK_DELIVERED, CampaignRunState.OBSERVED,
                  CampaignRunState.DELETING):
        run = transition_campaign_run(run, state)
    final, _ = complete_deletion(run, occurred_at=NOW, residual_ids=())
    assert final.state is CampaignRunState.DELETED
