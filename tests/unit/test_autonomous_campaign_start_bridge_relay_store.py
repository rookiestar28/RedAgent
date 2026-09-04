from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "redagent_platform/campaign_service/admission_start_relay_store.py"


def test_r173_relay_store_claims_only_committed_admitted_exact_bridge_rows() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert 'outbox.c.event_type == ADMISSION_START_BRIDGE_EVENT_TYPE' in source
    assert 'outbox.c.aggregate_type == "autonomous_campaign_start"' in source
    assert 'starts.c.id == row["aggregate_id"]' in source
    assert 'applications.c.lifecycle_state == "ADMITTED"' in source
    assert 'reservations.c.reservation_state == "reserved"' in source
    assert 'receipts.c.outcome == "admitted"' in source
    assert 'runs.c.run_state == "start_pending"' in source
    assert 'bound.start["expires_at"]' in source
    assert "min(" in source


def test_r173_relay_ack_queues_application_without_starting_r159_execution() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert 'start_state="execution_queued"' in source
    assert 'target=AutonomousCampaignLifecycle.EXECUTION_QUEUED' in source
    assert 'event_type="autonomous_campaign.execution_queued.v1"' in source
    assert 'run_state="running"' not in source
    assert 'campaign.dag.start.requested.v1' not in source


def test_r173_relay_store_has_distinct_unknown_mismatch_and_pre_io_failure_paths() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert "AutonomousCampaignStartBridgeFailure.UNKNOWN_START" in source
    assert "AutonomousCampaignStartBridgeFailure.BINDING_MISMATCH" in source
    assert "AutonomousCampaignAdmissionStartState.RECONCILIATION_REQUIRED" in source
    assert "AutonomousCampaignAdmissionStartState.MANUAL_REVIEW_REQUIRED" in source
    assert 'start_state="failed_before_io"' in source
    assert 'effect_started=False' in source
    assert '_require_single_row(changed_start, "start_bridge_relay_link_failure_conflict")' in source
    assert '_require_single_row(changed_run, "start_bridge_relay_run_failure_conflict")' in source
    assert '"start_bridge_relay_nodes_failure_conflict"' in source
