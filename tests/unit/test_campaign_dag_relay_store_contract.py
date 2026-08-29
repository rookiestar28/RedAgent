from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "redagent_platform/campaign_service/dag_relay_store.py"


def test_dag_relay_store_claims_only_its_event_and_updates_execution_run() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert 'outbox.c.event_type == "campaign.dag.start.requested.v1"' in source
    assert 'outbox.c.aggregate_type == "campaign_execution"' in source
    assert 'runs.c.id == row["aggregate_id"]' in source
    assert 'runs.c.workflow_id == expected_workflow_id' in source
    assert 'runs.c.request_sha256 == expected_request_sha256' in source
    assert 'run_state="running"' in source
    assert 'action="campaign.dag.workflow_started"' in source


def test_dag_relay_store_never_calls_r123_campaign_acknowledgement() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert ".acknowledge_workflow_start(" not in source
    assert '"workflow.start.requested.v1"' not in source
    assert "current_strategy_revision_id" not in source
