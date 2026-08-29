from pathlib import Path

from redagent_platform.campaign_service.dag_containment_store import _snapshot
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagContainActivityInputV1,
    DagStopSignalV1,
    DagWorkflowInputV1,
)


ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "redagent_platform/campaign_service/dag_containment_store.py"


def test_dag_containment_uses_canonical_control_and_projects_truthful_terminal_state() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert "ActivityContainmentOwner" in source
    assert "await self._containment.contain(" in source
    assert 'run_state = "contained"' in source
    assert 'run_state = "manual_review_required"' in source
    assert "stop_requested=True" in source
    assert 'action="campaign.dag.containment_recorded"' in source
    assert 'node_state = "contained"' in source
    assert 'node_state = "manual_review_required"' in source


def test_dag_containment_never_releases_budget_or_claims_cleanup_without_owner_result() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert "campaign_budget_reservations" not in source
    assert "active_concurrency = 0" in source
    assert 'if outcome == "contained"' in source
    assert "PostgresActivityContainmentOwner" not in source


def test_containment_terminal_replay_preserves_absent_reason() -> None:
    workflow = DagWorkflowInputV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        tenant_id="tenant-a",
        execution_run_id="run-a",
        input_sha256="a" * 64,
        plan_sha256="b" * 64,
        max_activity_attempts=2,
        max_transitions=8,
    )
    request = DagContainActivityInputV1(
        request=workflow,
        stop=DagStopSignalV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            signal_id="stop-a",
            actor_user_id="operator-a",
            reason_sha256="c" * 64,
        ),
        expected_revision=2,
    )

    snapshot = _snapshot(
        request,
        {
            "run_state": "failed",
            "version": 2,
            "transition_count": 1,
            "terminal_reason": None,
        },
    )

    assert snapshot.terminal_reason is None
