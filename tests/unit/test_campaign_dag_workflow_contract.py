from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / "redagent_platform/orchestration/dag_execution_workflow.py"


def test_dag_workflow_uses_only_frozen_names_and_patch_marker() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert '@workflow.defn(name="redagent.campaign-dag-execution.v1")' in source
    assert '"redagent.campaign-dag.reconcile.v1"' in source
    assert '"redagent.campaign-dag.dispatch.v1"' in source
    assert '"redagent.campaign-dag.contain.v1"' in source
    assert '@workflow.signal(name="stop")' in source
    assert '@workflow.query(name="status")' in source
    assert 'workflow.patched("campaign-dag-v1-cancel-wait")' in source


def test_workflow_has_no_database_policy_runner_or_wall_clock_import() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    for forbidden in (
        "sqlalchemy",
        "persistence",
        "policy_service",
        "runner_service",
        "datetime.now",
        "uuid4",
    ):
        assert forbidden not in source
