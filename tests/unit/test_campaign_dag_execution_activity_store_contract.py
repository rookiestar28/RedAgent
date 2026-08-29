from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "redagent_platform/campaign_service/dag_execution_activity_store.py"


def test_activity_store_rehydrates_and_uses_the_pure_frontier_reducer() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert "parse_attack_path_dag_revision(" in source
    assert "parse_planning_domain(" in source
    assert "derive_dag_frontier(" in source
    assert ".with_for_update()" in source
    assert "dag_workflow_request_sha256(request)" in source


def test_activity_store_uses_the_immutable_campaign_context_binding() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert "binding_from_campaign_context(context_payload, capability_id)" in source
    assert 'metadata.tables["campaign_strategy_revisions"]' in source
    assert "closed_execution_binding_for" not in source


def test_activity_store_reserves_only_the_shared_execution_lineage_effect() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert 'metadata.tables["campaign_effects"]' in source
    assert "campaign_execution_effects" not in source
    assert "strategy_revision_id=None" in source
    assert "execution_run_id=run[\"id\"]" in source
    assert '"schema_version": "redagent.campaign-dag-effect-intent/v1"' in source
    assert '"binding": asdict(binding)' in source
    assert "canonical_planning_sha256(intent)" in source


def test_activity_store_recovery_never_redispatches_dispatching_effect() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert 'effect["effect_state"] == "dispatching"' in source
    assert 'failure_code="worker_recovery_unknown"' in source
    assert "_reconciliation_command(" in source
    assert "DagActivityAction.RECONCILE" in source
    assert "DagActivityAction.WAIT" in source
