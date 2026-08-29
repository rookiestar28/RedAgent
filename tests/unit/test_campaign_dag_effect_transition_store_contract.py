from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "redagent_platform/campaign_service/dag_effect_transition_store.py"
REPOSITORY = ROOT / "redagent_platform/campaign_service/repository.py"


def test_dag_effect_store_delegates_to_the_shared_effect_state_machine() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert "class PostgresDagEffectTransitionStore:" in source
    for method in (
        "claim_effect(",
        "mark_effect_dispatching(",
        "record_effect_receipt(",
        "record_effect_ambiguity(",
        "record_effect_not_applied(",
        "record_effect_lookup_unavailable(",
    ):
        assert method in source
    assert 'metadata.tables["campaign_execution_nodes"]' in source
    assert 'metadata.tables["campaign_execution_runs"]' in source
    assert "CampaignReservationState.CONSUMED" in source
    assert "active_concurrency" in source


def test_shared_effect_audits_use_actual_lineage_namespace() -> None:
    source = REPOSITORY.read_text(encoding="utf-8")
    helper = source.split("def _effect_lineage_action(", 1)[1]
    helper = helper.split("\n\ndef ", 1)[0]

    assert 'row["execution_run_id"]' in helper
    assert 'action.replace("campaign.r123.", "campaign.dag.", 1)' in helper
    audit = source.split("async def _record_effect_audit(", 1)[1]
    audit = audit.split("\n    async def ", 1)[0]
    assert "action=_effect_lineage_action(row, action)" in audit


def test_dag_projection_updates_are_version_guarded_and_idempotent() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert "nodes.c.version == node[\"version\"]" in source
    assert "runs.c.version == run[\"version\"]" in source
    assert "if node[\"node_state\"] == target.value:" in source
    assert "max(int(run[\"active_concurrency\"]) - 1, 0)" in source
