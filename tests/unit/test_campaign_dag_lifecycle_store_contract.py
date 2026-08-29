from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "redagent_platform/campaign_service/dag_lifecycle_store.py"


def test_current_lifecycle_is_reconstructed_from_locked_relational_authority() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert 'metadata.tables["campaign_execution_runs"]' in source
    assert 'metadata.tables["plan_admission_receipts"]' in source
    assert 'metadata.tables["campaign_budget_reservations"]' in source
    assert 'metadata.tables["containment_controls"]' in source
    assert "select(func.now())" in source
    assert "with_for_update()" in source
    assert "CampaignAuthorityLifecycleV2(" in source


def test_current_lifecycle_does_not_treat_observation_history_as_authority() -> None:
    source = STORE.read_text(encoding="utf-8")

    assert "campaign_execution_authority_observations" not in source
    assert 'reason_code="authority_expired"' in source
    assert 'reason_code="kill_switch_active"' in source
    assert "kill_switch_epoch=int(run[\"kill_switch_epoch\"]) + 1" in source
