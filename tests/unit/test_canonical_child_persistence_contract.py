from __future__ import annotations

from alembic.config import Config
from alembic.script import ScriptDirectory
from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


def test_canonical_child_has_one_append_only_link_and_tenant_bound_peak_settlement():
    assert "campaign_child_capacity_settlements" in metadata.tables
    assert "autonomous_campaign_child_replans" in metadata.tables
    child = metadata.tables["autonomous_campaign_child_replans"]
    settlement = metadata.tables["campaign_child_capacity_settlements"]
    assert any(tuple(c.columns.keys()) == ("tenant_id", "application_id") for c in child.constraints)
    assert any(tuple(c.columns.keys()) == ("tenant_id", "parent_reservation_id") for c in settlement.constraints)
    assert {"parent_execution_run_id", "parent_run_version", "source_provenance_sha256",
            "latest_effect_completed_at", "capacity_available_at", "child_revision_sha256"}.issubset(settlement.c.keys())
    assert {"lineage_sha256", "preview_id", "proposal_id", "settlement_id", "source_payload"}.issubset(child.c.keys())


def test_canonical_child_migration_is_the_single_additive_runtime_head():
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["0033_bounded_child_replanning"]
    assert scripts.get_revision("0033_bounded_child_replanning").down_revision == "0032_owned_execution_mode"
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0033_bounded_child_replanning"
