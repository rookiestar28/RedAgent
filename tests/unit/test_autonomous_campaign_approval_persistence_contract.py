from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0030_autonomous_campaign_plan_approval.py"


def test_r172_additive_schema_is_current_rls_protected_and_append_only() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["0030_autonomous_plan_approval"]
    assert scripts.get_revision("0030_autonomous_plan_approval").down_revision == (
        "0029_autonomous_campaign_app"
    )
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == (
        "0030_autonomous_plan_approval"
    )
    assert {
        "autonomous_campaign_plan_previews",
        "autonomous_campaign_plan_approval_receipts",
    } <= set(metadata.tables)
    source = MIGRATION.read_text(encoding="utf-8")
    for table in (
        "autonomous_campaign_plan_previews",
        "autonomous_campaign_plan_approval_receipts",
    ):
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in source
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in source
        assert f"REVOKE UPDATE, DELETE ON {table} FROM PUBLIC" in source
    assert "autonomous_campaign_plan_preview_immutable" in source
    assert "autonomous_campaign_plan_approval_receipt_immutable" in source
    assert "autonomous_campaign_plan_approval_downgrade_requires_empty_state" in source
    assert "NO FORCE ROW LEVEL SECURITY" in source
