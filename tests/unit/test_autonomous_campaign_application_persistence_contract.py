from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0029_autonomous_campaign_application.py"


def test_r171_migration_is_additive_single_head_and_runtime_expected() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["0033_bounded_child_replanning"]
    assert scripts.get_revision("0029_autonomous_campaign_app").down_revision == ("0028_observation_replanning")
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == ("0033_bounded_child_replanning")


def test_r171_metadata_is_tenant_bound_closed_and_audit_linked() -> None:
    applications = metadata.tables["autonomous_campaign_applications"]
    events = metadata.tables["autonomous_campaign_application_events"]
    assert {
        "id",
        "tenant_id",
        "contract_version",
        "engagement_id",
        "target_id",
        "created_by_user_id",
        "intent_sha256",
        "source_binding_sha256",
        "mode",
        "lifecycle_state",
        "aggregate_revision",
    }.issubset(applications.c.keys())
    assert {
        "application_id",
        "audit_event_id",
        "event_sequence",
        "previous_state",
        "next_state",
        "request_sha256",
        "lifecycle_sha256",
        "event_payload",
    }.issubset(events.c.keys())
    names = {constraint.name for constraint in events.constraints}
    assert "fk_autonomous_campaign_event_tenant_application" in names
    assert "fk_autonomous_campaign_event_audit" in names


def test_r171_migration_enforces_rls_append_only_history_and_safe_downgrade() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    for table in (
        "autonomous_campaign_applications",
        "autonomous_campaign_application_events",
    ):
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in source
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in source
        assert f"CREATE POLICY {table}_tenant_isolation" in source
    assert "autonomous_campaign_application_event_immutable" in source
    assert "autonomous_campaign_application_downgrade_requires_empty_state" in source
    assert "def _has_persisted_application_state" in source
    assert "_has_persisted_application_state(connection)" in source
    assert "NO FORCE ROW LEVEL SECURITY" in source
