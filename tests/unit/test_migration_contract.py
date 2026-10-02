from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[2]


def test_alembic_has_one_head_and_initial_schema_revision() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    scripts = ScriptDirectory.from_config(config)

    assert scripts.get_heads() == ["0032_owned_execution_mode"]


def test_r118_retirement_migration_is_additive_reversible_and_table_scoped() -> None:
    revision = (
        ROOT / "migrations" / "versions" / "0024_r118_validation_retirement.py"
    ).read_text(encoding="utf-8")

    assert 'revision = "0024_r118_retirement"' in revision
    assert 'down_revision = "0023_r118_controller"' in revision
    assert "op.drop_table(ARTIFACT_TABLE)" in revision
    assert "op.drop_table(TABLE)" in revision
    assert "op.create_table(" in revision
    assert "ENABLE ROW LEVEL SECURITY" in revision
    assert "FORCE ROW LEVEL SECURITY" in revision


def test_identity_revision_owns_all_identity_tables_force_rls_and_reversible_order() -> None:
    revision = (ROOT / "migrations" / "versions" / "0002_r094_enterprise_identity.py").read_text(encoding="utf-8")

    for table in (
        "identity_providers",
        "tenant_memberships",
        "role_assignments",
        "login_transactions",
        "browser_sessions",
        "identity_replay_records",
        "jit_grants",
        "break_glass_reviews",
        "service_identities",
    ):
        assert f'"{table}"' in revision
    assert 'f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY"' in revision
    assert 'f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY"' in revision
    assert 'f"CREATE POLICY {table_name}_tenant_isolation ON {table_name} "' in revision
    assert 'down_revision = "0001_r093_control_plane"' in revision


def test_initial_revision_owns_inventory_rls_and_runtime_role_boundary() -> None:
    revision = (ROOT / "migrations" / "versions" / "0001_r093_control_plane.py").read_text(encoding="utf-8")

    for table in (
        "tenants",
        "users",
        "engagements",
        "targets",
        "roe_versions",
        "approvals",
        "policy_references",
        "jobs",
        "audit_events",
        "outbox_events",
        "idempotency_records",
        "issue_definitions",
        "finding_instances",
    ):
        assert f'"{table}"' in revision
    for table in ("users", "engagements", "targets", "jobs", "audit_events", "finding_instances"):
        assert f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY' in revision
        assert f'ALTER TABLE {table} FORCE ROW LEVEL SECURITY' in revision
        assert f'CREATE POLICY {table}_tenant_isolation' in revision
    assert "BYPASSRLS" in revision
    assert "runtime role must be non-owner" in revision


def test_application_never_silently_creates_schema() -> None:
    application_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "redagent_platform").rglob("*.py")
        if path.name != "models.py"
    )

    assert "create_all(" not in application_source


def test_alembic_engine_configuration_never_renders_a_plaintext_password() -> None:
    environment = (ROOT / "migrations" / "env.py").read_text(encoding="utf-8")

    assert "hide_password=False" not in environment
    assert "create_async_engine(settings.url" in environment
