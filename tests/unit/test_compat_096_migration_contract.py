from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[2]


def test_r096_revision_is_single_head_and_reversible() -> None:
    scripts = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    revision = (ROOT / "migrations" / "versions" / "0003_r096_durable_workflows.py").read_text(encoding="utf-8")

    assert scripts.get_revision("0003_r096_durable_workflows") is not None
    assert 'down_revision = "0002_r094_enterprise_identity"' in revision
    assert "def downgrade()" in revision
    assert 'op.drop_table("workflow_commands")' in revision
    assert 'op.drop_table("campaigns")' in revision


def test_r096_revision_adds_tenant_owned_campaign_command_and_job_reconciliation_state() -> None:
    revision = (ROOT / "migrations" / "versions" / "0003_r096_durable_workflows.py").read_text(encoding="utf-8")

    for table in ("campaigns", "workflow_commands"):
        assert f'op.create_table("{table}"' in revision
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in revision
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in revision
        assert f"CREATE POLICY {table}_tenant_isolation" in revision
    for column in (
        "campaign_id",
        "workflow_id",
        "workflow_run_id",
        "orchestration_state",
        "orchestration_revision",
        "current_gate",
        "failure_code",
        "retry_count",
        "dispatch_blocked",
        "stop_requested",
    ):
        assert f'"{column}"' in revision
    assert 'sa.UniqueConstraint("tenant_id", "job_id", "command_id")' in revision
