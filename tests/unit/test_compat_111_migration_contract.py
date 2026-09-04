from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0018_r111_purple_runtime.py"
TABLES = {
    "purple_adapter_artifacts", "purple_abilities", "purple_ability_phases", "purple_detection_expectations",
    "purple_lab_bindings", "purple_approvals", "purple_execution_plans", "purple_runs", "purple_snapshots",
    "purple_action_receipts", "purple_telemetry_events", "purple_cleanup_receipts", "purple_teardown_receipts",
    "purple_rehearsal_receipts",
}


def test_revision_0018_is_expected_head_and_force_rls_owned():
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0029_autonomous_campaign_app"
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0018_r111_purple"' in source and 'down_revision = "0017_r110_artifact"' in source
    assert "FORCE ROW LEVEL SECURITY" in source and "redagent.tenant_id" in source
    assert TABLES <= set(metadata.tables) and TABLES <= TENANT_TABLE_NAMES
    for name in TABLES:
        assert f'"{name}"' in source
        assert {"id", "tenant_id", "version", "created_at", "updated_at"} <= set(metadata.tables[name].c.keys())


def test_persistence_binds_approval_telemetry_cleanup_and_teardown_truth():
    approvals = set(metadata.tables["purple_approvals"].c.keys())
    telemetry = set(metadata.tables["purple_telemetry_events"].c.keys())
    teardown = set(metadata.tables["purple_teardown_receipts"].c.keys())
    assert {"ability_sha256", "adapter_sha256", "lab_snapshot_sha256", "requester_id", "approver_id", "executor_id"} <= approvals
    assert {"collector_id", "event_schema", "event_sha256", "integrity_verified", "correlated"} <= telemetry
    assert {"lease_revoked", "dispatch_blocked", "residual_resource_count", "teardown_verified"} <= teardown
