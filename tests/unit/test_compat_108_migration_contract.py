from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0015_r108_cloud_connectors.py"


def test_revision_0015_is_expected_database_head() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0029_autonomous_campaign_app"
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0015_r108_cloud"' in source
    assert 'down_revision = "0014_r107_network"' in source


def test_revision_0015_owns_adapter_snapshot_result_and_cleanup_truth() -> None:
    source = REVISION.read_text(encoding="utf-8")
    expected = {
        "cloud_adapter_artifacts",
        "cloud_provider_profiles",
        "cloud_operation_manifests",
        "cloud_identity_bindings",
        "cloud_control_packs",
        "cloud_offline_artifacts",
        "cloud_collection_plans",
        "cloud_collection_runs",
        "cloud_snapshot_pages",
        "cloud_snapshot_resources",
        "cloud_check_results",
        "cloud_cleanup_receipts",
    }
    assert expected <= TENANT_TABLE_NAMES
    assert expected <= set(metadata.tables)
    for table in expected:
        assert f'"{table}"' in source
        assert f'ALTER TABLE "{{table}}" FORCE ROW LEVEL SECURITY' in source
        assert "tenant_id" in metadata.tables[table].columns
