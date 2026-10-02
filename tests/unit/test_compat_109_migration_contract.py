from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0016_r109_identity_saas.py"


def test_revision_0016_is_expected_database_head() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0033_bounded_child_replanning"
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0016_r109_identity"' in source
    assert 'down_revision = "0015_r108_cloud"' in source


def test_revision_0016_owns_snapshot_baseline_exception_graph_and_cleanup_truth() -> None:
    expected = {
        "identity_adapter_artifacts", "identity_provider_profiles", "identity_operation_manifests",
        "identity_tenant_bindings", "identity_baseline_artifacts", "identity_collection_plans",
        "identity_collection_runs", "identity_snapshot_pages", "identity_snapshot_resources",
        "identity_baseline_evaluations", "identity_exception_annotations", "identity_exception_approvals",
        "identity_graph_approvals", "identity_graph_nodes", "identity_graph_edges",
        "identity_cleanup_receipts",
    }
    source = REVISION.read_text(encoding="utf-8")
    assert expected <= set(metadata.tables) and expected <= TENANT_TABLE_NAMES
    assert "FORCE ROW LEVEL SECURITY" in source and "redagent.tenant_id" in source
    for name in expected:
        assert f'"{name}"' in source
        assert {"id", "tenant_id", "version", "created_at", "updated_at"} <= set(metadata.tables[name].c.keys())
