from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0014_r107_network_assessment.py"


def test_revision_0014_is_expected_database_head() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0029_autonomous_campaign_app"
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0014_r107_network"' in source
    assert 'down_revision = "0013_r106_api_diff"' in source


def test_revision_0014_owns_scope_run_decision_result_and_cleanup_truth() -> None:
    source = REVISION.read_text(encoding="utf-8")
    required = {
        "network_engine_artifacts",
        "network_adapter_declarations",
        "network_profiles",
        "network_topology_attestations",
        "network_target_sets",
        "network_plans",
        "network_plan_tuples",
        "network_runs",
        "network_gateway_decisions",
        "network_observations",
        "network_cancellation_receipts",
        "network_cleanup_receipts",
    }
    assert required <= set(_table_names(source))
    assert "ENABLE ROW LEVEL SECURITY" in source
    assert "FORCE ROW LEVEL SECURITY" in source
    assert "redagent.tenant_id" in source
    assert "uq_network_tuple_tenant_plan_tuple" in source
    assert "uq_network_decision_tenant_id" in source


def test_revision_0014_tables_are_present_in_runtime_metadata_and_tenant_owned() -> None:
    required = {
        "network_engine_artifacts", "network_adapter_declarations", "network_profiles",
        "network_topology_attestations", "network_target_sets", "network_plans",
        "network_plan_tuples", "network_runs", "network_gateway_decisions",
        "network_observations", "network_cancellation_receipts", "network_cleanup_receipts",
    }
    assert required <= set(metadata.tables)
    assert required <= TENANT_TABLE_NAMES
    for name in required:
        assert {"id", "tenant_id", "version", "created_at", "updated_at"} <= set(metadata.tables[name].c.keys())


def _table_names(source: str) -> tuple[str, ...]:
    import re

    return tuple(re.findall(r'_create\("([a-z_]+)"', source))
