from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


def test_policy_tables_remain_in_metadata_after_revision_0008() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0026_campaign_plan_admission"
    for name in (
        "policy_bundle_revisions", "policy_bundle_promotions", "policy_agent_status",
        "policy_decisions", "policy_boundary_receipts", "policy_log_receipts",
    ):
        assert name in metadata.tables
        columns = metadata.tables[name].columns
        assert {"tenant_id", "version", "created_at", "updated_at"}.issubset(columns.keys())
