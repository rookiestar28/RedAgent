from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


TABLES = (
    "containment_controls", "containment_approvals", "containment_job_actions",
    "containment_phase_receipts", "containment_residual_risks", "containment_incidents",
    "quota_policies", "quota_usage", "quota_reservations", "quota_operations",
)


def test_r101_tables_are_tenant_owned_and_revision_0008_is_required() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0025_r123_closed_loop"
    for name in TABLES:
        assert name in metadata.tables
        assert {"tenant_id", "version", "created_at", "updated_at"} <= set(metadata.tables[name].c.keys())


def test_r101_relations_bind_controls_actions_phases_incidents_and_quota_operations() -> None:
    assert {item.column.table.name for item in metadata.tables["containment_job_actions"].foreign_keys} == {"containment_controls", "jobs"}
    assert {item.column.table.name for item in metadata.tables["containment_phase_receipts"].foreign_keys} == {"containment_job_actions"}
    assert {item.column.table.name for item in metadata.tables["quota_reservations"].foreign_keys} == {"quota_policies", "quota_usage"}
    assert {item.column.table.name for item in metadata.tables["quota_operations"].foreign_keys} == {"quota_policies", "quota_reservations", "containment_controls"}
