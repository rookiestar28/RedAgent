from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


TABLES = (
    "runner_classes",
    "runner_registrations",
    "runner_identities",
    "execution_capability_manifests",
    "artifact_verification_receipts",
    "runner_job_manifests",
    "runner_pull_leases",
    "runner_lifecycle_events",
    "runner_execution_receipts",
)


def test_runner_tables_are_tenant_owned_and_database_requires_revision_0008() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0029_autonomous_campaign_app"
    for name in TABLES:
        assert name in metadata.tables
        columns = metadata.tables[name].columns
        assert {"tenant_id", "version", "created_at", "updated_at"}.issubset(columns.keys())


def test_runner_relations_reference_jobs_registrations_manifests_leases_and_evidence_by_id_only() -> None:
    assert {foreign.column.table.name for foreign in metadata.tables["runner_job_manifests"].foreign_keys} >= {"jobs", "runner_registrations"}
    assert {foreign.column.table.name for foreign in metadata.tables["runner_pull_leases"].foreign_keys} == {"runner_job_manifests", "runner_registrations"}
    assert {foreign.column.table.name for foreign in metadata.tables["runner_lifecycle_events"].foreign_keys} == {"runner_pull_leases"}
    assert {foreign.column.table.name for foreign in metadata.tables["runner_execution_receipts"].foreign_keys} >= {"runner_pull_leases", "evidence_artifacts"}
