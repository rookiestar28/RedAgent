from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0022_r115_finding_operations.py"
TABLES = {
    "finding_import_sessions", "finding_import_records", "managed_issues", "finding_occurrences",
    "finding_evidence_links", "finding_operations", "finding_comments", "finding_risk_acceptances",
    "finding_retests", "finding_report_snapshots", "finding_report_claims", "finding_publications",
    "finding_connector_profiles", "finding_connector_deliveries", "finding_connector_attempts",
    "finding_connector_callbacks", "finding_connector_reconciliations",
}


def test_r115_revision_exists_and_advances_head() -> None:
    assert REVISION.is_file(), "compat_115 RED: revision 0022 finding operations persistence is missing"
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0022_r115_findings"' in source
    assert 'down_revision = "0021_r114_mcp"' in source
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0030_autonomous_plan_approval"


def test_revision_0022_defines_force_rls_owned_tables() -> None:
    source = REVISION.read_text(encoding="utf-8")
    assert TABLES.issubset(metadata.tables) and TABLES.issubset(TENANT_TABLE_NAMES)
    assert "FORCE ROW LEVEL SECURITY" in source and "redagent.tenant_id" in source
    for table_name in TABLES:
        assert table_name in source
        assert {"id", "tenant_id", "version", "created_at", "updated_at"}.issubset(
            metadata.tables[table_name].c.keys()
        )


def test_r115_persistence_cannot_represent_raw_sensitive_or_arbitrary_transport_material() -> None:
    forbidden = {
        "raw_evidence", "raw_payload", "secret", "password", "api_key", "access_token",
        "refresh_token", "command", "arguments", "environment", "headers", "destination_url",
    }
    for table_name in TABLES:
        assert forbidden.isdisjoint({column.name.lower() for column in metadata.tables[table_name].columns})
