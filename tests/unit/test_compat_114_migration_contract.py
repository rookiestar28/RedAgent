from __future__ import annotations

from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0021_r114_mcp_workbench.py"
TABLES = {
    "mcp_server_registrations", "mcp_transport_attestations", "mcp_inventory_revisions",
    "mcp_inventory_items", "mcp_freeze_events", "workbench_campaign_drafts", "workbench_trust_items",
    "workbench_disclosures", "workbench_reviewer_decisions", "workbench_conclusions",
    "workbench_lifecycle_events", "mcp_qualification_receipts",
}


def test_r114_revision_exists_and_advances_head() -> None:
    assert REVISION.is_file(), "compat_114 RED: revision 0021 MCP/workbench persistence is missing"
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0021_r114_mcp"' in source and 'down_revision = "0020_r113_agent"' in source
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0031_autonomous_admission_start"


def test_revision_0021_defines_force_rls_owned_tables() -> None:
    source = REVISION.read_text(encoding="utf-8")
    assert TABLES.issubset(metadata.tables) and TABLES.issubset(TENANT_TABLE_NAMES)
    assert "FORCE ROW LEVEL SECURITY" in source and "redagent.tenant_id" in source
    for table_name in TABLES:
        assert table_name in source
        assert {"id", "tenant_id", "version", "created_at", "updated_at"}.issubset(
            metadata.tables[table_name].c.keys()
        )


def test_r114_persistence_is_digest_only_and_cannot_represent_transport_or_sensitive_material() -> None:
    forbidden = {"prompt", "message", "reasoning", "raw_evidence", "credential", "secret", "token", "password",
                 "api_key", "command", "arguments", "environment", "headers", "url", "content", "input", "output"}
    for table_name in TABLES:
        assert forbidden.isdisjoint({column.name.lower() for column in metadata.tables[table_name].columns})
