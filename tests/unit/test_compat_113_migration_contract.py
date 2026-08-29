from __future__ import annotations

from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0020_r113_agent_kernel.py"
TABLES = {
    "agent_provider_profiles",
    "agent_projected_tools",
    "agent_runs",
    "agent_steps",
    "agent_proposals",
    "agent_approvals",
    "agent_budget_ledgers",
    "agent_working_memory",
    "agent_reviewed_facts",
    "agent_trace_envelopes",
    "agent_qualification_receipts",
}


def test_r113_revision_exists_before_relational_contract_checks() -> None:
    assert REVISION.is_file(), "compat_113 RED: revision 0020 agent-kernel persistence is missing"


def test_revision_0020_chains_from_r112_and_database_head_advances() -> None:
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0020_r113_agent"' in source
    assert 'down_revision = "0019_r112_human"' in source
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0027_campaign_dag_execution"


def test_revision_0020_defines_force_rls_tables_and_metadata_matches() -> None:
    source = REVISION.read_text(encoding="utf-8")
    assert TABLES.issubset(metadata.tables)
    assert TABLES.issubset(TENANT_TABLE_NAMES)
    assert "FORCE ROW LEVEL SECURITY" in source and "redagent.tenant_id" in source
    for table_name in TABLES:
        assert table_name in source
        table = metadata.tables[table_name]
        for required in ("id", "tenant_id", "version", "created_at", "updated_at"):
            assert required in table.c


def test_agent_persistence_cannot_represent_raw_prompts_outputs_reasoning_or_credentials() -> None:
    forbidden = {
        "prompt",
        "input",
        "output",
        "content",
        "message",
        "reasoning",
        "credential",
        "secret",
        "token",
        "password",
        "api_key",
        "arguments",
    }
    for table_name in TABLES:
        assert forbidden.isdisjoint({column.name.lower() for column in metadata.tables[table_name].columns})
