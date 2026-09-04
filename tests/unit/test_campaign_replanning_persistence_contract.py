from __future__ import annotations

import inspect
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0028_observation_replanning.py"
TABLES = {
    "campaign_observation_decisions",
    "trusted_campaign_observations",
    "campaign_replan_proposals",
    "campaign_replan_acceptances",
}
PRODUCT_SOURCES = (
    ROOT / "redagent_platform/campaign_service/trusted_observations.py",
    ROOT / "redagent_platform/campaign_service/replanning_contracts.py",
    ROOT / "redagent_platform/campaign_service/replanning.py",
    ROOT / "redagent_platform/campaign_service/replanning_repository.py",
    ROOT / "redagent_platform/persistence/models/campaign_replanning.py",
    MIGRATION,
)


def test_replanning_migration_is_the_single_additive_head() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["0031_autonomous_admission_start"]
    assert scripts.get_revision("0028_observation_replanning").down_revision == (
        "0027_campaign_dag_execution"
    )
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == (
        "0031_autonomous_admission_start"
    )


def test_replanning_metadata_is_tenant_owned_append_only_and_digest_bound() -> None:
    assert MIGRATION.is_file()
    source = MIGRATION.read_text(encoding="utf-8")
    assert TABLES.issubset(metadata.tables) and TABLES.issubset(TENANT_TABLE_NAMES)
    for table_name in TABLES:
        assert {"id", "tenant_id", "version", "created_at", "updated_at"}.issubset(
            metadata.tables[table_name].c.keys()
        )
        assert f'"{table_name}"' in source
    assert "ENABLE ROW LEVEL SECURITY" in source
    assert "FORCE ROW LEVEL SECURITY" in source
    assert "_tenant_isolation" in source
    assert "_immutable" in source
    assert {
        "campaign_id",
        "candidate_sha256",
        "decision_sha256",
        "outcome",
        "candidate_payload",
        "decision_payload",
    }.issubset(metadata.tables["campaign_observation_decisions"].c.keys())
    assert {
        "decision_id",
        "campaign_id",
        "observation_sha256",
        "provenance_sha256",
        "trusted_payload",
    }.issubset(metadata.tables["trusted_campaign_observations"].c.keys())
    assert {
        "campaign_id",
        "request_sha256",
        "proposal_sha256",
        "parent_revision_sha256",
        "child_revision_sha256",
        "observation_history_sha256",
        "residual_budget_sha256",
        "planned_budget_sha256",
        "lifecycle_epoch",
        "policy_revocation_epoch",
        "roe_revocation_epoch",
        "kill_switch_epoch",
        "proposal_payload",
    }.issubset(metadata.tables["campaign_replan_proposals"].c.keys())
    assert {
        "proposal_id",
        "campaign_id",
        "admission_receipt_id",
        "accepted_replan_sha256",
        "acceptance_payload",
    }.issubset(metadata.tables["campaign_replan_acceptances"].c.keys())


def test_replanning_storage_has_no_raw_payload_command_or_network_surface() -> None:
    from redagent_platform.campaign_service import replanning_repository

    source = inspect.getsource(replanning_repository).lower()
    for forbidden in (
        "raw_payload",
        "raw_evidence",
        "credential",
        "password",
        "subprocess",
        "socket",
        "runner_service",
        "execute_payload",
    ):
        assert forbidden not in source
    columns = {
        column.name.lower()
        for table_name in TABLES
        for column in metadata.tables[table_name].columns
    }
    assert {"command", "credentials", "secret", "token", "raw_payload"}.isdisjoint(columns)


def test_replanning_product_surface_is_item_neutral_and_contains_no_private_authority_docs() -> None:
    assert not (ROOT / ".planning").exists()
    assert not (ROOT / "ROADMAP.md").exists()
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in PRODUCT_SOURCES)
    assert "r160" not in combined
    assert ".planning/" not in combined
    assert "roadmap.md" not in combined
