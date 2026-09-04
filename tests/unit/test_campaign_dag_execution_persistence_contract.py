from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, UniqueConstraint

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata
from redagent_platform.campaign_service.dag_execution_contracts import DagNodeState, DagRunState
from redagent_platform.campaign_service.authority_envelope import CampaignAuthorityLifecycleState


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0027_campaign_dag_execution.py"


def test_dag_execution_migration_is_the_single_head_and_runtime_default() -> None:
    scripts = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    assert scripts.get_heads() == ["0029_autonomous_campaign_app"]
    assert scripts.get_revision("0027_campaign_dag_execution").down_revision == (
        "0026_campaign_plan_admission"
    )
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == (
        "0029_autonomous_campaign_app"
    )
    source = MIGRATION.read_text(encoding="utf-8")
    assert "OLD.input_payload::jsonb" in source
    assert "NEW.input_payload::jsonb" in source


def test_metadata_has_exact_new_tables_and_shared_lineage_columns() -> None:
    assert {
        "campaign_execution_runs",
        "campaign_execution_nodes",
        "campaign_execution_authority_observations",
    } <= set(metadata.tables)

    effects = metadata.tables["campaign_effects"]
    jobs = metadata.tables["jobs"]
    assert effects.c.strategy_revision_id.nullable is True
    assert {
        "execution_run_id",
        "pre_io_policy_decision_id",
        "pre_io_policy_input_sha256",
        "pre_io_policy_valid_until",
        "pre_io_authorized_at",
    } <= set(effects.c.keys())
    assert "execution_run_id" in jobs.c
    assert _has_check(effects, "campaign_effect_lineage_exactly_one")
    assert _has_check(jobs, "jobs_campaign_lineage_not_ambiguous")
    assert _has_unique(effects, {"tenant_id", "execution_run_id", "node_id"})


def test_run_relationships_are_tenant_campaign_plan_bound() -> None:
    runs = metadata.tables["campaign_execution_runs"]
    nodes = metadata.tables["campaign_execution_nodes"]
    observations = metadata.tables["campaign_execution_authority_observations"]
    assert _has_unique(runs, {"tenant_id", "id", "campaign_id"})
    assert _has_unique(runs, {"tenant_id", "campaign_id", "plan_sha256"})
    assert _has_unique(runs, {"tenant_id", "campaign_id", "idempotency_key"})
    assert _has_unique(nodes, {"tenant_id", "execution_run_id", "node_id"})
    assert _has_unique(observations, {"tenant_id", "execution_run_id", "observation_sequence"})
    assert _has_fk(
        runs,
        ("tenant_id", "admission_receipt_id", "campaign_id"),
        ("plan_admission_receipts.tenant_id", "plan_admission_receipts.id", "plan_admission_receipts.campaign_id"),
    )


def test_execution_state_and_epoch_columns_match_the_typed_authority_contract() -> None:
    runs = metadata.tables["campaign_execution_runs"]
    nodes = metadata.tables["campaign_execution_nodes"]
    observations = metadata.tables["campaign_execution_authority_observations"]
    epoch_columns = {
        "lifecycle_epoch",
        "policy_revocation_epoch",
        "roe_revocation_epoch",
        "kill_switch_epoch",
    }
    assert epoch_columns <= set(runs.c.keys())
    assert epoch_columns <= set(observations.c.keys())
    assert {"principal_id", "signed_authority_sha256", "reserved_budget_sha256"} <= set(runs.c.keys())
    assert "reservation_sha256" not in runs.c
    run_state_sql = _check_sql(runs, "campaign_execution_run_state_closed")
    node_state_sql = _check_sql(nodes, "campaign_execution_node_state_closed")
    lifecycle_state_sql = _check_sql(
        observations, "campaign_execution_authority_observation_state_closed"
    )
    assert {item.value for item in DagRunState} <= set(run_state_sql.replace("'", "").split())
    assert {item.value for item in DagNodeState} <= set(node_state_sql.replace("'", "").split())
    assert {item.value for item in CampaignAuthorityLifecycleState} <= set(
        lifecycle_state_sql.replace("'", "").split()
    )
    assert _has_fk(
        runs,
        ("tenant_id", "reservation_id", "campaign_id"),
        (
            "campaign_budget_reservations.tenant_id",
            "campaign_budget_reservations.id",
            "campaign_budget_reservations.campaign_id",
        ),
    )


def test_migration_enables_rls_and_immutable_input_observation_guards() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    for table in (
        "campaign_execution_runs",
        "campaign_execution_nodes",
        "campaign_execution_authority_observations",
    ):
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in source
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in source
    assert "campaign_execution_run_input_immutable" in source
    assert "campaign_execution_node_input_immutable" in source
    assert "campaign_execution_authority_observation_immutable" in source


def _has_unique(table, columns: set[str]) -> bool:
    return any(
        isinstance(constraint, UniqueConstraint)
        and {column.name for column in constraint.columns} == columns
        for constraint in table.constraints
    )


def _has_check(table, name: str) -> bool:
    return any(
        isinstance(constraint, CheckConstraint) and constraint.name == name
        for constraint in table.constraints
    )


def _check_sql(table, name: str) -> str:
    return next(
        str(constraint.sqltext).replace(",", " ").replace("(", " ").replace(")", " ")
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
        and constraint.name is not None
        and str(constraint.name).endswith(name)
    )


def _has_fk(table, local: tuple[str, ...], remote: tuple[str, ...]) -> bool:
    return any(
        isinstance(constraint, ForeignKeyConstraint)
        and tuple(column.name for column in constraint.columns) == local
        and tuple(element.target_fullname for element in constraint.elements) == remote
        for constraint in table.constraints
    )
