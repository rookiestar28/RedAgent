from __future__ import annotations

from sqlalchemy import UniqueConstraint

from redagent_platform.persistence.models import metadata


def test_r096_metadata_contains_campaign_command_and_orchestration_columns() -> None:
    assert {"campaigns", "workflow_commands"} <= set(metadata.tables)
    jobs = metadata.tables["jobs"]
    assert {
        "created_by_user_id",
        "campaign_id",
        "workflow_id",
        "workflow_run_id",
        "orchestration_state",
        "orchestration_revision",
        "current_gate",
        "failure_code",
        "retry_count",
        "dispatch_blocked",
        "stop_requested",
    } <= set(jobs.columns.keys())


def test_r096_database_uniqueness_prevents_duplicate_workflow_and_logical_command() -> None:
    jobs = metadata.tables["jobs"]
    campaigns = metadata.tables["campaigns"]
    commands = metadata.tables["workflow_commands"]

    assert _has_unique(jobs, {"tenant_id", "workflow_id"})
    assert _has_unique(campaigns, {"tenant_id", "workflow_id"})
    assert _has_unique(commands, {"tenant_id", "job_id", "command_id"})


def _has_unique(table, columns: set[str]) -> bool:
    return any(
        isinstance(constraint, UniqueConstraint)
        and {column.name for column in constraint.columns} == columns
        for constraint in table.constraints
    )
