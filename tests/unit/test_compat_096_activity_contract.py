from __future__ import annotations

import inspect

from temporalio import activity

from redagent_platform.orchestration.activities import WorkflowActivities
from redagent_platform.orchestration.contracts import ActivityCommand


def test_activity_command_carries_canonical_request_hash_not_reason_or_payload() -> None:
    command = ActivityCommand(
        schema_version="1.0",
        tenant_id="tenant-1",
        job_id="job-1",
        command_id="command-1",
        action="approve",
        actor_user_id="approver-1",
        expected_revision=2,
        policy_reference="policy:compat_096:1",
        request_hash="a" * 64,
    )

    assert command.request_hash == "a" * 64
    assert not hasattr(command, "reason")
    assert not hasattr(command, "payload")


def test_activity_names_are_fixed_typed_and_not_dynamic_operator_input() -> None:
    definitions = {
        activity._Definition.must_from_callable(WorkflowActivities.admit_job).name,
        activity._Definition.must_from_callable(WorkflowActivities.apply_command).name,
        activity._Definition.must_from_callable(WorkflowActivities.record_system_state).name,
        activity._Definition.must_from_callable(WorkflowActivities.admit_campaign).name,
    }

    assert definitions == {
        "r096_admit_job",
        "r096_apply_command",
        "r096_record_system_state",
        "r096_admit_campaign",
    }


def test_activity_module_contains_database_boundary_but_no_runner_target_or_secret_resolution() -> None:
    source = inspect.getsource(__import__("redagent_platform.orchestration.activities", fromlist=["*"])).lower()

    assert "async_sessionmaker" in source
    assert "controlplanerepository" in source
    for forbidden in ("runner_execution", "socket", "subprocess", "credential", "secret_provider", "httpx"):
        assert forbidden not in source
