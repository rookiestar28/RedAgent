from __future__ import annotations

from dataclasses import asdict, fields

import pytest

from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CommandAction,
    JobWorkflowInput,
    OperatorCommand,
    WorkflowState,
    command_request_hash,
    deterministic_job_workflow_id,
)


def _workflow_input(**overrides: object) -> JobWorkflowInput:
    values: dict[str, object] = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "tenant_id": "tenant-1",
        "job_id": "job-1",
        "engagement_id": "engagement-1",
        "roe_version_id": "roe-1",
        "policy_reference": "policy:compat_096:1",
        "expected_job_version": 1,
        "approval_timeout_seconds": 3600,
        "max_activity_attempts": 3,
        "runner_dispatch_enabled": False,
    }
    values.update(overrides)
    return JobWorkflowInput(**values)  # type: ignore[arg-type]


def _command(**overrides: object) -> OperatorCommand:
    values: dict[str, object] = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "command_id": "command-1",
        "action": CommandAction.APPROVE,
        "actor_user_id": "approver-1",
        "expected_revision": 1,
        "policy_reference": "policy:compat_096:1",
        "reason": "Approved synthetic no-side-effect lifecycle",
    }
    values.update(overrides)
    return OperatorCommand(**values)  # type: ignore[arg-type]


def test_workflow_contracts_are_versioned_bounded_and_closed() -> None:
    request = _workflow_input()

    assert request.schema_version == "1.0"
    assert request.approval_timeout_seconds == 3600
    assert request.max_activity_attempts == 3
    assert WorkflowState.STOP_REQUESTED.value == "stop_requested"
    assert {field.name for field in fields(request)} == {
        "schema_version",
        "tenant_id",
        "job_id",
        "engagement_id",
        "roe_version_id",
        "policy_reference",
        "expected_job_version",
        "approval_timeout_seconds",
        "max_activity_attempts",
        "runner_dispatch_enabled",
    }
    assert all(field.type not in (dict, object) for field in fields(request))


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"schema_version": "2.0"}, "contract_schema_version_unsupported"),
        ({"tenant_id": "../tenant"}, "tenant_id_invalid"),
        ({"job_id": "x" * 65}, "job_id_invalid"),
        ({"policy_reference": "secret=value"}, "policy_reference_invalid"),
        ({"approval_timeout_seconds": 0}, "approval_timeout_invalid"),
        ({"approval_timeout_seconds": 604801}, "approval_timeout_invalid"),
        ({"max_activity_attempts": 0}, "activity_attempts_invalid"),
        ({"max_activity_attempts": 6}, "activity_attempts_invalid"),
    ],
)
def test_workflow_input_fails_closed_on_unbounded_or_executable_values(
    overrides: dict[str, object], reason: str
) -> None:
    with pytest.raises(ValueError, match=reason):
        _workflow_input(**overrides)


def test_deterministic_ids_and_command_hashes_are_stable_and_non_disclosing() -> None:
    first = deterministic_job_workflow_id("tenant-1", "job-1")
    second = deterministic_job_workflow_id("tenant-1", "job-1")
    other = deterministic_job_workflow_id("tenant-2", "job-1")

    assert first == second
    assert first != other
    assert first.startswith("redagent-job-v1-")
    assert "tenant-1" not in first and "job-1" not in first
    assert len(first) <= 64

    command = _command()
    assert command_request_hash(command) == command_request_hash(command)
    assert command_request_hash(command) != command_request_hash(_command(reason="A different bounded reason"))


def test_operator_commands_reject_stale_shape_and_sensitive_or_arbitrary_fields() -> None:
    command = _command()

    assert command.action == CommandAction.APPROVE.value
    assert {field.name for field in fields(command)} == {
        "schema_version",
        "command_id",
        "action",
        "actor_user_id",
        "expected_revision",
        "policy_reference",
        "reason",
    }
    with pytest.raises(TypeError):
        OperatorCommand(**{**asdict(command), "payload": {"secret": "blocked"}})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="command_reason_invalid"):
        _command(reason="password=not-allowed")
    with pytest.raises(ValueError, match="expected_revision_invalid"):
        _command(expected_revision=0)
