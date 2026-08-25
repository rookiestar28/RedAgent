from __future__ import annotations

import pytest

from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CommandAction,
    OperatorCommand,
    WorkflowState,
)
from redagent_platform.orchestration.state import CommandConflict, CommandRejected, LifecycleReducer


def _command(action: CommandAction, revision: int, **overrides: object) -> OperatorCommand:
    values: dict[str, object] = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "command_id": f"command-{action.value}-{revision}",
        "action": action,
        "actor_user_id": "operator-1",
        "expected_revision": revision,
        "policy_reference": "policy:compat_096:1",
        "reason": f"Bounded synthetic {action.value} lifecycle command",
    }
    values.update(overrides)
    return OperatorCommand(**values)  # type: ignore[arg-type]


def test_lifecycle_requires_admission_and_approval_and_never_claims_runner_dispatch() -> None:
    reducer = LifecycleReducer("job-1")

    assert reducer.snapshot.state == WorkflowState.DISPATCH_PENDING.value
    admitted = reducer.admit()
    assert admitted.state == WorkflowState.AWAITING_APPROVAL.value
    assert admitted.revision == 2

    decision = reducer.apply(_command(CommandAction.APPROVE, 2))
    assert decision.replayed is False
    assert decision.snapshot.state == WorkflowState.READY.value
    assert decision.snapshot.current_gate == "runner_dispatch_ready"
    assert decision.snapshot.dispatch_blocked is True
    assert not hasattr(decision.snapshot, "containment_complete")


def test_pause_resume_cancel_and_stop_are_versioned_fail_closed_transitions() -> None:
    reducer = LifecycleReducer("job-1")
    reducer.admit()
    reducer.apply(_command(CommandAction.APPROVE, 2))
    paused = reducer.apply(_command(CommandAction.PAUSE, 3)).snapshot
    assert paused.state == WorkflowState.PAUSED.value
    resumed = reducer.apply(_command(CommandAction.RESUME, 4)).snapshot
    assert resumed.state == WorkflowState.READY.value
    cancelled = reducer.apply(_command(CommandAction.CANCEL, 5)).snapshot
    assert cancelled.state == WorkflowState.CANCELLED.value
    assert cancelled.dispatch_blocked is True

    stopped = LifecycleReducer("job-2")
    stopped.admit()
    snapshot = stopped.request_stop("stop-signal-1")
    assert snapshot.state == WorkflowState.STOP_REQUESTED.value
    assert snapshot.current_gate == "containment_owned_by_r101"
    assert snapshot.stop_requested is True
    assert snapshot.dispatch_blocked is True


def test_duplicate_command_replays_but_mismatched_reuse_and_stale_version_fail() -> None:
    reducer = LifecycleReducer("job-1")
    reducer.admit()
    approve = _command(CommandAction.APPROVE, 2)
    first = reducer.apply(approve)
    replay = reducer.apply(approve)

    assert replay.replayed is True
    assert replay.snapshot == first.snapshot
    with pytest.raises(CommandConflict, match="workflow_command_id_mismatch"):
        reducer.apply(_command(CommandAction.APPROVE, 2, command_id=approve.command_id, reason="Different bounded approval reason"))
    with pytest.raises(CommandRejected, match="workflow_revision_conflict"):
        reducer.apply(_command(CommandAction.PAUSE, 2))


def test_failure_retry_and_approval_timeout_remain_recoverable_and_bounded() -> None:
    reducer = LifecycleReducer("job-1")
    reducer.admit()
    timed_out = reducer.fail("approval_timeout")

    assert timed_out.state == WorkflowState.FAILED.value
    assert timed_out.failure_code == "approval_timeout"
    retried = reducer.apply(_command(CommandAction.RETRY, 3)).snapshot
    assert retried.state == WorkflowState.AWAITING_APPROVAL.value
    assert retried.retry_count == 1
    assert retried.failure_code is None


@pytest.mark.parametrize(
    ("state_setup", "action"),
    [
        ("awaiting", CommandAction.RESUME),
        ("awaiting", CommandAction.PAUSE),
        ("ready", CommandAction.RETRY),
        ("paused", CommandAction.APPROVE),
        ("failed", CommandAction.APPROVE),
    ],
)
def test_invalid_commands_are_rejected_before_activity_side_effect(
    state_setup: str, action: CommandAction
) -> None:
    reducer = LifecycleReducer("job-1")
    reducer.admit()
    if state_setup in {"ready", "paused"}:
        reducer.apply(_command(CommandAction.APPROVE, 2))
    if state_setup == "paused":
        reducer.apply(_command(CommandAction.PAUSE, 3))
    if state_setup == "failed":
        reducer.fail("transient_database_failure")
    revision = reducer.snapshot.revision

    with pytest.raises(CommandRejected, match="workflow_command_invalid_for_state"):
        reducer.validate(_command(action, revision))
