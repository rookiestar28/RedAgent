"""Pure deterministic compat_096 lifecycle reducer shared by workflow code and tests."""

from __future__ import annotations

from dataclasses import dataclass, replace

from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CommandAction,
    JobSnapshot,
    OperatorCommand,
    WorkflowState,
    command_request_hash,
)


class CommandRejected(ValueError):
    """The requested transition is invalid for current durable state."""


class CommandConflict(ValueError):
    """A command ID was reused with different content."""


@dataclass(frozen=True, slots=True)
class CommandDecision:
    snapshot: JobSnapshot
    replayed: bool


_VALID_ACTIONS: dict[WorkflowState, frozenset[CommandAction]] = {
    WorkflowState.DISPATCH_PENDING: frozenset({CommandAction.CANCEL}),
    WorkflowState.AWAITING_APPROVAL: frozenset({CommandAction.APPROVE, CommandAction.CANCEL}),
    WorkflowState.READY: frozenset({CommandAction.PAUSE, CommandAction.CANCEL}),
    WorkflowState.DISPATCHING: frozenset(),
    WorkflowState.SUCCEEDED: frozenset(),
    WorkflowState.PAUSED: frozenset({CommandAction.RESUME, CommandAction.CANCEL}),
    WorkflowState.FAILED: frozenset({CommandAction.RETRY, CommandAction.CANCEL}),
    WorkflowState.CANCEL_REQUESTED: frozenset(),
    WorkflowState.CANCELLED: frozenset(),
    WorkflowState.STOP_REQUESTED: frozenset(),
}


class LifecycleReducer:
    MAX_PROCESSED_COMMANDS = 1_000

    def __init__(self, job_id: str) -> None:
        self._snapshot = JobSnapshot(
            schema_version=CONTRACT_SCHEMA_VERSION,
            job_id=job_id,
            state=WorkflowState.DISPATCH_PENDING.value,
            revision=1,
            current_gate="temporal_admission",
            failure_code=None,
            retry_count=0,
            dispatch_blocked=True,
            stop_requested=False,
            last_command_id=None,
        )
        self._processed: dict[str, tuple[str, JobSnapshot]] = {}
        self._stop_signal_id: str | None = None

    @classmethod
    def from_snapshot(cls, snapshot: JobSnapshot) -> "LifecycleReducer":
        reducer = cls(snapshot.job_id)
        reducer._snapshot = snapshot
        return reducer

    @property
    def snapshot(self) -> JobSnapshot:
        return self._snapshot

    def admit(self) -> JobSnapshot:
        if WorkflowState(self._snapshot.state) is not WorkflowState.DISPATCH_PENDING:
            raise CommandRejected("workflow_admission_state_invalid")
        self._snapshot = replace(
            self._snapshot,
            state=WorkflowState.AWAITING_APPROVAL.value,
            revision=self._snapshot.revision + 1,
            current_gate="operator_approval_required",
        )
        return self._snapshot

    def validate(self, command: OperatorCommand) -> None:
        existing = self._processed.get(command.command_id)
        if existing is not None:
            if existing[0] != command_request_hash(command):
                raise CommandConflict("workflow_command_id_mismatch")
            return
        if command.expected_revision != self._snapshot.revision:
            raise CommandRejected("workflow_revision_conflict")
        action = CommandAction(command.action)
        if action not in _VALID_ACTIONS[WorkflowState(self._snapshot.state)]:
            raise CommandRejected("workflow_command_invalid_for_state")
        if len(self._processed) >= self.MAX_PROCESSED_COMMANDS:
            raise CommandRejected("workflow_command_history_limit_reached")

    def replay(self, command: OperatorCommand) -> CommandDecision | None:
        existing = self._processed.get(command.command_id)
        if existing is None:
            return None
        if existing[0] != command_request_hash(command):
            raise CommandConflict("workflow_command_id_mismatch")
        return CommandDecision(snapshot=existing[1], replayed=True)

    def apply(self, command: OperatorCommand) -> CommandDecision:
        replay = self.replay(command)
        if replay is not None:
            return replay
        self.validate(command)
        state, gate, failure_code, retry_count = self._transition(CommandAction(command.action))
        self._snapshot = replace(
            self._snapshot,
            state=state.value,
            revision=self._snapshot.revision + 1,
            current_gate=gate,
            failure_code=failure_code,
            retry_count=retry_count,
            dispatch_blocked=True,
            last_command_id=command.command_id,
        )
        self._processed[command.command_id] = (command_request_hash(command), self._snapshot)
        return CommandDecision(snapshot=self._snapshot, replayed=False)

    def fail(self, failure_code: str) -> JobSnapshot:
        if not failure_code or len(failure_code) > 100:
            raise ValueError("workflow_failure_code_invalid")
        self._snapshot = replace(
            self._snapshot,
            state=WorkflowState.FAILED.value,
            revision=self._snapshot.revision + 1,
            current_gate="operator_retry_or_cancel_required",
            failure_code=failure_code,
            dispatch_blocked=True,
        )
        return self._snapshot

    def begin_dispatch(self) -> JobSnapshot:
        if WorkflowState(self._snapshot.state) is not WorkflowState.READY:
            raise CommandRejected("runner_dispatch_state_invalid")
        self._snapshot = replace(
            self._snapshot,
            state=WorkflowState.DISPATCHING.value,
            revision=self._snapshot.revision + 1,
            current_gate="runner_dispatch_in_progress",
            dispatch_blocked=False,
        )
        return self._snapshot

    def complete_dispatch(self) -> JobSnapshot:
        if WorkflowState(self._snapshot.state) is not WorkflowState.DISPATCHING:
            raise CommandRejected("runner_completion_state_invalid")
        self._snapshot = replace(
            self._snapshot,
            state=WorkflowState.SUCCEEDED.value,
            revision=self._snapshot.revision + 1,
            current_gate="runner_evidence_finalized",
            failure_code=None,
            dispatch_blocked=True,
        )
        return self._snapshot

    def request_stop(self, signal_id: str) -> JobSnapshot:
        if self._stop_signal_id == signal_id:
            return self._snapshot
        if self._stop_signal_id is not None:
            raise CommandConflict("workflow_stop_signal_conflict")
        self._stop_signal_id = signal_id
        self._snapshot = replace(
            self._snapshot,
            state=WorkflowState.STOP_REQUESTED.value,
            revision=self._snapshot.revision + 1,
            current_gate="containment_owned_by_r101",
            dispatch_blocked=True,
            stop_requested=True,
            last_command_id=signal_id,
        )
        return self._snapshot

    def complete_stop(self, *, outcome: str, failure_code: str | None) -> JobSnapshot:
        if WorkflowState(self._snapshot.state) is not WorkflowState.STOP_REQUESTED:
            raise CommandRejected("containment_completion_state_invalid")
        contained = outcome == "contained"
        if outcome not in {"contained", "contained_with_residual_risk", "containment_failed"}:
            raise CommandRejected("containment_outcome_invalid")
        self._snapshot = replace(
            self._snapshot,
            state=(WorkflowState.CANCELLED if contained else WorkflowState.FAILED).value,
            revision=self._snapshot.revision + 1,
            current_gate="containment_verified" if contained else "containment_incident_open",
            failure_code=None if contained else (failure_code or outcome),
            dispatch_blocked=True,
            stop_requested=True,
        )
        return self._snapshot

    def _transition(self, action: CommandAction) -> tuple[WorkflowState, str, str | None, int]:
        if action is CommandAction.APPROVE:
            return WorkflowState.READY, "runner_dispatch_ready", None, self._snapshot.retry_count
        if action is CommandAction.PAUSE:
            return WorkflowState.PAUSED, "operator_resume_or_cancel_required", None, self._snapshot.retry_count
        if action is CommandAction.RESUME:
            return WorkflowState.READY, "runner_dispatch_ready", None, self._snapshot.retry_count
        if action is CommandAction.RETRY:
            return WorkflowState.AWAITING_APPROVAL, "operator_approval_required", None, self._snapshot.retry_count + 1
        if action is CommandAction.CANCEL:
            return WorkflowState.CANCELLED, "cancelled_before_runner_dispatch", None, self._snapshot.retry_count
        raise CommandRejected("workflow_command_invalid_for_state")
