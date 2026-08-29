import asyncio
from datetime import datetime, timezone

from redagent_platform.campaign_service.dag_execution_activity import (
    DagActivityAction,
    DagActivityMaterialV1,
    DagExecutionActivity,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
    DagWorkflowInputV1,
)
from tests.unit.test_compat_123_effect_coordinator import _command


NOW = datetime(2026, 8, 29, 15, 0, tzinfo=timezone.utc)


def _workflow_input() -> DagWorkflowInputV1:
    return DagWorkflowInputV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        tenant_id="tenant-r123",
        execution_run_id="dag-run-a",
        input_sha256="a" * 64,
        plan_sha256="b" * 64,
        max_activity_attempts=3,
        max_transitions=20,
    )


def _snapshot(state=DagRunState.RUNNING, node_state=DagNodeState.RESERVED):
    terminal = state in {DagRunState.COMPLETED, DagRunState.CONTAINED}
    return DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id="dag-run-a",
        workflow_request_sha256="c" * 64,
        state=state,
        revision=1,
        transition_count=1,
        current_node_id=None if terminal else "node-a",
        current_node_state=None if terminal else node_state,
        stop_requested=False,
        terminal_reason="all_nodes_confirmed" if state is DagRunState.COMPLETED else None,
    )


class State:
    def __init__(self, material, final):
        self.material = material
        self.final = final
        self.prepared = []
        self.snapshots = []

    async def prepare(self, request, *, now):
        self.prepared.append((request, now))
        return self.material

    async def snapshot(self, request, *, now):
        self.snapshots.append((request, now))
        return self.final


class Coordinator:
    def __init__(self):
        self.dispatched = []
        self.reconciled = []

    async def dispatch(self, command, *, now):
        self.dispatched.append((command, now))

    async def reconcile(self, command, *, now):
        self.reconciled.append((command, now))


def test_activity_dispatches_only_the_prepared_exact_effect_then_rereads() -> None:
    command = _command()
    state = State(
        DagActivityMaterialV1(
            action=DagActivityAction.DISPATCH,
            snapshot=_snapshot(),
            effect_command=command,
            reconciliation_command=None,
        ),
        _snapshot(DagRunState.COMPLETED, DagNodeState.CONFIRMED),
    )
    coordinator = Coordinator()

    result = asyncio.run(
        DagExecutionActivity(state, coordinator).execute(_workflow_input(), now=NOW)
    )

    assert result.state is DagRunState.COMPLETED
    assert coordinator.dispatched == [(command, NOW)]
    assert not coordinator.reconciled
    assert len(state.snapshots) == 1


def test_terminal_or_wait_material_performs_no_effect_io() -> None:
    terminal = _snapshot(DagRunState.COMPLETED, DagNodeState.CONFIRMED)
    state = State(
        DagActivityMaterialV1(
            action=DagActivityAction.TERMINAL,
            snapshot=terminal,
            effect_command=None,
            reconciliation_command=None,
        ),
        terminal,
    )
    coordinator = Coordinator()

    result = asyncio.run(
        DagExecutionActivity(state, coordinator).execute(_workflow_input(), now=NOW)
    )

    assert result == terminal
    assert not coordinator.dispatched
    assert not coordinator.reconciled
    assert not state.snapshots
