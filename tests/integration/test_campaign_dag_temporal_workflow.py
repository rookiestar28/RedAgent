from __future__ import annotations

import asyncio

from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagContainActivityInputV1,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
    DagStopSignalV1,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
)
from redagent_platform.orchestration.dag_execution_workflow import (
    CampaignDagExecutionWorkflow,
)


def test_dag_temporal_workflow_dispatches_settles_and_replays() -> None:
    asyncio.run(_dispatch_settle_and_replay())


def test_dag_temporal_stop_cancels_dispatch_before_containment() -> None:
    asyncio.run(_stop_cancels_then_contains())


def test_dag_temporal_transition_budget_contains_without_dispatch() -> None:
    asyncio.run(_transition_budget_contains())


class ScriptedDagActivities:
    def __init__(self, *, block_dispatch: bool = False, never_ready: bool = False) -> None:
        self.block_dispatch = block_dispatch
        self.never_ready = never_ready
        self.reconcile_calls: list[DagWorkflowInputV1] = []
        self.dispatch_calls: list[DagWorkflowInputV1] = []
        self.contain_calls: list[DagContainActivityInputV1] = []
        self.events: list[str] = []
        self.dispatch_started = asyncio.Event()

    @activity.defn(name="redagent.campaign-dag.reconcile.v1")
    async def reconcile(self, request: DagWorkflowInputV1) -> DagExecutionSnapshotV1:
        self.reconcile_calls.append(request)
        if self.never_ready:
            return _snapshot(
                request,
                revision=len(self.reconcile_calls) + 1,
                transitions=len(self.reconcile_calls),
                node_state=DagNodeState.PENDING,
            )
        if self.dispatch_calls:
            return _snapshot(
                request,
                revision=4,
                transitions=3,
                state=DagRunState.COMPLETED,
                terminal_reason="all_nodes_confirmed",
            )
        return _snapshot(
            request,
            revision=2,
            transitions=1,
            node_state=DagNodeState.RESERVED,
        )

    @activity.defn(name="redagent.campaign-dag.dispatch.v1")
    async def dispatch(self, request: DagWorkflowInputV1) -> DagExecutionSnapshotV1:
        self.dispatch_calls.append(request)
        self.events.append("dispatch-started")
        self.dispatch_started.set()
        if self.block_dispatch:
            try:
                while True:
                    activity.heartbeat({"phase": "dag_dispatch"})
                    await asyncio.sleep(0.01)
            finally:
                self.events.append("dispatch-cancelled")
        return _snapshot(
            request,
            revision=3,
            transitions=2,
            node_state=DagNodeState.CONFIRMED,
        )

    @activity.defn(name="redagent.campaign-dag.contain.v1")
    async def contain(
        self, request: DagContainActivityInputV1
    ) -> DagExecutionSnapshotV1:
        self.events.append("contain-started")
        self.contain_calls.append(request)
        return _snapshot(
            request.request,
            revision=request.expected_revision + 1,
            transitions=min(
                request.request.max_transitions,
                len(self.reconcile_calls) + len(self.dispatch_calls) + 1,
            ),
            state=DagRunState.CONTAINED,
            stop_requested=True,
            terminal_reason="stop_contained",
        )


async def _dispatch_settle_and_replay() -> None:
    activities = ScriptedDagActivities()
    request = _request(max_transitions=5)
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="dag-normal",
            workflows=[CampaignDagExecutionWorkflow],
            activities=[activities.reconcile, activities.dispatch, activities.contain],
        ):
            handle = await environment.client.start_workflow(
                CampaignDagExecutionWorkflow.run,
                request,
                id="dag-normal-workflow",
                task_queue="dag-normal",
            )
            result = await handle.result()
            history = await handle.fetch_history()
    assert result.state is DagRunState.COMPLETED
    assert result.terminal_reason == "all_nodes_confirmed"
    assert len(activities.reconcile_calls) == 2
    assert len(activities.dispatch_calls) == 1
    await Replayer(workflows=[CampaignDagExecutionWorkflow]).replay_workflow(history)


async def _stop_cancels_then_contains() -> None:
    activities = ScriptedDagActivities(block_dispatch=True)
    request = _request(max_transitions=5)
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="dag-stop",
            workflows=[CampaignDagExecutionWorkflow],
            activities=[activities.reconcile, activities.dispatch, activities.contain],
        ):
            handle = await environment.client.start_workflow(
                CampaignDagExecutionWorkflow.run,
                request,
                id="dag-stop-workflow",
                task_queue="dag-stop",
            )
            await asyncio.wait_for(activities.dispatch_started.wait(), timeout=5)
            current = await handle.query(
                "status", result_type=DagExecutionSnapshotV1
            )
            assert current.current_node_state is DagNodeState.RESERVED
            await handle.signal(
                "stop",
                DagStopSignalV1(
                    schema_version=DAG_EXECUTION_SCHEMA_VERSION,
                    signal_id="stop-dag-test",
                    actor_user_id="operator-dag-test",
                    reason_sha256="4" * 64,
                ),
            )
            result = await asyncio.wait_for(handle.result(), timeout=5)
    assert result.state is DagRunState.CONTAINED
    assert result.stop_requested is True
    assert len(activities.contain_calls) == 1
    assert activities.events.index("dispatch-cancelled") < activities.events.index(
        "contain-started"
    )


async def _transition_budget_contains() -> None:
    activities = ScriptedDagActivities(never_ready=True)
    request = _request(max_transitions=2)
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="dag-budget",
            workflows=[CampaignDagExecutionWorkflow],
            activities=[activities.reconcile, activities.dispatch, activities.contain],
        ):
            result = await environment.client.execute_workflow(
                CampaignDagExecutionWorkflow.run,
                request,
                id="dag-budget-workflow",
                task_queue="dag-budget",
            )
    assert result.state is DagRunState.CONTAINED
    assert len(activities.reconcile_calls) == 2
    assert not activities.dispatch_calls
    assert len(activities.contain_calls) == 1
    assert activities.contain_calls[0].stop.signal_id.startswith("transition-budget-")


def _request(*, max_transitions: int) -> DagWorkflowInputV1:
    return DagWorkflowInputV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        tenant_id="tenant-dag-test",
        execution_run_id="dag-run-test",
        input_sha256="1" * 64,
        plan_sha256="2" * 64,
        max_activity_attempts=2,
        max_transitions=max_transitions,
    )


def _snapshot(
    request: DagWorkflowInputV1,
    *,
    revision: int,
    transitions: int,
    state: DagRunState = DagRunState.RUNNING,
    node_state: DagNodeState | None = None,
    stop_requested: bool = False,
    terminal_reason: str | None = None,
) -> DagExecutionSnapshotV1:
    return DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id=request.execution_run_id,
        workflow_request_sha256=dag_workflow_request_sha256(request),
        state=state,
        revision=revision,
        transition_count=transitions,
        current_node_id="node-dag-test" if node_state is not None else None,
        current_node_state=node_state,
        stop_requested=stop_requested,
        terminal_reason=terminal_reason,
    )
