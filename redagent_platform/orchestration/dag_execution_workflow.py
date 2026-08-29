"""Deterministic Temporal control for one admitted campaign DAG execution."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError
from temporalio.workflow import ActivityCancellationType, ActivityHandle

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


_TERMINAL_STATES = {
    DagRunState.COMPLETED,
    DagRunState.CONTAINED,
    DagRunState.MANUAL_REVIEW_REQUIRED,
    DagRunState.FAILED_BEFORE_IO,
    DagRunState.FAILED,
}
_DISPATCH_STATES = {
    DagNodeState.RESERVED,
    DagNodeState.CLAIMED,
    DagNodeState.DISPATCHING,
    DagNodeState.RECONCILIATION_REQUIRED,
}
_NON_RETRYABLE = (
    "AuthorizationDenied",
    "DispatchDenied",
    "ExecutionDisabled",
    "InvalidWorkflowInput",
    "PolicyDenied",
    "ScopeDenied",
    "UnsupportedCapability",
    "WorkflowVersionConflict",
)


def dag_activity_retry_policy(maximum_attempts: int) -> RetryPolicy:
    if type(maximum_attempts) is not int or not 1 <= maximum_attempts <= 5:
        raise ValueError("dag_activity_attempts_invalid")
    return RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=10),
        maximum_attempts=maximum_attempts,
        non_retryable_error_types=_NON_RETRYABLE,
    )


@workflow.defn(name="redagent.campaign-dag-execution.v1")
class CampaignDagExecutionWorkflow:
    """Keep only bounded control state; PostgreSQL Activities own all transitions."""

    def __init__(self) -> None:
        self._request: DagWorkflowInputV1 | None = None
        self._snapshot: DagExecutionSnapshotV1 | None = None
        self._pending_stop: DagStopSignalV1 | None = None
        self._dispatch_handle: ActivityHandle[DagExecutionSnapshotV1] | None = None

    @workflow.run
    async def run(self, request: DagWorkflowInputV1) -> DagExecutionSnapshotV1:
        self._request = request
        self._snapshot = DagExecutionSnapshotV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            execution_run_id=request.execution_run_id,
            workflow_request_sha256=dag_workflow_request_sha256(request),
            state=DagRunState.RUNNING,
            revision=1,
            transition_count=0,
            current_node_id=None,
            current_node_state=None,
            stop_requested=False,
            terminal_reason=None,
        )
        for _ in range(request.max_transitions):
            if self._pending_stop is not None:
                return await self._contain(self._pending_stop)
            self._snapshot = await workflow.execute_activity(
                "redagent.campaign-dag.reconcile.v1",
                request,
                result_type=DagExecutionSnapshotV1,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=dag_activity_retry_policy(request.max_activity_attempts),
            )
            snapshot = self._required_snapshot()
            self._validate_snapshot(snapshot)
            if snapshot.state in _TERMINAL_STATES:
                return snapshot
            if self._pending_stop is not None:
                continue
            if snapshot.current_node_state not in _DISPATCH_STATES:
                await workflow.sleep(timedelta(seconds=1))
                continue
            self._dispatch_handle = workflow.start_activity(
                "redagent.campaign-dag.dispatch.v1",
                request,
                result_type=DagExecutionSnapshotV1,
                start_to_close_timeout=timedelta(seconds=90),
                heartbeat_timeout=timedelta(seconds=2),
                cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                retry_policy=dag_activity_retry_policy(request.max_activity_attempts),
            )
            try:
                self._snapshot = await self._dispatch_handle
            except (asyncio.CancelledError, ActivityError):
                if self._pending_stop is None:
                    raise
                continue
            finally:
                self._dispatch_handle = None
            self._validate_snapshot(self._required_snapshot())
        stop = DagStopSignalV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            signal_id=f"transition-budget-{request.execution_run_id}",
            actor_user_id="redagent-workflow",
            reason_sha256="c729f5f93861e2ef9a9e1d9503b6a6cb17d1b6fd162eee4a332610c2293090b5",
        )
        return await self._contain(stop)

    @workflow.signal(name="stop")
    def stop(self, request: DagStopSignalV1) -> None:
        if self._pending_stop is not None and self._pending_stop != request:
            raise RuntimeError("dag_stop_signal_conflict")
        self._pending_stop = request
        if self._snapshot is not None:
            self._snapshot = replace(self._snapshot, stop_requested=True)
        if self._dispatch_handle is not None and workflow.patched("campaign-dag-v1-cancel-wait"):
            self._dispatch_handle.cancel()

    @workflow.query(name="status")
    def status(self) -> DagExecutionSnapshotV1:
        return self._required_snapshot()

    async def _contain(self, stop: DagStopSignalV1) -> DagExecutionSnapshotV1:
        request = self._required_request()
        snapshot = self._required_snapshot()
        self._snapshot = await workflow.execute_activity(
            "redagent.campaign-dag.contain.v1",
            DagContainActivityInputV1(
                request=request,
                stop=stop,
                expected_revision=snapshot.revision,
            ),
            result_type=DagExecutionSnapshotV1,
            start_to_close_timeout=timedelta(seconds=30),
            heartbeat_timeout=timedelta(seconds=2),
            cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
            retry_policy=dag_activity_retry_policy(request.max_activity_attempts),
        )
        self._validate_snapshot(self._required_snapshot())
        return self._required_snapshot()

    def _validate_snapshot(self, snapshot: DagExecutionSnapshotV1) -> None:
        request = self._required_request()
        if (
            snapshot.execution_run_id != request.execution_run_id
            or snapshot.workflow_request_sha256
            != dag_workflow_request_sha256(request)
            or snapshot.transition_count > request.max_transitions
        ):
            raise RuntimeError("dag_workflow_snapshot_binding_invalid")

    def _required_request(self) -> DagWorkflowInputV1:
        if self._request is None:
            raise RuntimeError("dag_workflow_not_initialized")
        return self._request

    def _required_snapshot(self) -> DagExecutionSnapshotV1:
        if self._snapshot is None:
            raise RuntimeError("dag_workflow_not_initialized")
        return self._snapshot
