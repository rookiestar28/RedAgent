from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from redagent_platform.campaign_service.dag_execution_activity import (
    DagActivityAction,
    DagActivityMaterialV1,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagContainActivityInputV1,
    DagExecutionSnapshotV1,
    DagRunState,
    DagStopSignalV1,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
)
from redagent_platform.orchestration.dag_execution_activities import (
    DagExecutionTemporalActivities,
)
from redagent_platform.campaign_service.dag_containment_store import (
    PostgresDagContainmentOwner,
)


NOW = datetime(2026, 8, 29, 8, tzinfo=timezone.utc)


def _request() -> DagWorkflowInputV1:
    return DagWorkflowInputV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        tenant_id="tenant-a",
        execution_run_id="run-a",
        input_sha256="a" * 64,
        plan_sha256="b" * 64,
        max_activity_attempts=3,
        max_transitions=20,
    )


def _snapshot(*, state: DagRunState = DagRunState.RUNNING) -> DagExecutionSnapshotV1:
    request = _request()
    return DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id=request.execution_run_id,
        workflow_request_sha256=dag_workflow_request_sha256(request),
        state=state,
        revision=2,
        transition_count=1,
        current_node_id=None,
        current_node_state=None,
        stop_requested=state is DagRunState.CONTAINED,
        terminal_reason="operator_stop" if state is DagRunState.CONTAINED else None,
    )


class State:
    async def prepare(self, request, *, now):
        assert request == _request() and now == NOW
        return DagActivityMaterialV1(
            action=DagActivityAction.WAIT,
            snapshot=_snapshot(),
            effect_command=None,
            reconciliation_command=None,
        )


class Application:
    async def execute(self, request, *, now):
        assert request == _request() and now == NOW
        return _snapshot()


class Containment:
    async def contain(self, request, *, now):
        assert isinstance(request, DagContainActivityInputV1) and now == NOW
        return _snapshot(state=DagRunState.CONTAINED)


def test_temporal_activity_names_are_exact_and_calls_remain_bounded(monkeypatch) -> None:
    definitions = {
        activity._Definition.must_from_callable(
            DagExecutionTemporalActivities.reconcile
        ).name,
        activity._Definition.must_from_callable(
            DagExecutionTemporalActivities.dispatch
        ).name,
        activity._Definition.must_from_callable(
            DagExecutionTemporalActivities.contain
        ).name,
    }
    assert definitions == {
        "redagent.campaign-dag.reconcile.v1",
        "redagent.campaign-dag.dispatch.v1",
        "redagent.campaign-dag.contain.v1",
    }

    monkeypatch.setattr(
        "redagent_platform.orchestration.dag_execution_activities._activity_now",
        lambda: NOW,
    )
    activities = DagExecutionTemporalActivities(State(), Application(), Containment())
    assert asyncio.run(activities.reconcile(_request())) == _snapshot()
    assert asyncio.run(activities.dispatch(_request())) == _snapshot()
    stop = DagStopSignalV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        signal_id="stop-a",
        actor_user_id="operator-a",
        reason_sha256="c" * 64,
    )
    result = asyncio.run(
        activities.contain(
            DagContainActivityInputV1(
                request=_request(), stop=stop, expected_revision=2
            )
        )
    )
    assert result.state is DagRunState.CONTAINED


def test_postgres_dag_containment_owner_is_the_activity_containment_port() -> None:
    assert callable(PostgresDagContainmentOwner.contain)


def _heartbeat_environment() -> ActivityEnvironment:
    env = ActivityEnvironment()
    env.info = replace(env.info, heartbeat_timeout=timedelta(milliseconds=90))
    return env


def test_pending_dispatch_sends_periodic_heartbeats_and_stops_after_completion() -> None:
    async def scenario():
        release = asyncio.Event()
        pulses = []

        class PendingApplication:
            async def execute(self, request, *, now):
                await release.wait()
                return _snapshot()

        env = _heartbeat_environment()

        def on_heartbeat(*details):
            pulses.append(details)
            if len(pulses) == 3:
                release.set()

        env.on_heartbeat = on_heartbeat
        activities = DagExecutionTemporalActivities(State(), PendingApplication(), Containment())
        result = await asyncio.wait_for(env.run(activities.dispatch, _request()), timeout=1)
        assert result == _snapshot()
        assert pulses == [("run-a",)] * 3
        await asyncio.sleep(0.1)
        assert len(pulses) == 3

    asyncio.run(scenario())


def test_dispatch_cancellation_awaits_application_cleanup_and_stops_heartbeats() -> None:
    async def scenario():
        started = asyncio.Event()
        cleanup_started = asyncio.Event()
        cleanup_release = asyncio.Event()
        cleanup_done = asyncio.Event()
        pulses = []

        class PendingApplication:
            async def execute(self, request, *, now):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cleanup_started.set()
                    await cleanup_release.wait()
                    cleanup_done.set()

        env = _heartbeat_environment()
        env.on_heartbeat = lambda *details: pulses.append(details)
        activities = DagExecutionTemporalActivities(State(), PendingApplication(), Containment())
        task = asyncio.create_task(env.run(activities.dispatch, _request()))
        await asyncio.wait_for(started.wait(), timeout=1)
        env.cancel()
        await asyncio.wait_for(cleanup_started.wait(), timeout=1)
        assert not task.done()
        cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cleanup_done.is_set() and pulses
        count = len(pulses)
        await asyncio.sleep(0.1)
        assert len(pulses) == count

    asyncio.run(scenario())


def test_heartbeat_failure_cancels_dispatch_and_awaits_application_cleanup() -> None:
    async def scenario():
        cleaned = asyncio.Event()
        pulses = []

        class PendingApplication:
            async def execute(self, request, *, now):
                try:
                    await asyncio.Event().wait()
                finally:
                    await asyncio.sleep(0)
                    cleaned.set()

        env = _heartbeat_environment()

        def on_heartbeat(*details):
            pulses.append(details)
            if len(pulses) == 2:
                raise RuntimeError("heartbeat_unavailable")

        env.on_heartbeat = on_heartbeat
        activities = DagExecutionTemporalActivities(State(), PendingApplication(), Containment())
        with pytest.raises(ApplicationError, match="heartbeat_unavailable"):
            await asyncio.wait_for(env.run(activities.dispatch, _request()), timeout=1)
        assert cleaned.is_set()
        await asyncio.sleep(0.1)
        assert pulses == [("run-a",)] * 2

    asyncio.run(scenario())
