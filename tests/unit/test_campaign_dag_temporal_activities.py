from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from temporalio import activity

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
