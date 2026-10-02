from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from redagent_platform.campaign_service.dag_execution_contracts import DagRunState, DagWorkflowInputV1, DagExecutionSnapshotV1, DagContainActivityInputV1
from redagent_platform.orchestration.dag_execution_workflow import CampaignDagExecutionWorkflow
from tests.integration.test_campaign_dag_temporal_workflow import ScriptedDagActivities, _request, _snapshot


class FailingActivities(ScriptedDagActivities):
    def __init__(self, phase):
        super().__init__()
        self.phase = phase

    @activity.defn(name="redagent.campaign-dag.reconcile.v1")
    async def reconcile(self, request: DagWorkflowInputV1) -> DagExecutionSnapshotV1:
        if self.phase == "reconcile":
            self.reconcile_calls.append(request)
            raise ApplicationError("database unavailable", non_retryable=True)
        return await super().reconcile(request)

    @activity.defn(name="redagent.campaign-dag.dispatch.v1")
    async def dispatch(self, request: DagWorkflowInputV1) -> DagExecutionSnapshotV1:
        self.dispatch_calls.append(request)
        raise ApplicationError("worker result lost", non_retryable=True)

    @activity.defn(name="redagent.campaign-dag.contain.v1")
    async def contain(self, request: DagContainActivityInputV1) -> DagExecutionSnapshotV1:
        self.contain_calls.append(request)
        return _snapshot(request.request, revision=request.expected_revision + 2,
                         transitions=2, state=DagRunState.MANUAL_REVIEW_REQUIRED,
                         stop_requested=True, terminal_reason="campaign_stop_active_cleanup_required")


@pytest.mark.parametrize("phase", ["reconcile", "dispatch"])
def test_failed_activity_contains_and_replays_without_a_second_dispatch(phase):
    asyncio.run(_scenario(phase))


async def _scenario(phase):
    activities = FailingActivities(phase)
    request = replace(_request(max_transitions=5), max_activity_attempts=1)
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(environment.client, task_queue=f"failure-{phase}",
                          workflows=[CampaignDagExecutionWorkflow],
                          activities=[activities.reconcile, activities.dispatch, activities.contain]):
            handle = await environment.client.start_workflow(CampaignDagExecutionWorkflow.run,
                request, id=f"failure-{phase}", task_queue=f"failure-{phase}")
            result = await handle.result()
            history = await handle.fetch_history()
    assert result.state is DagRunState.MANUAL_REVIEW_REQUIRED
    assert result.stop_requested
    assert result.terminal_reason == "campaign_stop_active_cleanup_required"
    assert len(activities.contain_calls) == 1
    assert len(activities.dispatch_calls) == (1 if phase == "dispatch" else 0)
    await Replayer(workflows=[CampaignDagExecutionWorkflow]).replay_workflow(history)
