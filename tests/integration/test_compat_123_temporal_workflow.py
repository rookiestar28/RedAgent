from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

import pytest

from redagent_platform.campaign_service.relay import WorkflowAlreadyStarted
from redagent_platform.orchestration.config import TemporalSettings

from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    R123CampaignSnapshot,
    R123CampaignWorkflowInput,
    R123ContainActivityCommand,
    R123ContainActivityResult,
    R123DispatchActivityCommand,
    R123DispatchActivityResult,
    R123ReconcileActivityCommand,
    R123ReconcileActivityResult,
    R123StopSignal,
    deterministic_r123_campaign_workflow_id,
    r123_workflow_request_sha256,
)
from redagent_platform.orchestration.gateway import connect_temporal, temporal_data_converter
from redagent_platform.orchestration.compat_123_gateway import R123TemporalStartGateway
from redagent_platform.orchestration.workflow import R123ClosedLoopWorkflow
from tests.integration.runtime_coordinates import persisted_temporal_target


ROOT = Path(__file__).resolve().parents[2]


def test_r123_temporal_workflow_dispatches_once_then_settles() -> None:
    asyncio.run(_dispatch_then_settle())


def test_r123_temporal_stop_cancels_dispatch_and_contains() -> None:
    asyncio.run(_stop_and_contain())


def test_r123_real_temporal_gateway_duplicate_query_and_replay() -> None:
    asyncio.run(_real_temporal_gateway())


class ScriptedActivities:
    def __init__(self, *, block_dispatch: bool = False) -> None:
        self.reconcile_calls: list[R123ReconcileActivityCommand] = []
        self.dispatch_calls: list[R123DispatchActivityCommand] = []
        self.contain_calls: list[R123ContainActivityCommand] = []
        self.block_dispatch = block_dispatch
        self.dispatch_started = asyncio.Event()

    @activity.defn(name="redagent.r123.reconcile-level.v1")
    async def reconcile(self, command: R123ReconcileActivityCommand) -> R123ReconcileActivityResult:
        self.reconcile_calls.append(command)
        if not self.dispatch_calls:
            return R123ReconcileActivityResult(
                CONTRACT_SCHEMA_VERSION,
                command.campaign_id,
                command.strategy_revision_id,
                command.revision + 1,
                1,
                0,
                "node-zap",
                "effect-zap",
                "dispatch_once",
                False,
                "effect_reserved",
                None,
            )
        return R123ReconcileActivityResult(
            CONTRACT_SCHEMA_VERSION,
            command.campaign_id,
            command.strategy_revision_id,
            command.revision + 1,
            1,
            0,
            "node-zap",
            "effect-zap",
            "settled",
            True,
            "trusted_evidence_satisfied",
            None,
        )

    @activity.defn(name="redagent.r123.dispatch-effect.v1")
    async def dispatch(self, command: R123DispatchActivityCommand) -> R123DispatchActivityResult:
        self.dispatch_calls.append(command)
        self.dispatch_started.set()
        if self.block_dispatch:
            while True:
                activity.heartbeat({"phase": "r123_dispatch", "effect_id": command.effect_id})
                await asyncio.sleep(0.01)
        return R123DispatchActivityResult(
            CONTRACT_SCHEMA_VERSION,
            command.campaign_id,
            command.effect_id,
            "dispatched",
            command.expected_revision + 1,
            None,
        )

    @activity.defn(name="redagent.r123.contain.v1")
    async def contain(self, command: R123ContainActivityCommand) -> R123ContainActivityResult:
        self.contain_calls.append(command)
        return R123ContainActivityResult(
            CONTRACT_SCHEMA_VERSION,
            command.campaign_id,
            "contained",
            command.expected_revision + 1,
            "stop_contained",
        )


async def _dispatch_then_settle() -> None:
    activities = ScriptedActivities()
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="r123-normal",
            workflows=[R123ClosedLoopWorkflow],
            activities=[activities.reconcile, activities.dispatch, activities.contain],
        ):
            result = await environment.client.execute_workflow(
                R123ClosedLoopWorkflow.run,
                _request(),
                id="r123-normal-workflow",
                task_queue="r123-normal",
            )
    assert result.state == "settled"
    assert result.terminal_reason == "trusted_evidence_satisfied"
    assert result.depth == 1
    assert len(activities.dispatch_calls) == 1
    assert activities.dispatch_calls[0].effect_id == "effect-zap"
    assert len(activities.reconcile_calls) == 2


async def _stop_and_contain() -> None:
    activities = ScriptedActivities(block_dispatch=True)
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="r123-stop",
            workflows=[R123ClosedLoopWorkflow],
            activities=[activities.reconcile, activities.dispatch, activities.contain],
        ):
            handle = await environment.client.start_workflow(
                R123ClosedLoopWorkflow.run,
                _request(),
                id="r123-stop-workflow",
                task_queue="r123-stop",
            )
            await asyncio.wait_for(activities.dispatch_started.wait(), timeout=5)
            await handle.signal(
                "emergency_stop",
                R123StopSignal(
                    CONTRACT_SCHEMA_VERSION,
                    "stop-r123",
                    "operator-r123",
                    "4" * 64,
                ),
            )
            result = await asyncio.wait_for(handle.result(), timeout=5)
    assert result.state == "contained"
    assert result.stop_requested is True
    assert result.terminal_reason == "stop_contained"
    assert len(activities.dispatch_calls) == 1
    assert len(activities.contain_calls) == 1


def _request() -> R123CampaignWorkflowInput:
    return R123CampaignWorkflowInput(
        CONTRACT_SCHEMA_VERSION,
        "tenant-r123",
        "campaign-r123",
        "strategy-r123-v1",
        "1" * 64,
        2,
        1,
        3,
    )


async def _real_temporal_gateway() -> None:
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-{suffix[:12]}"
    campaign_id = f"campaign-r123-{suffix[:12]}"
    strategy_revision_id = f"strategy-r123-{suffix[:12]}"
    queue = f"r123-real-{suffix[:12]}"
    settings = TemporalSettings(
        target=persisted_temporal_target(ROOT),
        namespace="default",
        task_queue=queue,
        codec_key_id=f"r123-{suffix[:12]}",
        codec_key_path=ROOT / ".tmp" / "r123-temporal-test-key",
        codec_key=b"g" * 32,
        tls=False,
        profile="local",
    )
    client = await connect_temporal(settings)
    activities = ScriptedActivities()
    request = R123CampaignWorkflowInput(
        CONTRACT_SCHEMA_VERSION,
        tenant_id,
        campaign_id,
        strategy_revision_id,
        "1" * 64,
        2,
        1,
        3,
    )
    workflow_id = deterministic_r123_campaign_workflow_id(tenant_id, campaign_id)
    payload = {
        "schema_version": "redagent.r123-workflow-start/v1",
        "tenant_id": tenant_id,
        "principal_id": f"principal-r123-{suffix[:12]}",
        "engagement_id": f"eng-r123-{suffix[:12]}",
        "target_id": f"target-r123-{suffix[:12]}",
        "campaign_id": campaign_id,
        "strategy_revision_id": strategy_revision_id,
        "workflow_id": workflow_id,
        "workflow_request_sha256": r123_workflow_request_sha256(request),
        "envelope_sha256": request.envelope_sha256,
    }
    async with Worker(
        client,
        task_queue=queue,
        workflows=[R123ClosedLoopWorkflow],
        activities=[activities.reconcile, activities.dispatch, activities.contain],
    ):
        gateway = R123TemporalStartGateway(client, task_queue=queue)
        started = await gateway.start(
            workflow_id=workflow_id,
            request_sha256=r123_workflow_request_sha256(request),
            payload=payload,
        )
        assert started.workflow_run_id
        result = await client.get_workflow_handle(
            workflow_id, result_type=R123CampaignSnapshot
        ).result()
        assert result.state == "settled"
        queried = await gateway.query(workflow_id)
        assert queried.workflow_id == workflow_id
        assert queried.workflow_run_id == started.workflow_run_id
        assert queried.request_sha256 == r123_workflow_request_sha256(request)
        with pytest.raises(WorkflowAlreadyStarted):
            await gateway.start(
                workflow_id=workflow_id,
                request_sha256=r123_workflow_request_sha256(request),
                payload=payload,
            )
        history = await client.get_workflow_handle(workflow_id).fetch_history()
        serialized = history.to_json()
        assert tenant_id not in serialized
        assert campaign_id not in serialized
        assert request.envelope_sha256 not in serialized
        await Replayer(
            workflows=[R123ClosedLoopWorkflow],
            data_converter=temporal_data_converter(settings),
        ).replay_workflow(history)
