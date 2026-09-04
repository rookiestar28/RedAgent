from __future__ import annotations

import asyncio

import pytest
from temporalio.api.enums.v1 import EventType
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from redagent_platform.campaign_service.admission_start_contracts import (
    ADMISSION_START_BRIDGE_SCHEMA_VERSION,
    AutonomousCampaignStartBridgeState,
    AutonomousCampaignStartBridgeWorkflowInputV1,
    admission_start_bridge_request_sha256,
    deterministic_admission_start_bridge_workflow_id,
)
from redagent_platform.campaign_service.relay import WorkflowAlreadyStarted
from redagent_platform.orchestration.admission_start_gateway import (
    AutonomousCampaignStartBridgeTemporalGateway,
)
from redagent_platform.orchestration.admission_start_workflow import (
    AutonomousCampaignStartBridgeWorkflow,
)


def test_start_bridge_is_durable_queryable_duplicate_safe_and_schedules_no_activity() -> None:
    asyncio.run(_durable_start_bridge())


async def _durable_start_bridge() -> None:
    request = AutonomousCampaignStartBridgeWorkflowInputV1(
        schema_version=ADMISSION_START_BRIDGE_SCHEMA_VERSION,
        tenant_id="tenant-start-bridge",
        campaign_id="campaign-start-bridge",
        execution_run_id="execution-start-bridge",
        input_sha256="1" * 64,
        approval_receipt_sha256="2" * 64,
        admission_receipt_sha256="3" * 64,
    )
    workflow_id = deterministic_admission_start_bridge_workflow_id(
        request.tenant_id,
        request.execution_run_id,
    )
    request_sha256 = admission_start_bridge_request_sha256(request)
    payload = {
        "schema_version": request.schema_version,
        "tenant_id": request.tenant_id,
        "campaign_id": request.campaign_id,
        "execution_run_id": request.execution_run_id,
        "input_sha256": request.input_sha256,
        "approval_receipt_sha256": request.approval_receipt_sha256,
        "admission_receipt_sha256": request.admission_receipt_sha256,
    }

    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue="start-bridge-test",
            workflows=[AutonomousCampaignStartBridgeWorkflow],
            activities=[],
        ):
            gateway = AutonomousCampaignStartBridgeTemporalGateway(
                environment.client,
                task_queue="start-bridge-test",
            )
            started = await gateway.start(
                workflow_id=workflow_id,
                request_sha256=request_sha256,
                payload=payload,
            )
            current = await gateway.query(workflow_id)
            assert current.workflow_id == workflow_id
            assert current.workflow_run_id == started.workflow_run_id
            assert current.request_sha256 == request_sha256

            handle = environment.client.get_workflow_handle(workflow_id)
            snapshot = await handle.query("status")
            assert snapshot["state"] == AutonomousCampaignStartBridgeState.EXECUTION_QUEUED.value
            with pytest.raises(WorkflowAlreadyStarted):
                await gateway.start(
                    workflow_id=workflow_id,
                    request_sha256=request_sha256,
                    payload=payload,
                )
            await handle.cancel()
            history = await handle.fetch_history()

    assert all(
        event.event_type != EventType.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED
        for event in history.events
    )
    await Replayer(workflows=[AutonomousCampaignStartBridgeWorkflow]).replay_workflow(
        history
    )
