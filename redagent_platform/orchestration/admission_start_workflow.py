"""Inert durable Workflow for an admitted R173 execution start."""

from __future__ import annotations

from temporalio import workflow

from redagent_platform.orchestration.admission_start_contracts import (
    ADMISSION_START_BRIDGE_SCHEMA_VERSION,
    ADMISSION_START_BRIDGE_WORKFLOW_NAME,
    AutonomousCampaignStartBridgeSnapshotV1,
    AutonomousCampaignStartBridgeState,
    AutonomousCampaignStartBridgeWorkflowInputV1,
    admission_start_bridge_request_sha256,
)


@workflow.defn(name=ADMISSION_START_BRIDGE_WORKFLOW_NAME)
class AutonomousCampaignStartBridgeWorkflow:
    """Hold a durable queued identity; R173 intentionally schedules no Activity."""

    def __init__(self) -> None:
        self._snapshot: AutonomousCampaignStartBridgeSnapshotV1 | None = None
        self._closed = False

    @workflow.run
    async def run(
        self,
        request: AutonomousCampaignStartBridgeWorkflowInputV1,
    ) -> AutonomousCampaignStartBridgeSnapshotV1:
        self._snapshot = AutonomousCampaignStartBridgeSnapshotV1(
            schema_version=ADMISSION_START_BRIDGE_SCHEMA_VERSION,
            execution_run_id=request.execution_run_id,
            workflow_request_sha256=admission_start_bridge_request_sha256(request),
            state=AutonomousCampaignStartBridgeState.EXECUTION_QUEUED,
            revision=1,
        )
        # CRITICAL: this Workflow must stay effectless until a separately accepted R174 contract.
        await workflow.wait_condition(lambda: self._closed)
        return self._required_snapshot()

    @workflow.query(name="status")
    def status(self) -> AutonomousCampaignStartBridgeSnapshotV1:
        return self._required_snapshot()

    def _required_snapshot(self) -> AutonomousCampaignStartBridgeSnapshotV1:
        if self._snapshot is None:
            raise RuntimeError("start_bridge_workflow_not_initialized")
        return self._snapshot
