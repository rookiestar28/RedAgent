"""Closed Temporal gateway for the R173 zero-Activity start bridge."""

from __future__ import annotations

from typing import Any

from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError
from temporalio.service import RPCError, RPCStatusCode

from redagent_platform.orchestration.admission_start_contracts import (
    ADMISSION_START_BRIDGE_SCHEMA_VERSION,
    AutonomousCampaignStartBridgeSnapshotV1,
    AutonomousCampaignStartBridgeState,
    AutonomousCampaignStartBridgeWorkflowInputV1,
    admission_start_bridge_request_sha256,
    deterministic_admission_start_bridge_workflow_id,
)
from redagent_platform.campaign_service.relay import (
    WorkflowAlreadyStarted,
    WorkflowNotFound,
    WorkflowQueryReceipt,
    WorkflowStartReceipt,
    WorkflowStartUnknown,
    WorkflowStartUnavailable,
)
from redagent_platform.orchestration.admission_start_workflow import (
    AutonomousCampaignStartBridgeWorkflow,
)


class AutonomousCampaignStartBridgeTemporalGateway:
    def __init__(self, client: Any, *, task_queue: str) -> None:
        self._client = client
        self._task_queue = _required("start_bridge_task_queue", task_queue, 100)

    async def start(
        self,
        *,
        workflow_id: str,
        request_sha256: str,
        payload: dict[str, object],
    ) -> WorkflowStartReceipt:
        request = workflow_input_from_admission_start_payload(payload)
        expected_id = deterministic_admission_start_bridge_workflow_id(
            request.tenant_id,
            request.execution_run_id,
        )
        if workflow_id != expected_id:
            raise ValueError("start_bridge_workflow_id_mismatch")
        if request_sha256 != admission_start_bridge_request_sha256(request):
            raise ValueError("start_bridge_workflow_request_digest_mismatch")
        try:
            handle = await self._client.start_workflow(
                AutonomousCampaignStartBridgeWorkflow.run,
                request,
                id=expected_id,
                task_queue=self._task_queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
        except WorkflowAlreadyStartedError as exc:
            raise WorkflowAlreadyStarted("start_bridge_workflow_already_started") from exc
        except Exception as exc:
            # CRITICAL: after a start RPC exception, absence is unproven; a blind retry can
            # attach different material to an already-created deterministic Workflow ID.
            raise WorkflowStartUnknown("start_bridge_temporal_start_outcome_unknown") from exc
        run_id = _started_run_id(handle)
        if run_id is None:
            # CRITICAL: a returned handle without a run ID follows a successful start RPC;
            # absence is unproven, so this must never enter the before-I/O retry path.
            raise WorkflowStartUnknown("start_bridge_temporal_run_id_missing")
        return WorkflowStartReceipt(workflow_run_id=run_id)

    async def query(self, workflow_id: str) -> WorkflowQueryReceipt:
        normalized_id = _required("start_bridge_workflow_id", workflow_id, 100)
        try:
            handle = self._client.get_workflow_handle(normalized_id)
            raw_snapshot = await handle.query("status")
            snapshot = _snapshot_from_query(raw_snapshot)
            description = await handle.describe()
        except RPCError as exc:
            if exc.status is RPCStatusCode.NOT_FOUND:
                # CRITICAL: only the SDK's exact NOT_FOUND status proves absence; all
                # other query failures remain charged unknown outcomes.
                raise WorkflowNotFound("start_bridge_temporal_workflow_not_found") from exc
            raise WorkflowStartUnavailable("start_bridge_temporal_query_unavailable") from exc
        except Exception as exc:
            raise WorkflowStartUnavailable("start_bridge_temporal_query_unavailable") from exc
        return WorkflowQueryReceipt(
            workflow_id=normalized_id,
            request_sha256=snapshot.workflow_request_sha256,
            workflow_run_id=_required_run_id(description),
        )


def workflow_input_from_admission_start_payload(
    payload: dict[str, object],
) -> AutonomousCampaignStartBridgeWorkflowInputV1:
    required = {
        "schema_version",
        "tenant_id",
        "campaign_id",
        "execution_run_id",
        "input_sha256",
        "approval_receipt_sha256",
        "admission_receipt_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("start_bridge_payload_fields_invalid")
    if payload["schema_version"] != ADMISSION_START_BRIDGE_SCHEMA_VERSION:
        raise ValueError("start_bridge_payload_schema_invalid")
    return AutonomousCampaignStartBridgeWorkflowInputV1(
        schema_version=str(payload["schema_version"]),
        tenant_id=str(payload["tenant_id"]),
        campaign_id=str(payload["campaign_id"]),
        execution_run_id=str(payload["execution_run_id"]),
        input_sha256=str(payload["input_sha256"]),
        approval_receipt_sha256=str(payload["approval_receipt_sha256"]),
        admission_receipt_sha256=str(payload["admission_receipt_sha256"]),
    )


def _started_run_id(value: object) -> str | None:
    run_id = getattr(value, "first_execution_run_id", None) or getattr(value, "run_id", None)
    if not isinstance(run_id, str) or not run_id or len(run_id) > 100:
        return None
    return run_id


def _snapshot_from_query(value: object) -> AutonomousCampaignStartBridgeSnapshotV1:
    if isinstance(value, AutonomousCampaignStartBridgeSnapshotV1):
        return value
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "execution_run_id",
        "workflow_request_sha256",
        "state",
        "revision",
    }:
        raise WorkflowStartUnavailable("start_bridge_temporal_query_result_invalid")
    try:
        return AutonomousCampaignStartBridgeSnapshotV1(
            schema_version=str(value["schema_version"]),
            execution_run_id=str(value["execution_run_id"]),
            workflow_request_sha256=str(value["workflow_request_sha256"]),
            state=AutonomousCampaignStartBridgeState(str(value["state"])),
            revision=value["revision"],
        )
    except (TypeError, ValueError) as exc:
        raise WorkflowStartUnavailable(
            "start_bridge_temporal_query_result_invalid"
        ) from exc


def _required_run_id(value: object) -> str:
    run_id = _started_run_id(value)
    if run_id is None:
        raise WorkflowStartUnavailable("start_bridge_temporal_query_run_id_missing")
    return run_id


def _required(name: str, value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name}_invalid")
    return value
