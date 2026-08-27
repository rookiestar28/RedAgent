"""Exact Temporal gateway implementing the compat_123 workflow-start relay port."""

from __future__ import annotations

from typing import Any

from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from redagent_platform.campaign_service.relay import (
    WorkflowAlreadyStarted,
    WorkflowQueryReceipt,
    WorkflowStartReceipt,
    WorkflowStartUnavailable,
)
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ClosedLoopCampaignSnapshot,
    ClosedLoopCampaignWorkflowInput,
    deterministic_closed_loop_campaign_workflow_id,
    closed_loop_workflow_request_sha256,
)
from redagent_platform.orchestration.workflow import ClosedLoopWorkflow


class ClosedLoopTemporalStartGateway:
    def __init__(self, client: Any, *, task_queue: str) -> None:
        self._client = client
        self._task_queue = _required("task_queue", task_queue, 100)

    async def start(
        self, *, workflow_id: str, request_sha256: str, payload: dict[str, object]
    ) -> WorkflowStartReceipt:
        request = workflow_input_from_start_payload(payload)
        expected_id = deterministic_closed_loop_campaign_workflow_id(
            request.tenant_id, request.campaign_id
        )
        if workflow_id != expected_id or payload.get("workflow_id") != expected_id:
            raise ValueError("r123_workflow_id_mismatch")
        if request_sha256 != closed_loop_workflow_request_sha256(request):
            raise ValueError("r123_workflow_request_digest_mismatch")
        try:
            handle = await self._client.start_workflow(
                ClosedLoopWorkflow.run,
                request,
                id=expected_id,
                task_queue=self._task_queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
        except WorkflowAlreadyStartedError as exc:
            raise WorkflowAlreadyStarted("r123_workflow_already_started") from exc
        except Exception as exc:
            raise WorkflowStartUnavailable("temporal_start_unavailable") from exc
        run_id = _started_run_id(handle)
        if run_id is None:
            raise WorkflowStartUnavailable("temporal_start_run_id_missing")
        return WorkflowStartReceipt(workflow_run_id=run_id)

    async def query(self, workflow_id: str) -> WorkflowQueryReceipt:
        normalized_id = _required("workflow_id", workflow_id, 64)
        try:
            handle = self._client.get_workflow_handle(normalized_id)
            snapshot = await handle.query(
                "status", result_type=ClosedLoopCampaignSnapshot
            )
            description = await handle.describe()
        except Exception as exc:
            raise WorkflowStartUnavailable("temporal_query_unavailable") from exc
        if not isinstance(snapshot, ClosedLoopCampaignSnapshot):
            raise WorkflowStartUnavailable("temporal_query_result_invalid")
        return WorkflowQueryReceipt(
            workflow_id=normalized_id,
            request_sha256=snapshot.workflow_request_sha256,
            workflow_run_id=_required_query_run_id(description),
        )


def workflow_input_from_start_payload(
    payload: dict[str, object], *, verify_request_digest: bool = True
) -> ClosedLoopCampaignWorkflowInput:
    required = {
        "schema_version",
        "tenant_id",
        "principal_id",
        "engagement_id",
        "target_id",
        "campaign_id",
        "strategy_revision_id",
        "workflow_id",
        "workflow_request_sha256",
        "envelope_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("r123_workflow_payload_fields_invalid")
    if payload["schema_version"] != "redagent.r123-workflow-start/v1":
        raise ValueError("r123_workflow_payload_schema_invalid")
    request = ClosedLoopCampaignWorkflowInput(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id=str(payload["tenant_id"]),
        campaign_id=str(payload["campaign_id"]),
        strategy_revision_id=str(payload["strategy_revision_id"]),
        envelope_sha256=str(payload["envelope_sha256"]),
        max_depth=2,
        max_replan_count=1,
        max_activity_attempts=3,
    )
    expected_id = deterministic_closed_loop_campaign_workflow_id(
        request.tenant_id, request.campaign_id
    )
    if payload["workflow_id"] != expected_id:
        raise ValueError("r123_workflow_id_mismatch")
    if (
        verify_request_digest
        and payload["workflow_request_sha256"] != closed_loop_workflow_request_sha256(request)
    ):
        raise ValueError("r123_workflow_request_digest_mismatch")
    return request


def _started_run_id(handle: Any) -> str | None:
    value = getattr(handle, "first_execution_run_id", None) or getattr(handle, "run_id", None)
    if not isinstance(value, str) or not value or len(value) > 100:
        return None
    return value


def _required_query_run_id(handle: Any) -> str:
    value = _started_run_id(handle)
    if value is None:
        raise WorkflowStartUnavailable("temporal_query_run_id_missing")
    return value


def _required(name: str, value: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name}_invalid")
    return value
