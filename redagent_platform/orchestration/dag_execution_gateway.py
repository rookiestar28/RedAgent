"""Closed Temporal gateway for the admitted campaign DAG workflow."""

from __future__ import annotations

from typing import Any

from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError
from temporalio.service import RPCError, RPCStatusCode

from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionSnapshotV1,
    DagWorkflowInputV1,
    DagStopSignalV1,
    dag_workflow_request_sha256,
    deterministic_dag_workflow_id,
)
from redagent_platform.campaign_service.relay import (
    WorkflowAlreadyStarted,
    WorkflowNotFound,
    WorkflowQueryReceipt,
    WorkflowStartReceipt,
    WorkflowStartUnavailable,
    WorkflowStartUnknown,
)
from redagent_platform.orchestration.dag_execution_workflow import (
    CampaignDagExecutionWorkflow,
)
from redagent_platform.orchestration.gateway import OrchestrationUnavailable


class DagExecutionTemporalStartGateway:
    def __init__(self, client: Any, *, task_queue: str) -> None:
        self._client = client
        self._task_queue = _required("task_queue", task_queue, 100)

    async def stop_campaign_dag(self, workflow_id: str, request: DagStopSignalV1, *, run_id: str | None = None) -> None:
        normalized_id = _required("workflow_id", workflow_id, 100)
        if not isinstance(request, DagStopSignalV1):
            raise ValueError("dag_stop_request_invalid")
        if run_id is not None:
            _required("workflow_run_id", run_id, 100)
        try:
            # IMPORTANT: native owner selects the exact workflow/run after durable stop commits.
            # Signal acceptance is only a delivery observation; cleanup remains workflow-owned.
            await self._client.get_workflow_handle(normalized_id, run_id=run_id).signal("stop", request)
        except Exception as exc:
            raise OrchestrationUnavailable("dag_temporal_stop_outcome_unknown") from exc

    async def start(
        self, *, workflow_id: str, request_sha256: str, payload: dict[str, object]
    ) -> WorkflowStartReceipt:
        request = workflow_input_from_dag_start_payload(payload)
        expected_id = deterministic_dag_workflow_id(
            request.tenant_id, request.execution_run_id
        )
        if workflow_id != expected_id:
            raise ValueError("dag_workflow_id_mismatch")
        if request_sha256 != dag_workflow_request_sha256(request):
            raise ValueError("dag_workflow_request_digest_mismatch")
        try:
            handle = await self._client.start_workflow(
                CampaignDagExecutionWorkflow.run,
                request,
                id=expected_id,
                task_queue=self._task_queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
        except WorkflowAlreadyStartedError as exc:
            raise WorkflowAlreadyStarted("dag_workflow_already_started") from exc
        except Exception as exc:
            # CRITICAL: a lost start response does not prove absence; never blindly restart.
            raise WorkflowStartUnknown("dag_temporal_start_outcome_unknown") from exc
        run_id = _started_run_id(handle)
        if run_id is None:
            raise WorkflowStartUnknown("dag_temporal_start_run_id_missing")
        return WorkflowStartReceipt(workflow_run_id=run_id)

    async def query(self, workflow_id: str) -> WorkflowQueryReceipt:
        normalized_id = _required("workflow_id", workflow_id, 100)
        try:
            handle = self._client.get_workflow_handle(normalized_id)
            snapshot = await handle.query(
                "status", result_type=DagExecutionSnapshotV1
            )
            description = await handle.describe()
        except RPCError as exc:
            if exc.status is RPCStatusCode.NOT_FOUND:
                raise WorkflowNotFound("dag_temporal_workflow_not_found") from exc
            raise WorkflowStartUnavailable("dag_temporal_query_unavailable") from exc
        except Exception as exc:
            raise WorkflowStartUnavailable("dag_temporal_query_unavailable") from exc
        if not isinstance(snapshot, DagExecutionSnapshotV1):
            raise WorkflowStartUnavailable("dag_temporal_query_result_invalid")
        return WorkflowQueryReceipt(
            workflow_id=normalized_id,
            request_sha256=snapshot.workflow_request_sha256,
            workflow_run_id=_required_query_run_id(description),
        )


def workflow_input_from_dag_start_payload(
    payload: dict[str, object], *, verify_request_digest: bool = True
) -> DagWorkflowInputV1:
    del verify_request_digest  # The digest is an outer outbox binding, not payload content.
    required = {
        "schema_version",
        "tenant_id",
        "execution_run_id",
        "input_sha256",
        "plan_sha256",
        "max_activity_attempts",
        "max_transitions",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("dag_workflow_payload_fields_invalid")
    if payload["schema_version"] != DAG_EXECUTION_SCHEMA_VERSION:
        raise ValueError("dag_workflow_payload_schema_invalid")
    return DagWorkflowInputV1(
        schema_version=str(payload["schema_version"]),
        tenant_id=str(payload["tenant_id"]),
        execution_run_id=str(payload["execution_run_id"]),
        input_sha256=str(payload["input_sha256"]),
        plan_sha256=str(payload["plan_sha256"]),
        max_activity_attempts=_exact_int(
            "max_activity_attempts", payload["max_activity_attempts"]
        ),
        max_transitions=_exact_int("max_transitions", payload["max_transitions"]),
    )


def _exact_int(name: str, value: object) -> int:
    if type(value) is not int:
        raise ValueError(f"dag_workflow_{name}_invalid")
    return value


def _started_run_id(handle: Any) -> str | None:
    value = getattr(handle, "first_execution_run_id", None) or getattr(
        handle, "run_id", None
    )
    if not isinstance(value, str) or not value or len(value) > 100:
        return None
    return value


def _required_query_run_id(handle: Any) -> str:
    value = _started_run_id(handle)
    if value is None:
        raise WorkflowStartUnavailable("dag_temporal_query_run_id_missing")
    return value


def _required(name: str, value: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name}_invalid")
    return value
