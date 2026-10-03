import asyncio

import pytest

from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
    DagWorkflowInputV1,
    DagStopSignalV1,
    dag_workflow_request_sha256,
    deterministic_dag_workflow_id,
)
from redagent_platform.campaign_service.relay import WorkflowAlreadyStarted
from redagent_platform.orchestration.dag_execution_gateway import (
    DagExecutionTemporalStartGateway,
    workflow_input_from_dag_start_payload,
)
from redagent_platform.orchestration.gateway import OrchestrationUnavailable


@pytest.mark.parametrize("unavailable", [False, True])
def test_dag_stop_gateway_uses_exact_native_workflow_run_and_never_claims_containment(unavailable):
    calls = []
    class SignalHandle:
        async def signal(self, name, request):
            calls.append((name, request))
            if unavailable:
                raise OSError("untrusted-transport-detail")
    class SignalClient:
        def get_workflow_handle(self, workflow_id, *, run_id):
            calls.append((workflow_id, run_id))
            return SignalHandle()
    request = DagStopSignalV1(DAG_EXECUTION_SCHEMA_VERSION, "stop-a", "operator-a", "a" * 64)
    gateway = DagExecutionTemporalStartGateway(SignalClient(), task_queue="queue-dag")
    operation = gateway.stop_campaign_dag("workflow-a", request, run_id="run-a")
    if unavailable:
        with pytest.raises(OrchestrationUnavailable, match="dag_temporal_stop_outcome_unknown"):
            asyncio.run(operation)
    else:
        assert asyncio.run(operation) is None
    assert calls == [("workflow-a", "run-a"), ("stop", request)]


def _request() -> DagWorkflowInputV1:
    return DagWorkflowInputV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        tenant_id="tenant-a",
        execution_run_id="dag-run-a",
        input_sha256="a" * 64,
        plan_sha256="b" * 64,
        max_activity_attempts=3,
        max_transitions=20,
    )


def _payload() -> dict[str, object]:
    request = _request()
    return {
        "schema_version": request.schema_version,
        "tenant_id": request.tenant_id,
        "execution_run_id": request.execution_run_id,
        "input_sha256": request.input_sha256,
        "plan_sha256": request.plan_sha256,
        "max_activity_attempts": request.max_activity_attempts,
        "max_transitions": request.max_transitions,
    }


class Handle:
    first_execution_run_id = "temporal-run-a"


class QueryHandle:
    async def query(self, name, *, result_type):
        assert name == "status"
        return DagExecutionSnapshotV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            execution_run_id="dag-run-a",
            workflow_request_sha256=dag_workflow_request_sha256(_request()),
            state=DagRunState.RUNNING,
            revision=2,
            transition_count=1,
            current_node_id="node-a",
            current_node_state=DagNodeState.RESERVED,
            stop_requested=False,
            terminal_reason=None,
        )

    async def describe(self):
        return Handle()


class Client:
    def __init__(self, duplicate=False):
        self.duplicate = duplicate
        self.calls = []

    async def start_workflow(self, workflow, request, **options):
        self.calls.append((workflow, request, options))
        if self.duplicate:
            from temporalio.exceptions import WorkflowAlreadyStartedError

            raise WorkflowAlreadyStartedError(
                workflow_id=options["id"], workflow_type="campaign-dag", run_id="run-existing"
            )
        return Handle()

    def get_workflow_handle(self, workflow_id):
        return QueryHandle()


def test_gateway_starts_exact_frozen_workflow_identity() -> None:
    request = _request()
    workflow_id = deterministic_dag_workflow_id(
        request.tenant_id, request.execution_run_id
    )
    client = Client()
    result = asyncio.run(
        DagExecutionTemporalStartGateway(client, task_queue="queue-dag").start(
            workflow_id=workflow_id,
            request_sha256=dag_workflow_request_sha256(request),
            payload=_payload(),
        )
    )

    assert result.workflow_run_id == "temporal-run-a"
    assert client.calls[0][2]["id"] == workflow_id
    assert workflow_input_from_dag_start_payload(_payload()) == request


def test_gateway_rejects_digest_substitution_and_surfaces_duplicate() -> None:
    request = _request()
    workflow_id = deterministic_dag_workflow_id(
        request.tenant_id, request.execution_run_id
    )
    gateway = DagExecutionTemporalStartGateway(Client(), task_queue="queue-dag")
    with pytest.raises(ValueError, match="dag_workflow_request_digest_mismatch"):
        asyncio.run(
            gateway.start(
                workflow_id=workflow_id,
                request_sha256="f" * 64,
                payload=_payload(),
            )
        )
    with pytest.raises(WorkflowAlreadyStarted):
        asyncio.run(
            DagExecutionTemporalStartGateway(
                Client(duplicate=True), task_queue="queue-dag"
            ).start(
                workflow_id=workflow_id,
                request_sha256=dag_workflow_request_sha256(request),
                payload=_payload(),
            )
        )


def test_gateway_queries_the_exact_bounded_snapshot_binding() -> None:
    request = _request()
    workflow_id = deterministic_dag_workflow_id(
        request.tenant_id, request.execution_run_id
    )
    receipt = asyncio.run(
        DagExecutionTemporalStartGateway(Client(), task_queue="queue-dag").query(
            workflow_id
        )
    )

    assert receipt.workflow_id == workflow_id
    assert receipt.request_sha256 == dag_workflow_request_sha256(request)
    assert receipt.workflow_run_id == "temporal-run-a"
