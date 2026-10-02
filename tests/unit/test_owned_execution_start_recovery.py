import asyncio

import pytest

from redagent_platform.campaign_service.dag_execution_contracts import (
    dag_workflow_request_sha256,
    deterministic_dag_workflow_id,
)
from redagent_platform.campaign_service.dag_relay import DagWorkflowRelay
from redagent_platform.campaign_service.relay import (
    RelayDeliveryResult,
    WorkflowStartUnknown,
)
from redagent_platform.orchestration.dag_execution_gateway import DagExecutionTemporalStartGateway
from tests.unit.test_campaign_dag_relay import Gateway, NOW, Repository, _claim
from tests.unit.test_campaign_dag_temporal_gateway import _payload, _request


def test_start_rpc_timeout_is_unknown_not_safe_to_retry() -> None:
    class LostResponseClient:
        async def start_workflow(self, *args, **kwargs):
            raise TimeoutError("response lost after server accepted")

    request = _request()
    gateway = DagExecutionTemporalStartGateway(LostResponseClient(), task_queue="queue-owned")
    with pytest.raises(WorkflowStartUnknown):
        asyncio.run(gateway.start(
            workflow_id=deterministic_dag_workflow_id(request.tenant_id, request.execution_run_id),
            request_sha256=dag_workflow_request_sha256(request),
            payload=_payload(),
        ))


def test_unknown_start_attaches_matching_workflow_without_second_start() -> None:
    class UnknownGateway(Gateway):
        async def start(self, **values):
            self.starts.append(values)
            raise WorkflowStartUnknown("response lost")

    gateway = UnknownGateway()
    repository = Repository()
    result = asyncio.run(DagWorkflowRelay(repository=repository, gateway=gateway).deliver(_claim(), now=NOW))
    assert result is RelayDeliveryResult.DUPLICATE_CONFIRMED
    assert len(gateway.starts) == 1
    assert repository.acknowledgements[0]["workflow_run_id"] == "temporal-run-existing"


def test_query_only_recovery_cannot_start_again() -> None:
    from dataclasses import replace

    gateway = Gateway()
    claim = replace(_claim(), reconciliation_only=True)
    repository = Repository()
    result = asyncio.run(DagWorkflowRelay(repository=repository, gateway=gateway).deliver(claim, now=NOW))
    assert result is RelayDeliveryResult.DUPLICATE_CONFIRMED
    assert gateway.starts == []
