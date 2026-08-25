from __future__ import annotations

import asyncio

import pytest

from redagent_platform.campaign_service.relay import WorkflowAlreadyStarted
from redagent_platform.orchestration.contracts import (
    deterministic_r123_campaign_workflow_id,
    r123_workflow_request_sha256,
)
from redagent_platform.orchestration.compat_123_gateway import (
    R123TemporalStartGateway,
    workflow_input_from_start_payload,
)


class Handle:
    first_execution_run_id = "run-r123"


class Client:
    def __init__(self, *, duplicate: bool = False) -> None:
        self.duplicate = duplicate
        self.calls: list[dict[str, object]] = []

    async def start_workflow(self, workflow, request, **options):
        self.calls.append({"workflow": workflow, "request": request, **options})
        if self.duplicate:
            from temporalio.exceptions import WorkflowAlreadyStartedError

            raise WorkflowAlreadyStartedError(
                workflow_id=options["id"], workflow_type="compat_123", run_id="run-existing"
            )
        return Handle()

    def get_workflow_handle(self, workflow_id: str):
        return QueryHandle(workflow_id)


class Description:
    run_id = "run-query-r123"


class QueryHandle:
    def __init__(self, workflow_id: str) -> None:
        self.workflow_id = workflow_id

    async def query(self, name: str, *, result_type):
        from redagent_platform.orchestration.contracts import R123CampaignSnapshot

        assert name == "status"
        return R123CampaignSnapshot(
            "1.0",
            "campaign-r123",
            "strategy-r123-v1",
            str(_payload()["workflow_request_sha256"]),
            "running",
            1,
            0,
            0,
            None,
            None,
            False,
        )

    async def describe(self):
        return Description()


def _payload() -> dict[str, object]:
    base = {
        "schema_version": "redagent.r123-workflow-start/v1",
        "tenant_id": "tenant-r123",
        "principal_id": "principal-r123",
        "engagement_id": "eng-r123",
        "target_id": "target-r123",
        "campaign_id": "campaign-r123",
        "strategy_revision_id": "strategy-r123-v1",
        "workflow_id": deterministic_r123_campaign_workflow_id(
            "tenant-r123", "campaign-r123"
        ),
        "workflow_request_sha256": "0" * 64,
        "envelope_sha256": "1" * 64,
    }
    request = workflow_input_from_start_payload(base, verify_request_digest=False)
    base["workflow_request_sha256"] = r123_workflow_request_sha256(request)
    return base


def test_gateway_payload_builds_only_fixed_bounded_workflow_input() -> None:
    request = workflow_input_from_start_payload(_payload())

    assert request.tenant_id == "tenant-r123"
    assert request.campaign_id == "campaign-r123"
    assert request.strategy_revision_id == "strategy-r123-v1"
    assert request.max_depth == 2
    assert request.max_replan_count == 1
    assert request.max_activity_attempts == 3

    mutated = _payload()
    mutated["workflow_request_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="r123_workflow_request_digest_mismatch"):
        workflow_input_from_start_payload(mutated)


def test_gateway_rejects_wrong_deterministic_id_before_temporal_call() -> None:
    payload = _payload()
    payload["workflow_id"] = "operator-chosen-workflow"
    client = Client()

    with pytest.raises(ValueError, match="r123_workflow_id_mismatch"):
        asyncio.run(
            R123TemporalStartGateway(client, task_queue="queue-r123").start(
                workflow_id=str(payload["workflow_id"]),
                request_sha256=str(payload["workflow_request_sha256"]),
                payload=payload,
            )
        )
    assert client.calls == []


def test_gateway_starts_exact_versioned_workflow_and_surfaces_duplicate() -> None:
    payload = _payload()
    client = Client()
    gateway = R123TemporalStartGateway(client, task_queue="queue-r123")

    receipt = asyncio.run(
        gateway.start(
            workflow_id=str(payload["workflow_id"]),
            request_sha256=str(payload["workflow_request_sha256"]),
            payload=payload,
        )
    )

    assert receipt.workflow_run_id == "run-r123"
    assert client.calls[0]["id"] == payload["workflow_id"]
    assert client.calls[0]["task_queue"] == "queue-r123"

    duplicate = R123TemporalStartGateway(Client(duplicate=True), task_queue="queue-r123")
    with pytest.raises(WorkflowAlreadyStarted):
        asyncio.run(
            duplicate.start(
                workflow_id=str(payload["workflow_id"]),
                request_sha256=str(payload["workflow_request_sha256"]),
                payload=payload,
            )
        )


def test_gateway_query_returns_exact_workflow_request_binding_and_run() -> None:
    payload = _payload()
    gateway = R123TemporalStartGateway(Client(), task_queue="queue-r123")

    result = asyncio.run(gateway.query(str(payload["workflow_id"])))

    assert result.workflow_id == payload["workflow_id"]
    assert result.request_sha256 == payload["workflow_request_sha256"]
    assert result.workflow_run_id == "run-query-r123"
