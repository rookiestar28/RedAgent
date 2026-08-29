from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
    deterministic_dag_workflow_id,
)
from redagent_platform.campaign_service.dag_relay import DagWorkflowRelay
from redagent_platform.campaign_service.relay import (
    RelayDeliveryResult,
    WorkflowAlreadyStarted,
    WorkflowQueryReceipt,
    WorkflowStartReceipt,
)
from redagent_platform.campaign_service.repository import ClaimedWorkflowStart


NOW = datetime(2026, 8, 29, 9, tzinfo=timezone.utc)


def _request() -> DagWorkflowInputV1:
    return DagWorkflowInputV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        tenant_id="tenant-a",
        execution_run_id="run-a",
        input_sha256="a" * 64,
        plan_sha256="b" * 64,
        max_activity_attempts=3,
        max_transitions=20,
    )


def _claim() -> ClaimedWorkflowStart:
    return ClaimedWorkflowStart(
        event_id="event-a",
        campaign_id="run-a",
        aggregate_sequence=1,
        attempt_count=1,
        claim_owner="relay-a",
        claim_expires_at=NOW + timedelta(seconds=30),
        payload=asdict(_request()),
    )


class Repository:
    def __init__(self) -> None:
        self.acknowledgements = []
        self.failures = []

    async def acknowledge_dag_workflow_start(self, **values):
        self.acknowledgements.append(values)

    async def record_dag_workflow_start_failure(self, **values):
        self.failures.append(values)


class Gateway:
    def __init__(self, *, duplicate: bool = False, mismatch: bool = False) -> None:
        self.duplicate = duplicate
        self.mismatch = mismatch
        self.starts = []

    async def start(self, **values):
        self.starts.append(values)
        if self.duplicate:
            raise WorkflowAlreadyStarted("already")
        return WorkflowStartReceipt(workflow_run_id="temporal-run-a")

    async def query(self, workflow_id):
        request = _request()
        return WorkflowQueryReceipt(
            workflow_id=workflow_id,
            request_sha256=(
                "f" * 64 if self.mismatch else dag_workflow_request_sha256(request)
            ),
            workflow_run_id="temporal-run-existing",
        )


def test_dag_relay_derives_outer_identity_and_acknowledges_exact_start() -> None:
    repository = Repository()
    gateway = Gateway()
    result = asyncio.run(
        DagWorkflowRelay(repository=repository, gateway=gateway).deliver(
            _claim(), now=NOW
        )
    )

    request = _request()
    assert result is RelayDeliveryResult.DELIVERED
    assert gateway.starts == [
        {
            "workflow_id": deterministic_dag_workflow_id(
                request.tenant_id, request.execution_run_id
            ),
            "request_sha256": dag_workflow_request_sha256(request),
            "payload": asdict(request),
        }
    ]
    assert repository.acknowledgements[0]["workflow_run_id"] == "temporal-run-a"


def test_dag_relay_confirms_only_exact_duplicate_binding() -> None:
    repository = Repository()
    result = asyncio.run(
        DagWorkflowRelay(
            repository=repository, gateway=Gateway(duplicate=True)
        ).deliver(_claim(), now=NOW)
    )
    assert result is RelayDeliveryResult.DUPLICATE_CONFIRMED
    assert repository.acknowledgements[0]["duplicate_confirmed"] is True

    repository = Repository()
    result = asyncio.run(
        DagWorkflowRelay(
            repository=repository, gateway=Gateway(duplicate=True, mismatch=True)
        ).deliver(_claim(), now=NOW)
    )
    assert result is RelayDeliveryResult.RECONCILIATION_REQUIRED
    assert repository.acknowledgements == []
    assert repository.failures[0]["last_error"] == "duplicate_binding_mismatch"
