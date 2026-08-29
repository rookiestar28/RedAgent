from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagWorkflowInputV1,
)
from redagent_platform.campaign_service.dag_relay_runtime import DagRelayPump
from redagent_platform.campaign_service.repository import ClaimedWorkflowStart
from redagent_platform.campaign_service.relay import WorkflowStartReceipt


NOW = datetime(2026, 8, 29, 10, tzinfo=timezone.utc)


def _payload(tenant_id: str) -> dict[str, object]:
    return asdict(
        DagWorkflowInputV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            tenant_id=tenant_id,
            execution_run_id=f"run-{tenant_id}",
            input_sha256="a" * 64,
            plan_sha256="b" * 64,
            max_activity_attempts=3,
            max_transitions=20,
        )
    )


class Tenants:
    async def read_page(self, *, after_tenant_id, limit):
        assert limit == 50
        return ("tenant-a", "tenant-b") if after_tenant_id is None else ()


class Repository:
    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.acknowledgements = []

    async def claim_dag_workflow_starts(self, **values):
        assert values["claim_owner"] == "dag-relay-a"
        return [
            ClaimedWorkflowStart(
                event_id=f"event-{self.tenant_id}",
                campaign_id=f"run-{self.tenant_id}",
                aggregate_sequence=1,
                attempt_count=1,
                claim_owner="dag-relay-a",
                claim_expires_at=NOW + timedelta(seconds=30),
                payload=_payload(self.tenant_id),
            )
        ]

    async def acknowledge_dag_workflow_start(self, **values):
        self.acknowledgements.append(values)

    async def record_dag_workflow_start_failure(self, **values):
        raise AssertionError(values)


class Gateway:
    async def start(self, **values):
        return WorkflowStartReceipt(workflow_run_id=f"temporal-{values['workflow_id'][-8:]}")

    async def query(self, workflow_id):
        raise AssertionError(workflow_id)


def test_dag_relay_pump_partitions_claims_and_delivers_each_once() -> None:
    repositories = {tenant: Repository(tenant) for tenant in ("tenant-a", "tenant-b")}
    pump = DagRelayPump(
        tenant_source=Tenants(),
        repository_factory=repositories.__getitem__,
        gateway=Gateway(),
        claim_owner="dag-relay-a",
    )

    assert asyncio.run(pump.run_once(now=NOW)) == 2
    assert all(len(item.acknowledgements) == 1 for item in repositories.values())
