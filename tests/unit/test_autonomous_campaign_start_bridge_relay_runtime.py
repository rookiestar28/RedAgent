from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.campaign_service.admission_start_contracts import (
    ADMISSION_START_BRIDGE_SCHEMA_VERSION,
    AutonomousCampaignStartBridgeWorkflowInputV1,
)
from redagent_platform.campaign_service.admission_start_relay_runtime import (
    AutonomousCampaignStartBridgeRelayPump,
)
from redagent_platform.campaign_service.repository import ClaimedWorkflowStart
from redagent_platform.campaign_service.relay import WorkflowStartReceipt


NOW = datetime(2026, 8, 30, 12, tzinfo=timezone.utc)


def _payload(tenant_id: str) -> dict[str, object]:
    return asdict(
        AutonomousCampaignStartBridgeWorkflowInputV1(
            schema_version=ADMISSION_START_BRIDGE_SCHEMA_VERSION,
            tenant_id=tenant_id,
            campaign_id=f"campaign-{tenant_id}",
            execution_run_id=f"run-{tenant_id}",
            input_sha256="a" * 64,
            approval_receipt_sha256="b" * 64,
            admission_receipt_sha256="c" * 64,
        )
    )


class Tenants:
    async def read_page(self, *, after_tenant_id, limit):
        assert limit == 50
        return ("tenant-a", "tenant-b") if after_tenant_id is None else ()


class Repository:
    def __init__(self, tenant_id: str, *, claim_tenant_id: str | None = None) -> None:
        self.tenant_id = tenant_id
        self.claim_tenant_id = claim_tenant_id or tenant_id
        self.acknowledgements: list[dict[str, object]] = []

    async def claim_admission_start_bridges(self, **values):
        assert values["claim_owner"] == "start-bridge-relay-a"
        return [
            ClaimedWorkflowStart(
                event_id=f"event-{self.tenant_id}",
                # Shared carrier field holds the R173 start aggregate, not a campaign ID.
                campaign_id=f"start-{self.tenant_id}",
                aggregate_sequence=1,
                attempt_count=1,
                claim_owner="start-bridge-relay-a",
                claim_expires_at=NOW + timedelta(seconds=30),
                payload=_payload(self.claim_tenant_id),
            )
        ]

    async def acknowledge_admission_start_bridge(self, **values):
        self.acknowledgements.append(values)

    async def confirm_admission_start_bridge_ready(self, **values):
        assert values["payload"] == _payload(self.tenant_id)
        return True

    async def record_admission_start_bridge_failure(self, **values):
        raise AssertionError(values)


class Gateway:
    def __init__(self) -> None:
        self.starts: list[dict[str, object]] = []

    async def start(self, **values):
        self.starts.append(values)
        return WorkflowStartReceipt(
            workflow_run_id=f"temporal-{values['workflow_id'][-8:]}"
        )

    async def query(self, workflow_id):
        raise AssertionError(workflow_id)


def test_start_bridge_relay_pump_partitions_claims_and_delivers_each_once() -> None:
    repositories = {
        tenant: Repository(tenant) for tenant in ("tenant-a", "tenant-b")
    }
    gateway = Gateway()
    pump = AutonomousCampaignStartBridgeRelayPump(
        tenant_source=Tenants(),
        repository_factory=repositories.__getitem__,
        gateway=gateway,
        claim_owner="start-bridge-relay-a",
    )

    assert asyncio.run(pump.run_once(now=NOW)) == 2
    assert len(gateway.starts) == 2
    assert all(len(item.acknowledgements) == 1 for item in repositories.values())


def test_start_bridge_relay_pump_rejects_cross_tenant_claim_before_temporal() -> None:
    repositories = {
        "tenant-a": Repository("tenant-a", claim_tenant_id="tenant-other"),
        "tenant-b": Repository("tenant-b"),
    }
    gateway = Gateway()
    pump = AutonomousCampaignStartBridgeRelayPump(
        tenant_source=Tenants(),
        repository_factory=repositories.__getitem__,
        gateway=gateway,
        claim_owner="start-bridge-relay-a",
    )

    with pytest.raises(ValueError, match="start_bridge_relay_claim_tenant_mismatch"):
        asyncio.run(pump.run_once(now=NOW))
    assert gateway.starts == []
