from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from redagent_platform.campaign_service.relay_runtime import CampaignRelayPump
from redagent_platform.campaign_service.repository import ClaimedWorkflowStart
from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    CanonicalAuthoritySnapshot,
    ResolutionRequest,
)
from redagent_platform.campaign_service.relay import WorkflowStartReceipt


NOW = datetime(2026, 8, 24, 4, 30, tzinfo=timezone.utc)


class _Tenants:
    def __init__(self) -> None:
        self.cursors: list[str | None] = []

    async def read_page(self, *, after_tenant_id: str | None, limit: int):
        self.cursors.append(after_tenant_id)
        assert limit == 2
        if after_tenant_id is None:
            return ("tenant-a", "tenant-b")
        return ()


class _Provider:
    async def read_current_authority(self, request: ResolutionRequest):
        return replace(
            _snapshot(),
            tenant_id=request.tenant_id,
            principal_id=request.principal_id,
            engagement_id=request.engagement_id,
            target_id=request.target_id,
            target_sha256=_target_digest(request.target_id),
        )


class _Repository:
    def __init__(self, tenant_id: str, *, wrong_tenant: bool = False) -> None:
        self.tenant_id = tenant_id
        self.wrong_tenant = wrong_tenant
        self.acknowledged: list[dict[str, object]] = []

    async def claim_workflow_starts(self, *, claim_owner, now, lease_seconds, limit):
        del now
        assert lease_seconds == 30 and limit == 1
        tenant_id = "tenant-other" if self.wrong_tenant else self.tenant_id
        return [_claim(tenant_id, claim_owner)]

    async def acknowledge_workflow_start(self, **values):
        self.acknowledged.append(values)

    async def record_workflow_start_failure(self, **values):
        raise AssertionError(values)


class _Repositories:
    def __init__(self, *, wrong_tenant: bool = False) -> None:
        self.wrong_tenant = wrong_tenant
        self.created: dict[str, _Repository] = {}

    def __call__(self, tenant_id: str) -> _Repository:
        repository = _Repository(tenant_id, wrong_tenant=self.wrong_tenant)
        self.created[tenant_id] = repository
        return repository


class _Gateway:
    def __init__(self) -> None:
        self.started: list[dict[str, object]] = []

    async def start(self, **values):
        self.started.append(values)
        return WorkflowStartReceipt(workflow_run_id=f"run-{len(self.started)}")

    async def query(self, workflow_id: str):
        raise AssertionError(workflow_id)


def test_relay_pump_pages_tenants_and_delivers_each_claim_under_its_exact_partition() -> None:
    tenants = _Tenants()
    repositories = _Repositories()
    gateway = _Gateway()
    pump = CampaignRelayPump(
        tenant_source=tenants,
        repository_factory=repositories,
        resolver=CampaignContextResolver(_Provider()),
        gateway=gateway,
        claim_owner="relay-instance-r123",
        tenant_page_size=2,
        claim_limit=1,
    )

    delivered = asyncio.run(pump.run_once(now=NOW))

    assert delivered == 2
    assert tenants.cursors == [None, "tenant-b"]
    assert [item["payload"]["tenant_id"] for item in gateway.started] == [
        "tenant-a",
        "tenant-b",
    ]
    assert all(repository.acknowledged for repository in repositories.created.values())


def test_relay_pump_rejects_a_claim_that_escapes_the_current_tenant_partition() -> None:
    gateway = _Gateway()
    pump = CampaignRelayPump(
        tenant_source=_Tenants(),
        repository_factory=_Repositories(wrong_tenant=True),
        resolver=CampaignContextResolver(_Provider()),
        gateway=gateway,
        claim_owner="relay-instance-r123",
        tenant_page_size=2,
        claim_limit=1,
    )

    with pytest.raises(ValueError, match="r123_relay_claim_tenant_mismatch"):
        asyncio.run(pump.run_once(now=NOW))
    assert gateway.started == []


def _claim(tenant_id: str, claim_owner: str) -> ClaimedWorkflowStart:
    suffix = tenant_id.rsplit("-", 1)[-1]
    return ClaimedWorkflowStart(
        event_id=f"event-{suffix}",
        campaign_id=f"campaign-{suffix}",
        aggregate_sequence=1,
        attempt_count=1,
        claim_owner=claim_owner,
        claim_expires_at=NOW + timedelta(seconds=30),
        payload={
            "schema_version": "redagent.r123-workflow-start/v1",
            "tenant_id": tenant_id,
            "principal_id": f"principal-{suffix}",
            "engagement_id": f"eng-{suffix}",
            "target_id": f"target-{suffix}",
            "campaign_id": f"campaign-{suffix}",
            "strategy_revision_id": f"strategy-{suffix}",
            "workflow_id": f"workflow-{suffix}",
            "workflow_request_sha256": "9" * 64,
            "envelope_sha256": "8" * 64,
        },
    )


def _snapshot() -> CanonicalAuthoritySnapshot:
    target_sha256 = _target_digest("target-a")
    return CanonicalAuthoritySnapshot(
        tenant_id="tenant-a",
        principal_id="principal-a",
        engagement_id="eng-a",
        engagement_version=1,
        roe_version_id="roe-a",
        roe_revision=1,
        roe_sha256="1" * 64,
        roe_status="approved",
        roe_revocation_epoch=0,
        policy_decision_id="decision-a",
        policy_revision="policy-r123",
        policy_sha256="2" * 64,
        policy_status="allowed",
        policy_revocation_epoch=0,
        target_id="target-a",
        target_revision=1,
        target_sha256=target_sha256,
        target_value="http://127.0.0.1:41731",
        target_resolution_mode="owned-loopback",
        credential_class="none",
        credential_reference=None,
        quota_reference="quota-a",
        quota_available=True,
        runner_id="runner-a",
        runner_workload_identity="spiffe://redagent.test/runner-a",
        runner_ready=True,
        reservation_id="reservation-a",
        lease_id="lease-a",
        lease_expires_at=NOW + timedelta(minutes=5),
        stop_requested=False,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def _target_digest(target_id: str) -> str:
    return hashlib.sha256(json.dumps({
        "target_id": target_id,
        "revision": 1,
        "target_type": "url",
        "normalized_value": "http://127.0.0.1:41731",
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
