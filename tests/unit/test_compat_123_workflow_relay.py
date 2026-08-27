from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json

from redagent_platform.campaign_service.relay import (
    OutboxDeliveryState,
    CampaignWorkflowRelay,
    RelayDeliveryResult,
    RelayFailure,
    WorkflowAlreadyStarted,
    WorkflowQueryReceipt,
    WorkflowStartReceipt,
    WorkflowStartUnavailable,
)
from redagent_platform.campaign_service.repository import ClaimedWorkflowStart
from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    CanonicalAuthoritySnapshot,
    ResolutionRequest,
)


NOW = datetime(2026, 8, 24, 1, 30, tzinfo=timezone.utc)


class Provider:
    def __init__(self, snapshot: CanonicalAuthoritySnapshot | None) -> None:
        self.snapshot = snapshot
        self.requests: list[ResolutionRequest] = []

    async def read_current_authority(self, request: ResolutionRequest):
        self.requests.append(request)
        return self.snapshot


class Repository:
    def __init__(self) -> None:
        self.acknowledged: list[dict[str, object]] = []
        self.failures: list[dict[str, object]] = []

    async def acknowledge_workflow_start(self, **values):
        self.acknowledged.append(values)

    async def record_workflow_start_failure(self, **values):
        self.failures.append(values)


class Gateway:
    def __init__(
        self,
        *,
        start_result: WorkflowStartReceipt | Exception,
        query_result: WorkflowQueryReceipt | Exception | None = None,
    ) -> None:
        self.start_result = start_result
        self.query_result = query_result
        self.started: list[dict[str, object]] = []
        self.queried: list[str] = []

    async def start(self, **values):
        self.started.append(values)
        if isinstance(self.start_result, Exception):
            raise self.start_result
        return self.start_result

    async def query(self, workflow_id: str):
        self.queried.append(workflow_id)
        if isinstance(self.query_result, Exception):
            raise self.query_result
        assert self.query_result is not None
        return self.query_result


def test_relay_rechecks_current_authority_before_temporal_start() -> None:
    provider = Provider(None)
    repository = Repository()
    gateway = Gateway(start_result=WorkflowStartReceipt(workflow_run_id="run-r123"))

    result = asyncio.run(
        CampaignWorkflowRelay(
            resolver=CampaignContextResolver(provider), repository=repository, gateway=gateway
        ).deliver(_claim(), now=NOW)
    )

    assert result is RelayDeliveryResult.AUTHORITY_DENIED
    assert gateway.started == []
    assert repository.acknowledged == []
    assert repository.failures[0]["failure"] is RelayFailure.PERMANENT
    assert repository.failures[0]["last_error"] == "canonical_authority_not_found"


def test_relay_starts_exact_request_and_acknowledges_exact_claim() -> None:
    provider = Provider(_snapshot())
    repository = Repository()
    gateway = Gateway(start_result=WorkflowStartReceipt(workflow_run_id="run-r123"))

    result = asyncio.run(
        CampaignWorkflowRelay(
            resolver=CampaignContextResolver(provider), repository=repository, gateway=gateway
        ).deliver(_claim(), now=NOW)
    )

    assert result is RelayDeliveryResult.DELIVERED
    assert gateway.started == [
        {
            "workflow_id": "workflow-r123",
            "request_sha256": "9" * 64,
            "payload": _claim().payload,
        }
    ]
    assert repository.acknowledged[0]["event_id"] == "event-r123"
    assert repository.acknowledged[0]["claim_owner"] == "relay-r123"
    assert repository.acknowledged[0]["workflow_run_id"] == "run-r123"
    assert repository.acknowledged[0]["duplicate_confirmed"] is False


def test_relay_reconciles_duplicate_start_only_on_exact_digest_match() -> None:
    exact_repository = Repository()
    exact_gateway = Gateway(
        start_result=WorkflowAlreadyStarted("workflow_exists"),
        query_result=WorkflowQueryReceipt(
            workflow_id="workflow-r123",
            request_sha256="9" * 64,
            workflow_run_id="run-existing",
        ),
    )
    exact = asyncio.run(
        CampaignWorkflowRelay(
            resolver=CampaignContextResolver(Provider(_snapshot())),
            repository=exact_repository,
            gateway=exact_gateway,
        ).deliver(_claim(), now=NOW)
    )
    assert exact is RelayDeliveryResult.DUPLICATE_CONFIRMED
    assert exact_repository.acknowledged[0]["duplicate_confirmed"] is True

    mismatch_repository = Repository()
    mismatch_gateway = Gateway(
        start_result=WorkflowAlreadyStarted("workflow_exists"),
        query_result=WorkflowQueryReceipt(
            workflow_id="workflow-r123",
            request_sha256="8" * 64,
            workflow_run_id="run-existing",
        ),
    )
    mismatch = asyncio.run(
        CampaignWorkflowRelay(
            resolver=CampaignContextResolver(Provider(_snapshot())),
            repository=mismatch_repository,
            gateway=mismatch_gateway,
        ).deliver(_claim(), now=NOW)
    )
    assert mismatch is RelayDeliveryResult.RECONCILIATION_REQUIRED
    assert mismatch_repository.acknowledged == []
    assert mismatch_repository.failures[0]["failure"] is RelayFailure.AMBIGUOUS_START


def test_relay_classifies_definite_unavailability_as_bounded_retry() -> None:
    repository = Repository()
    gateway = Gateway(start_result=WorkflowStartUnavailable("temporal_unavailable"))

    result = asyncio.run(
        CampaignWorkflowRelay(
            resolver=CampaignContextResolver(Provider(_snapshot())),
            repository=repository,
            gateway=gateway,
        ).deliver(_claim(), now=NOW)
    )

    assert result is RelayDeliveryResult.RETRY_SCHEDULED
    assert repository.failures[0]["failure"] is RelayFailure.TRANSIENT
    assert repository.failures[0]["last_error"] == "temporal_unavailable"


def _claim() -> ClaimedWorkflowStart:
    return ClaimedWorkflowStart(
        event_id="event-r123",
        campaign_id="campaign-r123",
        aggregate_sequence=1,
        attempt_count=1,
        claim_owner="relay-r123",
        claim_expires_at=NOW + timedelta(seconds=30),
        payload={
            "schema_version": "redagent.r123-workflow-start/v1",
            "tenant_id": "tenant-r123",
            "principal_id": "principal-r123",
            "engagement_id": "eng-r123",
            "target_id": "target-r123",
            "campaign_id": "campaign-r123",
            "strategy_revision_id": "strategy-r123",
            "workflow_id": "workflow-r123",
            "workflow_request_sha256": "9" * 64,
            "envelope_sha256": "8" * 64,
        },
    )


def _snapshot() -> CanonicalAuthoritySnapshot:
    target_sha256 = hashlib.sha256(json.dumps({
        "target_id": "target-r123",
        "revision": 1,
        "target_type": "url",
        "normalized_value": "http://127.0.0.1:41731",
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return CanonicalAuthoritySnapshot(
        tenant_id="tenant-r123",
        principal_id="principal-r123",
        engagement_id="eng-r123",
        engagement_version=1,
        roe_version_id="roe-r123",
        roe_revision=1,
        roe_sha256="1" * 64,
        roe_status="approved",
        roe_revocation_epoch=0,
        policy_decision_id="decision-r123",
        policy_revision="policy-r123",
        policy_sha256="2" * 64,
        policy_status="allowed",
        policy_revocation_epoch=0,
        target_id="target-r123",
        target_revision=1,
        target_sha256=target_sha256,
        target_value="http://127.0.0.1:41731",
        target_resolution_mode="owned-loopback",
        credential_class="none",
        credential_reference=None,
        quota_reference="quota-r123",
        quota_available=True,
        runner_id="runner-r123",
        runner_workload_identity="spiffe://redagent.test/runner/r123",
        runner_ready=True,
        reservation_id="reservation-r123",
        lease_id="lease-r123",
        lease_expires_at=NOW + timedelta(minutes=5),
        stop_requested=False,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )
