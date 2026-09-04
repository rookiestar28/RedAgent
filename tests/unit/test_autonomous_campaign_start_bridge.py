from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from redagent_platform.campaign_service.admission_start_contracts import (
    ADMISSION_START_BRIDGE_SCHEMA_VERSION,
    AutonomousCampaignStartBridgeSnapshotV1,
    AutonomousCampaignStartBridgeState,
    AutonomousCampaignStartBridgeWorkflowInputV1,
    admission_start_bridge_request_sha256,
    deterministic_admission_start_bridge_workflow_id,
)
from redagent_platform.campaign_service.admission_start_relay import (
    AutonomousCampaignStartBridgeFailure,
    AutonomousCampaignStartBridgeRelay,
)
from redagent_platform.campaign_service.relay import (
    RelayDeliveryResult,
    WorkflowAlreadyStarted,
    WorkflowQueryReceipt,
    WorkflowStartReceipt,
    WorkflowStartUnknown,
    WorkflowStartUnavailable,
)
from redagent_platform.campaign_service.repository import ClaimedWorkflowStart
from redagent_platform.orchestration.admission_start_gateway import (
    AutonomousCampaignStartBridgeTemporalGateway,
    workflow_input_from_admission_start_payload,
)
from redagent_platform.orchestration.worker import worker_registration


NOW = datetime(2026, 9, 5, 2, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _request() -> AutonomousCampaignStartBridgeWorkflowInputV1:
    return AutonomousCampaignStartBridgeWorkflowInputV1(
        schema_version=ADMISSION_START_BRIDGE_SCHEMA_VERSION,
        tenant_id="tenant-1",
        campaign_id="campaign-1",
        execution_run_id="dag-run-1",
        input_sha256=SHA_A,
        approval_receipt_sha256=SHA_B,
        admission_receipt_sha256=SHA_C,
    )


def _claim(request: AutonomousCampaignStartBridgeWorkflowInputV1 | None = None) -> ClaimedWorkflowStart:
    selected = request or _request()
    return ClaimedWorkflowStart(
        event_id="outbox-r173-1",
        campaign_id=selected.execution_run_id,
        aggregate_sequence=1,
        attempt_count=1,
        claim_owner="r173-relay-1",
        claim_expires_at=NOW + timedelta(seconds=30),
        payload=asdict(selected),
    )


def test_start_bridge_contract_is_deterministic_and_closed() -> None:
    request = _request()
    workflow_id = deterministic_admission_start_bridge_workflow_id(
        request.tenant_id, request.execution_run_id
    )
    assert workflow_id == deterministic_admission_start_bridge_workflow_id(
        request.tenant_id, request.execution_run_id
    )
    assert workflow_id.startswith("redagent-autonomous-start-")
    assert len(admission_start_bridge_request_sha256(request)) == 64
    assert workflow_input_from_admission_start_payload(asdict(request)) == request

    with pytest.raises(ValueError, match="start_bridge_payload_fields_invalid"):
        workflow_input_from_admission_start_payload({**asdict(request), "workflow_id": "client-owned"})


def test_start_bridge_snapshot_cannot_claim_running() -> None:
    request = _request()
    snapshot = AutonomousCampaignStartBridgeSnapshotV1(
        schema_version=ADMISSION_START_BRIDGE_SCHEMA_VERSION,
        execution_run_id=request.execution_run_id,
        workflow_request_sha256=admission_start_bridge_request_sha256(request),
        state=AutonomousCampaignStartBridgeState.EXECUTION_QUEUED,
        revision=1,
    )
    assert snapshot.state is AutonomousCampaignStartBridgeState.EXECUTION_QUEUED
    assert "RUNNING" not in {state.name for state in AutonomousCampaignStartBridgeState}


class _Repository:
    def __init__(self, *, ready: bool = True) -> None:
        self.ready = ready
        self.preflights: list[dict[str, object]] = []
        self.acknowledged: list[dict[str, object]] = []
        self.failures: list[dict[str, object]] = []

    async def confirm_admission_start_bridge_ready(self, **values: object) -> bool:
        self.preflights.append(values)
        return self.ready

    async def acknowledge_admission_start_bridge(self, **values: object) -> None:
        self.acknowledged.append(values)

    async def record_admission_start_bridge_failure(self, **values: object) -> None:
        self.failures.append(values)


class _Gateway:
    def __init__(
        self,
        *,
        duplicate: bool = False,
        query_request_sha256: str | None = None,
        start_failure: Exception | None = None,
        query_failure: Exception | None = None,
    ) -> None:
        self.duplicate = duplicate
        self.query_request_sha256 = query_request_sha256
        self.start_failure = start_failure
        self.query_failure = query_failure
        self.starts: list[dict[str, object]] = []

    async def start(self, **values: object) -> WorkflowStartReceipt:
        self.starts.append(values)
        if self.start_failure is not None:
            raise self.start_failure
        if self.duplicate:
            raise WorkflowAlreadyStarted("already_started")
        return WorkflowStartReceipt(workflow_run_id="temporal-run-1")

    async def query(self, workflow_id: str) -> WorkflowQueryReceipt:
        if self.query_failure is not None:
            raise self.query_failure
        request_sha256 = self.query_request_sha256 or admission_start_bridge_request_sha256(_request())
        return WorkflowQueryReceipt(
            workflow_id=workflow_id,
            request_sha256=request_sha256,
            workflow_run_id="temporal-run-existing",
        )


def test_start_bridge_relay_delivers_exact_committed_claim() -> None:
    repository = _Repository()
    gateway = _Gateway()
    relay = AutonomousCampaignStartBridgeRelay(repository=repository, gateway=gateway)

    outcome = asyncio.run(relay.deliver(_claim(), now=NOW))

    assert outcome is RelayDeliveryResult.DELIVERED
    assert len(gateway.starts) == 1
    assert repository.acknowledged[0]["workflow_run_id"] == "temporal-run-1"
    assert repository.acknowledged[0]["duplicate_confirmed"] is False
    assert repository.failures == []
    assert repository.preflights[0]["payload"] == _claim().payload


def test_start_bridge_relay_rechecks_claim_before_temporal() -> None:
    repository = _Repository(ready=False)
    gateway = _Gateway()

    outcome = asyncio.run(
        AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=gateway,
        ).deliver(_claim(), now=NOW)
    )

    assert outcome is RelayDeliveryResult.AUTHORITY_DENIED
    assert len(repository.preflights) == 1
    assert gateway.starts == []
    assert repository.acknowledged == []


def test_start_bridge_relay_reconciles_matching_duplicate_without_restart() -> None:
    repository = _Repository()
    gateway = _Gateway(duplicate=True)
    relay = AutonomousCampaignStartBridgeRelay(repository=repository, gateway=gateway)

    outcome = asyncio.run(relay.deliver(_claim(), now=NOW))

    assert outcome is RelayDeliveryResult.DUPLICATE_CONFIRMED
    assert len(gateway.starts) == 1
    assert repository.acknowledged[0]["workflow_run_id"] == "temporal-run-existing"
    assert repository.acknowledged[0]["duplicate_confirmed"] is True


def test_start_bridge_relay_contains_mismatched_duplicate() -> None:
    repository = _Repository()
    gateway = _Gateway(duplicate=True, query_request_sha256="d" * 64)
    relay = AutonomousCampaignStartBridgeRelay(repository=repository, gateway=gateway)

    outcome = asyncio.run(relay.deliver(_claim(), now=NOW))

    assert outcome is RelayDeliveryResult.MANUAL_REVIEW_REQUIRED
    assert repository.acknowledged == []
    assert (
        repository.failures[0]["failure"]
        is AutonomousCampaignStartBridgeFailure.BINDING_MISMATCH
    )
    assert repository.failures[0]["last_error"] == "duplicate_binding_mismatch"


def test_start_bridge_relay_separates_safe_retry_from_unknown_start() -> None:
    transient_repository = _Repository()
    transient = asyncio.run(
        AutonomousCampaignStartBridgeRelay(
            repository=transient_repository,
            gateway=_Gateway(
                start_failure=WorkflowStartUnavailable("known_not_attempted")
            ),
        ).deliver(_claim(), now=NOW)
    )
    assert transient is RelayDeliveryResult.RETRY_SCHEDULED
    assert (
        transient_repository.failures[0]["failure"]
        is AutonomousCampaignStartBridgeFailure.TRANSIENT_BEFORE_IO
    )

    unknown_repository = _Repository()
    unknown = asyncio.run(
        AutonomousCampaignStartBridgeRelay(
            repository=unknown_repository,
            gateway=_Gateway(start_failure=WorkflowStartUnknown("start_outcome_unknown")),
        ).deliver(_claim(), now=NOW)
    )
    assert unknown is RelayDeliveryResult.RECONCILIATION_REQUIRED
    assert (
        unknown_repository.failures[0]["failure"]
        is AutonomousCampaignStartBridgeFailure.UNKNOWN_START
    )


def test_start_bridge_unqueryable_duplicate_is_unknown_not_a_blind_retry() -> None:
    repository = _Repository()
    outcome = asyncio.run(
        AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=_Gateway(
                duplicate=True,
                query_failure=WorkflowStartUnavailable("query_unavailable"),
            ),
        ).deliver(_claim(), now=NOW)
    )
    assert outcome is RelayDeliveryResult.RECONCILIATION_REQUIRED
    assert (
        repository.failures[0]["failure"]
        is AutonomousCampaignStartBridgeFailure.UNKNOWN_START
    )


def test_temporal_handle_without_run_id_is_unknown_not_a_before_io_retry() -> None:
    class Client:
        async def start_workflow(self, *args, **kwargs):
            return object()

    gateway = AutonomousCampaignStartBridgeTemporalGateway(
        Client(),
        task_queue="redagent-r173-test",
    )
    request = _request()
    with pytest.raises(
        WorkflowStartUnknown,
        match="start_bridge_temporal_run_id_missing",
    ):
        asyncio.run(
            gateway.start(
                workflow_id=deterministic_admission_start_bridge_workflow_id(
                    request.tenant_id,
                    request.execution_run_id,
                ),
                request_sha256=admission_start_bridge_request_sha256(request),
                payload=asdict(request),
            )
        )


def test_start_bridge_worker_registration_has_no_activity() -> None:
    registration = worker_registration(start_bridge_enabled=True)
    assert "redagent.autonomous-campaign-start-bridge.v1" in registration.workflow_names
    assert not any("start-bridge" in name for name in registration.activity_names)


def test_r173_bridge_source_has_no_effect_or_r159_workflow_path() -> None:
    paths = (
        ROOT / "redagent_platform" / "campaign_service" / "admission_start_relay.py",
        ROOT / "redagent_platform" / "orchestration" / "admission_start_gateway.py",
        ROOT / "redagent_platform" / "orchestration" / "admission_start_workflow.py",
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for forbidden in (
        "campaign.dag.start.requested.v1",
        "CampaignDagExecutionWorkflow",
        "execute_activity",
        "start_activity",
        "runner_service",
        "zap_service",
        "nuclei_service",
    ):
        assert forbidden not in source
