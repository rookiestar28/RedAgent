from __future__ import annotations

import asyncio
from datetime import timedelta

from sqlalchemy import select

from redagent_platform.campaign_service.admission_start_contracts import (
    AutonomousCampaignAdmissionStartState,
)
from redagent_platform.campaign_service.admission_start_relay import (
    AutonomousCampaignStartBridgeFailure,
    AutonomousCampaignStartBridgeRelay,
)
from redagent_platform.campaign_service.admission_start_relay_store import (
    PostgresAutonomousCampaignStartBridgeRelayRepository,
)
from redagent_platform.campaign_service.application_contracts import (
    AutonomousCampaignLifecycle,
)
from redagent_platform.campaign_service.relay import (
    RelayDeliveryResult,
    WorkflowAlreadyStarted,
    WorkflowQueryReceipt,
    WorkflowStartReceipt,
    WorkflowStartUnknown,
)
from redagent_platform.persistence.models import metadata
from tests.integration.test_autonomous_campaign_admission_start_repository import (
    NOW,
    _prepare_approved_campaign,
)
from tests.integration.test_autonomous_campaign_application_repository import _set_tenant


class _Gateway:
    def __init__(
        self,
        *,
        workflow_run_id: str = "temporal-r173-run",
        duplicate: bool = False,
        query_digest: str | None = None,
        unknown: bool = False,
    ) -> None:
        self.workflow_run_id = workflow_run_id
        self.duplicate = duplicate
        self.query_digest = query_digest
        self.unknown = unknown
        self.starts: list[dict[str, object]] = []

    async def start(self, **values: object) -> WorkflowStartReceipt:
        self.starts.append(values)
        if self.unknown:
            raise WorkflowStartUnknown("synthetic_start_outcome_unknown")
        if self.duplicate:
            raise WorkflowAlreadyStarted("synthetic_duplicate")
        return WorkflowStartReceipt(workflow_run_id=self.workflow_run_id)

    async def query(self, workflow_id: str) -> WorkflowQueryReceipt:
        started = self.starts[-1]
        return WorkflowQueryReceipt(
            workflow_id=workflow_id,
            request_sha256=self.query_digest or str(started["request_sha256"]),
            workflow_run_id=self.workflow_run_id,
        )


def test_r173_relay_claim_and_ack_atomically_queue_without_starting_r159() -> None:
    asyncio.run(_ack_scenario())


def test_r173_relay_distinguishes_unknown_mismatch_retry_and_expiry() -> None:
    asyncio.run(_failure_scenarios())


async def _ack_scenario() -> None:
    prepared = await _prepare_approved_campaign()
    try:
        admitted = await prepared.service.admit_and_queue(prepared.command)
        repository = _repository(prepared)
        claims = await repository.claim_admission_start_bridges(
            claim_owner="r173-relay-test",
            now=NOW + timedelta(seconds=6),
            lease_seconds=20,
            limit=10,
        )
        assert len(claims) == 1
        assert claims[0].campaign_id.startswith("autostart-")
        assert claims[0].campaign_id != admitted.execution_run_id
        outcome = await AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=_Gateway(),
        ).deliver(claims[0], now=NOW + timedelta(seconds=7))
        assert outcome is RelayDeliveryResult.DELIVERED
        await _assert_states(
            prepared,
            application=AutonomousCampaignLifecycle.EXECUTION_QUEUED,
            start=AutonomousCampaignAdmissionStartState.EXECUTION_QUEUED,
            run="start_pending",
            reservation="reserved",
            outbox="delivered",
            workflow_run_id="temporal-r173-run",
        )
    finally:
        await prepared.engine.dispose()


async def _failure_scenarios() -> None:
    unknown = await _prepare_approved_campaign()
    try:
        await unknown.service.admit_and_queue(unknown.command)
        repository = _repository(unknown)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-unknown",
                now=NOW + timedelta(seconds=6),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        outcome = await AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=_Gateway(unknown=True),
        ).deliver(claim, now=NOW + timedelta(seconds=7))
        assert outcome is RelayDeliveryResult.RECONCILIATION_REQUIRED
        await _assert_states(
            unknown,
            application=AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
            start=AutonomousCampaignAdmissionStartState.RECONCILIATION_REQUIRED,
            run="reconciliation_required",
            reservation="reserved",
            outbox="reconciliation_required",
        )
    finally:
        await unknown.engine.dispose()

    mismatch = await _prepare_approved_campaign()
    try:
        await mismatch.service.admit_and_queue(mismatch.command)
        repository = _repository(mismatch)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-mismatch",
                now=NOW + timedelta(seconds=6),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        outcome = await AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=_Gateway(duplicate=True, query_digest="f" * 64),
        ).deliver(claim, now=NOW + timedelta(seconds=7))
        assert outcome is RelayDeliveryResult.MANUAL_REVIEW_REQUIRED
        await _assert_states(
            mismatch,
            application=AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
            start=AutonomousCampaignAdmissionStartState.MANUAL_REVIEW_REQUIRED,
            run="manual_review_required",
            reservation="reserved",
            outbox="reconciliation_required",
        )
    finally:
        await mismatch.engine.dispose()

    transient = await _prepare_approved_campaign()
    try:
        await transient.service.admit_and_queue(transient.command)
        repository = _repository(transient)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-transient",
                now=NOW + timedelta(seconds=6),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        await repository.record_admission_start_bridge_failure(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            failure=AutonomousCampaignStartBridgeFailure.TRANSIENT_BEFORE_IO,
            last_error="known_not_attempted",
            occurred_at=NOW + timedelta(seconds=7),
            max_attempts=5,
        )
        await _assert_states(
            transient,
            application=AutonomousCampaignLifecycle.ADMITTED,
            start=AutonomousCampaignAdmissionStartState.START_PENDING,
            run="start_pending",
            reservation="reserved",
            outbox="pending",
        )
        assert not await repository.claim_admission_start_bridges(
            claim_owner="r173-relay-transient",
            now=NOW + timedelta(seconds=8),
            lease_seconds=20,
            limit=1,
        )
        recovered = await repository.claim_admission_start_bridges(
            claim_owner="r173-relay-transient",
            now=NOW + timedelta(seconds=10),
            lease_seconds=20,
            limit=1,
        )
        assert len(recovered) == 1
        assert recovered[0].attempt_count == 2
    finally:
        await transient.engine.dispose()

    late = await _prepare_approved_campaign()
    try:
        await late.service.admit_and_queue(late.command)
        repository = _repository(late)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-late",
                now=NOW + timedelta(seconds=6),
                lease_seconds=40,
                limit=1,
            )
        )[0]
        gateway = _Gateway()
        outcome = await AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=gateway,
        ).deliver(claim, now=NOW + timedelta(seconds=36))
        assert outcome is RelayDeliveryResult.AUTHORITY_DENIED
        assert gateway.starts == []
        await _assert_states(
            late,
            application=AutonomousCampaignLifecycle.EXPIRED,
            start=AutonomousCampaignAdmissionStartState.FAILED_BEFORE_IO,
            run="failed_before_io",
            reservation="expired",
            outbox="dead_letter",
        )
        replay = await late.service.admit_and_queue(late.command)
        assert replay.replayed is True
        assert replay.application.lifecycle_state is AutonomousCampaignLifecycle.EXPIRED
        assert replay.start_state is AutonomousCampaignAdmissionStartState.FAILED_BEFORE_IO
        assert replay.start_reason_code == "admission_start_expired_before_io"
    finally:
        await late.engine.dispose()

    expired = await _prepare_approved_campaign()
    try:
        await expired.service.admit_and_queue(expired.command)
        repository = _repository(expired)
        assert not await repository.claim_admission_start_bridges(
            claim_owner="r173-relay-expired",
            now=NOW + timedelta(seconds=36),
            lease_seconds=20,
            limit=1,
        )
        await _assert_states(
            expired,
            application=AutonomousCampaignLifecycle.EXPIRED,
            start=AutonomousCampaignAdmissionStartState.FAILED_BEFORE_IO,
            run="failed_before_io",
            reservation="expired",
            outbox="dead_letter",
        )
    finally:
        await expired.engine.dispose()


def _repository(prepared):
    return PostgresAutonomousCampaignStartBridgeRelayRepository(
        prepared.sessions,
        tenant_id=prepared.tenant,
        actor_user_id=prepared.command.actor_user_id,
        correlation_prefix="r173-relay-integration",
    )


async def _assert_states(
    prepared,
    *,
    application: AutonomousCampaignLifecycle,
    start: AutonomousCampaignAdmissionStartState,
    run: str,
    reservation: str,
    outbox: str,
    workflow_run_id: str | None = None,
) -> None:
    current = await prepared.repository.read(
        tenant_id=prepared.tenant,
        campaign_id=prepared.campaign,
    )
    assert current is not None
    assert current.lifecycle_state is application
    async with prepared.sessions() as session, session.begin():
        await _set_tenant(session, prepared.tenant)
        starts = metadata.tables["autonomous_campaign_execution_starts"]
        runs = metadata.tables["campaign_execution_runs"]
        reservations = metadata.tables["campaign_budget_reservations"]
        events = metadata.tables["outbox_events"]
        start_row = (
            await session.execute(select(starts).where(starts.c.tenant_id == prepared.tenant))
        ).mappings().one()
        run_state = await session.scalar(
            select(runs.c.run_state).where(runs.c.tenant_id == prepared.tenant)
        )
        reservation_state = await session.scalar(
            select(reservations.c.reservation_state).where(
                reservations.c.tenant_id == prepared.tenant
            )
        )
        delivery_state = await session.scalar(
            select(events.c.delivery_state).where(
                events.c.tenant_id == prepared.tenant,
                events.c.id == start_row["outbox_event_id"],
            )
        )
        assert start_row["start_state"] == start.value
        assert start_row["workflow_run_id"] == workflow_run_id
        assert run_state == run
        assert reservation_state == reservation
        assert delivery_state == outbox
