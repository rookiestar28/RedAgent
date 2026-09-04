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
    APPLICATION_CONTRACT_VERSION,
    AutonomousCampaignLifecycle,
    RevokeAutonomousCampaignIntentV1,
)
from redagent_platform.campaign_service.relay import (
    RelayDeliveryResult,
    WorkflowAlreadyStarted,
    WorkflowNotFound,
    WorkflowQueryReceipt,
    WorkflowStartReceipt,
    WorkflowStartUnknown,
    WorkflowStartUnavailable,
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
        query_failure: Exception | None = None,
    ) -> None:
        self.workflow_run_id = workflow_run_id
        self.duplicate = duplicate
        self.query_digest = query_digest
        self.unknown = unknown
        self.query_failure = query_failure
        self.starts: list[dict[str, object]] = []
        self.queries: list[str] = []

    async def start(self, **values: object) -> WorkflowStartReceipt:
        self.starts.append(values)
        if self.unknown:
            raise WorkflowStartUnknown("synthetic_start_outcome_unknown")
        if self.duplicate:
            raise WorkflowAlreadyStarted("synthetic_duplicate")
        return WorkflowStartReceipt(workflow_run_id=self.workflow_run_id)

    async def query(self, workflow_id: str) -> WorkflowQueryReceipt:
        self.queries.append(workflow_id)
        if self.query_failure is not None:
            raise self.query_failure
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


def test_r173_relay_closes_post_admission_revocation_before_temporal() -> None:
    asyncio.run(_revocation_scenarios())


def test_r173_unknown_start_reconciliation_converges_without_restart() -> None:
    asyncio.run(_reconciliation_scenarios())


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
        assert claims[0].start_id.startswith("autostart-")
        assert claims[0].start_id != admitted.execution_run_id
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


async def _revocation_scenarios() -> None:
    before_claim = await _prepare_approved_campaign()
    try:
        admitted = await before_claim.service.admit_and_queue(before_claim.command)
        await _revoke(
            before_claim,
            expected_revision=admitted.application.aggregate_revision,
            occurred_at=NOW + timedelta(seconds=6),
            suffix="before-claim",
        )
        repository = _repository(before_claim)
        assert not await repository.claim_admission_start_bridges(
            claim_owner="r173-relay-revoked-before-claim",
            now=NOW + timedelta(seconds=7),
            lease_seconds=20,
            limit=1,
        )
        await _assert_states(
            before_claim,
            application=AutonomousCampaignLifecycle.REVOKED,
            start=AutonomousCampaignAdmissionStartState.FAILED_BEFORE_IO,
            run="failed_before_io",
            reservation="released",
            outbox="dead_letter",
        )
    finally:
        await before_claim.engine.dispose()

    after_claim = await _prepare_approved_campaign()
    try:
        admitted = await after_claim.service.admit_and_queue(after_claim.command)
        repository = _repository(after_claim)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-revoked-after-claim",
                now=NOW + timedelta(seconds=6),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        await _revoke(
            after_claim,
            expected_revision=admitted.application.aggregate_revision,
            occurred_at=NOW + timedelta(seconds=7),
            suffix="after-claim",
        )
        gateway = _Gateway()
        outcome = await AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=gateway,
        ).deliver(claim, now=NOW + timedelta(seconds=8))
        assert outcome is RelayDeliveryResult.AUTHORITY_DENIED
        assert gateway.starts == []
        assert gateway.queries == []
        await _assert_states(
            after_claim,
            application=AutonomousCampaignLifecycle.REVOKED,
            start=AutonomousCampaignAdmissionStartState.FAILED_BEFORE_IO,
            run="failed_before_io",
            reservation="released",
            outbox="dead_letter",
        )
    finally:
        await after_claim.engine.dispose()


async def _reconciliation_scenarios() -> None:
    matching = await _prepare_approved_campaign()
    try:
        await matching.service.admit_and_queue(matching.command)
        repository = _repository(matching)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-matching",
                now=NOW + timedelta(seconds=6),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        gateway = _Gateway(unknown=True)
        assert (
            await AutonomousCampaignStartBridgeRelay(
                repository=repository,
                gateway=gateway,
            ).deliver(claim, now=NOW + timedelta(seconds=7))
            is RelayDeliveryResult.RECONCILIATION_REQUIRED
        )
        gateway.unknown = False
        repository = _repository(matching)
        reconcile_claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-matching",
                now=NOW + timedelta(seconds=8),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        assert reconcile_claim.reconciliation_only is True
        assert (
            await AutonomousCampaignStartBridgeRelay(
                repository=repository,
                gateway=gateway,
            ).deliver(reconcile_claim, now=NOW + timedelta(seconds=9))
            is RelayDeliveryResult.DUPLICATE_CONFIRMED
        )
        assert len(gateway.starts) == 1
        assert len(gateway.queries) == 1
        await _assert_states(
            matching,
            application=AutonomousCampaignLifecycle.EXECUTION_QUEUED,
            start=AutonomousCampaignAdmissionStartState.EXECUTION_QUEUED,
            run="start_pending",
            reservation="reserved",
            outbox="delivered",
            workflow_run_id="temporal-r173-run",
        )
    finally:
        await matching.engine.dispose()

    absent = await _prepare_approved_campaign()
    try:
        await absent.service.admit_and_queue(absent.command)
        repository = _repository(absent)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-absent",
                now=NOW + timedelta(seconds=6),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        gateway = _Gateway(unknown=True)
        await AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=gateway,
        ).deliver(claim, now=NOW + timedelta(seconds=7))
        gateway.unknown = False
        gateway.query_failure = WorkflowNotFound("workflow_not_found")
        reconcile_claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-absent",
                now=NOW + timedelta(seconds=8),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        assert (
            await AutonomousCampaignStartBridgeRelay(
                repository=repository,
                gateway=gateway,
            ).deliver(reconcile_claim, now=NOW + timedelta(seconds=9))
            is RelayDeliveryResult.ABSENCE_CONFIRMED
        )
        assert len(gateway.starts) == 1
        await _assert_states(
            absent,
            application=AutonomousCampaignLifecycle.FAILED_CONTAINED,
            start=AutonomousCampaignAdmissionStartState.FAILED_BEFORE_IO,
            run="failed_before_io",
            reservation="released",
            outbox="dead_letter",
        )
    finally:
        await absent.engine.dispose()

    unavailable = await _prepare_approved_campaign()
    try:
        await unavailable.service.admit_and_queue(unavailable.command)
        repository = _repository(unavailable)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-unavailable",
                now=NOW + timedelta(seconds=6),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        gateway = _Gateway(unknown=True)
        await AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=gateway,
        ).deliver(claim, now=NOW + timedelta(seconds=7))
        gateway.unknown = False
        gateway.query_failure = WorkflowStartUnavailable("query_unavailable")
        reconcile_claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-unavailable",
                now=NOW + timedelta(seconds=8),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        assert (
            await AutonomousCampaignStartBridgeRelay(
                repository=repository,
                gateway=gateway,
            ).deliver(reconcile_claim, now=NOW + timedelta(seconds=9))
            is RelayDeliveryResult.RECONCILIATION_REQUIRED
        )
        assert len(gateway.starts) == 1
        later = await repository.claim_admission_start_bridges(
            claim_owner="r173-relay-reconcile-unavailable",
            now=NOW + timedelta(seconds=14),
            lease_seconds=20,
            limit=1,
        )
        assert len(later) == 1
        assert later[0].reconciliation_only is True
        relay = AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=gateway,
        )
        assert (
            await relay.deliver(later[0], now=NOW + timedelta(seconds=15))
            is RelayDeliveryResult.RECONCILIATION_REQUIRED
        )
        fourth = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-unavailable",
                now=NOW + timedelta(seconds=24),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        assert (
            await relay.deliver(fourth, now=NOW + timedelta(seconds=25))
            is RelayDeliveryResult.RECONCILIATION_REQUIRED
        )
        fifth = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-unavailable",
                now=NOW + timedelta(seconds=42),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        assert (
            await relay.deliver(fifth, now=NOW + timedelta(seconds=43))
            is RelayDeliveryResult.RECONCILIATION_REQUIRED
        )
        assert len(gateway.starts) == 1
        assert len(gateway.queries) == 4
        await _assert_states(
            unavailable,
            application=AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
            start=AutonomousCampaignAdmissionStartState.MANUAL_REVIEW_REQUIRED,
            run="manual_review_required",
            reservation="reserved",
            outbox="reconciliation_required",
        )
    finally:
        await unavailable.engine.dispose()

    mismatch = await _prepare_approved_campaign()
    try:
        await mismatch.service.admit_and_queue(mismatch.command)
        repository = _repository(mismatch)
        claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-mismatch",
                now=NOW + timedelta(seconds=6),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        gateway = _Gateway(unknown=True)
        await AutonomousCampaignStartBridgeRelay(
            repository=repository,
            gateway=gateway,
        ).deliver(claim, now=NOW + timedelta(seconds=7))
        gateway.unknown = False
        gateway.query_digest = "f" * 64
        reconcile_claim = (
            await repository.claim_admission_start_bridges(
                claim_owner="r173-relay-reconcile-mismatch",
                now=NOW + timedelta(seconds=8),
                lease_seconds=20,
                limit=1,
            )
        )[0]
        assert (
            await AutonomousCampaignStartBridgeRelay(
                repository=repository,
                gateway=gateway,
            ).deliver(reconcile_claim, now=NOW + timedelta(seconds=9))
            is RelayDeliveryResult.MANUAL_REVIEW_REQUIRED
        )
        assert len(gateway.starts) == 1
        assert len(gateway.queries) == 1
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


async def _revoke(
    prepared,
    *,
    expected_revision: int,
    occurred_at,
    suffix: str,
) -> None:
    await prepared.repository.revoke_intent(
        RevokeAutonomousCampaignIntentV1(
            schema_version=APPLICATION_CONTRACT_VERSION,
            tenant_id=prepared.tenant,
            campaign_id=prepared.campaign,
            actor_user_id=prepared.command.actor_user_id,
            reason_sha256="d" * 64,
            expected_revision=expected_revision,
            idempotency_key=f"revoke-{suffix}",
            correlation_id=f"revoke-{suffix}",
            occurred_at=occurred_at,
        )
    )


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
