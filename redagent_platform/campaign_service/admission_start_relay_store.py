"""Atomic PostgreSQL owner for R173 start-bridge delivery and containment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from sqlalchemy import and_, or_, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.admission_contracts import (
    CampaignReservationState,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.admission_repository import (
    _receipt_from_payload,
)
from redagent_platform.campaign_service.child_admission import transition_repository_for_run
from redagent_platform.campaign_service.admission_start_contracts import (
    ADMISSION_START_BRIDGE_EVENT_TYPE,
    AutonomousCampaignAdmissionStartState,
    ClaimedAutonomousCampaignStartBridgeV1,
    admission_start_bridge_request_sha256,
    deterministic_admission_start_bridge_workflow_id,
)
from redagent_platform.campaign_service.admission_start_relay import (
    AutonomousCampaignStartBridgeFailure,
)
from redagent_platform.campaign_service.admission_start_store import (
    _transition_application,
)
from redagent_platform.campaign_service.application_contracts import (
    is_owned_execution_mode,
    AutonomousCampaignMode,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle,
)
from redagent_platform.campaign_service.application_repository import (
    _state_from_row,
    _verified_receipt_from_payload,
    _verified_preview_from_payload,
)
from redagent_platform.campaign_service.approval_contracts import (
    AutonomousCampaignApprovalReceiptV1,
)
from redagent_platform.campaign_service.relay import (
    OutboxDeliveryState,
    RelayFailure,
    apply_relay_failure,
)
from redagent_platform.orchestration.admission_start_gateway import (
    workflow_input_from_admission_start_payload,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.campaign_service.owned_execution_store import emit_owned_execution_start
from redagent_platform.campaign_service.child_lineage import ChildLineageConflict, ChildLineageVerifier, require_current_child_lineage


_ACK_OPERATION = "autonomous_campaign.start_bridge.acknowledge.v1"
_FAILURE_OPERATION = "autonomous_campaign.start_bridge.failure.v1"


class AdmissionStartBridgeRelayConflict(RuntimeError):
    """The outbox claim no longer owns the exact admitted start material."""


@dataclass(frozen=True, slots=True)
class _BoundStart:
    outbox: RowMapping
    start: RowMapping
    application: AutonomousCampaignApplicationStateV1
    admission_receipt: PlanAdmissionReceiptV1
    approval_receipt: AutonomousCampaignApprovalReceiptV1
    reservation: RowMapping
    execution_run: RowMapping


class CampaignAdmissionStartBridgeRelayRepository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
        child_lineage_verifier: ChildLineageVerifier | None = None,
    ) -> None:
        self.session = session
        self._child_lineage_verifier = child_lineage_verifier
        self.tenant_id = _required("start_bridge_relay_tenant", tenant_id, 64)
        self.actor_user_id = _required("start_bridge_relay_actor", actor_user_id, 64)
        self.correlation_id = _required(
            "start_bridge_relay_correlation", correlation_id, 100
        )

    async def claim_admission_start_bridges(
        self,
        *,
        claim_owner: str,
        now: datetime,
        lease_seconds: int,
        limit: int,
    ) -> list[ClaimedAutonomousCampaignStartBridgeV1]:
        await self._tenant_context()
        owner = _required("start_bridge_relay_claim_owner", claim_owner, 100)
        _aware(now)
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("start_bridge_relay_lease_seconds_invalid")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("start_bridge_relay_claim_limit_invalid")
        outbox = metadata.tables["outbox_events"]
        rows = (
            await self.session.execute(
                select(outbox)
                .where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.event_type == ADMISSION_START_BRIDGE_EVENT_TYPE,
                    outbox.c.aggregate_type == "autonomous_campaign_start",
                    outbox.c.schema_revision == 2,
                    outbox.c.published.is_(False),
                    outbox.c.available_at <= now,
                    or_(
                        outbox.c.delivery_state == "pending",
                        and_(
                            outbox.c.delivery_state == "claimed",
                            outbox.c.claim_expires_at <= now,
                        ),
                        and_(
                            outbox.c.delivery_state == "reconciliation_required",
                            outbox.c.reconciliation_state == "start_outcome_unknown",
                        ),
                    ),
                )
                .order_by(outbox.c.aggregate_sequence, outbox.c.created_at, outbox.c.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        ).mappings().all()
        expires_at = now + timedelta(seconds=lease_seconds)
        claimed: list[ClaimedAutonomousCampaignStartBridgeV1] = []
        for row in rows:
            reconciliation_only = row["delivery_state"] == "reconciliation_required"
            bound = await self._bound_start(
                row,
                now=now,
                expected_reconciliation=reconciliation_only,
            )
            if (
                not reconciliation_only
                and bound.application.lifecycle_state
                is not AutonomousCampaignLifecycle.ADMITTED
            ):
                # CRITICAL: a legitimate terminal transition after admission is not a
                # binding mismatch; close the proven pre-I/O intent and release once.
                await self._fail_before_io(
                    bound,
                    reason_code=(
                        f"admission_start_{bound.application.lifecycle_state.value.lower()}_before_io"
                    ),
                    occurred_at=now,
                    expired=(
                        bound.application.lifecycle_state
                        is AutonomousCampaignLifecycle.EXPIRED
                    ),
                )
                continue
            if (
                not reconciliation_only
                and now
                >= min(
                    bound.start["expires_at"],
                    bound.admission_receipt.expires_at,
                    bound.reservation["lease_expires_at"],
                )
            ):
                await self._fail_before_io(
                    bound,
                    reason_code="admission_start_expired_before_io",
                    occurred_at=now,
                    expired=True,
                )
                continue
            attempt_count = int(row["attempt_count"]) + 1
            if attempt_count > 10:
                if reconciliation_only:
                    await self._record_ambiguous_state(
                        bound,
                        target=AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
                        start_state=AutonomousCampaignAdmissionStartState.MANUAL_REVIEW_REQUIRED,
                        reason_code="start_reconciliation_attempt_budget_exhausted",
                        delivery_state=OutboxDeliveryState.RECONCILIATION_REQUIRED,
                        reconciliation_state="manual_review_required",
                        occurred_at=now,
                    )
                    continue
                await self._fail_before_io(
                    bound,
                    reason_code="admission_start_attempt_budget_exhausted",
                    occurred_at=now,
                    expired=False,
                )
                continue
            changed = (
                await self.session.execute(
                    update(outbox)
                    .where(
                        outbox.c.tenant_id == self.tenant_id,
                        outbox.c.id == row["id"],
                        outbox.c.version == row["version"],
                    )
                    .values(
                        delivery_state="claimed",
                        claim_owner=owner,
                        claim_expires_at=expires_at,
                        attempt_count=attempt_count,
                        version=outbox.c.version + 1,
                        updated_at=now,
                    )
                    .returning(outbox)
                )
            ).mappings().one_or_none()
            if changed is not None:
                claimed.append(
                    ClaimedAutonomousCampaignStartBridgeV1(
                        event_id=str(changed["id"]),
                        start_id=str(changed["aggregate_id"]),
                        aggregate_sequence=int(changed["aggregate_sequence"]),
                        attempt_count=int(changed["attempt_count"]),
                        claim_owner=str(changed["claim_owner"]),
                        claim_expires_at=changed["claim_expires_at"],
                        payload=dict(changed["payload"]),
                        reconciliation_only=reconciliation_only,
                    )
                )
        return claimed

    async def acknowledge_admission_start_bridge(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> None:
        event = _required("start_bridge_relay_event", event_id, 64)
        owner = _required("start_bridge_relay_claim_owner", claim_owner, 100)
        run_id = _required("start_bridge_relay_temporal_run", workflow_run_id, 100)
        _aware(occurred_at)
        if type(duplicate_confirmed) is not bool:
            raise ValueError("start_bridge_relay_duplicate_flag_invalid")
        await self._tenant_context()
        row = await self._claimed_outbox(event, owner, occurred_at)
        bound = await self._bound_start(row, now=occurred_at)
        reconciling = bound.start["start_state"] == "reconciliation_required"
        if bound.application.lifecycle_state not in {
            AutonomousCampaignLifecycle.ADMITTED,
            AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
        }:
            raise AdmissionStartBridgeRelayConflict(
                "start_bridge_relay_ack_lifecycle_conflict"
            )
        if not reconciling and occurred_at >= min(
            bound.start["expires_at"],
            bound.admission_receipt.expires_at,
            bound.reservation["lease_expires_at"],
        ):
            # CRITICAL: a response after authority expiry cannot be attached as a safe queue;
            # the deterministic Workflow may exist, so preserve charge for reconciliation.
            await self._record_ambiguous_state(
                bound,
                target=AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
                start_state=AutonomousCampaignAdmissionStartState.RECONCILIATION_REQUIRED,
                reason_code="start_confirmation_after_expiry",
                delivery_state=OutboxDeliveryState.RECONCILIATION_REQUIRED,
                reconciliation_state="start_outcome_unknown",
                occurred_at=occurred_at,
            )
            return
        starts = metadata.tables["autonomous_campaign_execution_starts"]
        changed = await self.session.execute(
            update(starts)
            .where(
                starts.c.tenant_id == self.tenant_id,
                starts.c.id == bound.start["id"],
                starts.c.version == bound.start["version"],
                starts.c.start_state == bound.start["start_state"],
                starts.c.workflow_run_id.is_(None),
            )
            .values(
                workflow_run_id=run_id,
                start_state="execution_queued",
                reason_code=None,
                version=starts.c.version + 1,
                updated_at=occurred_at,
            )
        )
        if getattr(changed, "rowcount", None) != 1:
            raise AdmissionStartBridgeRelayConflict("start_bridge_relay_link_ack_conflict")
        if reconciling:
            runs = metadata.tables["campaign_execution_runs"]
            changed_run = await self.session.execute(
                update(runs)
                .where(
                    runs.c.tenant_id == self.tenant_id,
                    runs.c.id == bound.execution_run["id"],
                    runs.c.version == bound.execution_run["version"],
                    runs.c.run_state == "reconciliation_required",
                )
                .values(
                    run_state="start_pending",
                    terminal_reason=None,
                    version=runs.c.version + 1,
                    updated_at=occurred_at,
                )
            )
            _require_single_row(changed_run, "start_bridge_relay_run_ack_conflict")
        await self._deliver_outbox(
            bound.outbox,
            occurred_at=occurred_at,
            reconciliation_state=(
                "duplicate_confirmed" if duplicate_confirmed else "none"
            ),
        )
        await _transition_application(
            self.session,
            current=bound.application,
            target=AutonomousCampaignLifecycle.EXECUTION_QUEUED,
            operation=_ACK_OPERATION,
            event_type="autonomous_campaign.execution_queued.v1",
            actor_user_id=self.actor_user_id,
            correlation_id=self.correlation_id,
            request_sha256=str(bound.start["request_sha256"]),
            policy_reference=bound.approval_receipt.policy_reference,
            event_payload={
                "start_id": str(bound.start["id"]),
                "execution_run_id": str(bound.start["execution_run_id"]),
                "workflow_id": str(bound.start["workflow_id"]),
                "workflow_run_id": run_id,
                "duplicate_confirmed": duplicate_confirmed,
            },
            occurred_at=occurred_at,
        )
        if is_owned_execution_mode(bound.application.mode):
            if bound.application.mode is AutonomousCampaignMode.BOUNDED_REPLAN:
                previews = metadata.tables["autonomous_campaign_plan_previews"]
                preview_row = (await self.session.execute(select(previews).where(
                    previews.c.tenant_id == self.tenant_id, previews.c.application_id == bound.application.campaign_id,
                    previews.c.id == bound.approval_receipt.preview_id,
                ))).mappings().one_or_none()
                if preview_row is None:
                    raise AdmissionStartBridgeRelayConflict("child_start_preview_missing")
                preview = _verified_preview_from_payload(preview_row["preview_payload"], str(preview_row["preview_sha256"]))
                if preview.preview_sha256 != bound.approval_receipt.preview_sha256:
                    raise AdmissionStartBridgeRelayConflict("child_start_preview_binding_mismatch")
                try:
                    await require_current_child_lineage(preview=preview, tenant_id=self.tenant_id,
                        campaign_id=bound.application.campaign_id, now=occurred_at,
                        verifier=self._child_lineage_verifier, session=self.session)
                except (ChildLineageConflict, ValueError) as exc:
                    raise AdmissionStartBridgeRelayConflict("child_start_lineage_not_current") from exc
            # CRITICAL: only this confirmed exact approval emits the prepared DAG once.
            # The bridge workflow itself remains effectless for all existing histories.
            await emit_owned_execution_start(self.session, bound.execution_run, now=occurred_at)

    async def confirm_admission_start_bridge_ready(
        self,
        *,
        event_id: str,
        claim_owner: str,
        payload: dict[str, object],
        occurred_at: datetime,
    ) -> bool:
        event = _required("start_bridge_relay_event", event_id, 64)
        owner = _required("start_bridge_relay_claim_owner", claim_owner, 100)
        _aware(occurred_at)
        await self._tenant_context()
        row = await self._claimed_outbox(event, owner, occurred_at)
        if dict(row["payload"]) != payload:
            raise AdmissionStartBridgeRelayConflict(
                "start_bridge_relay_claim_payload_mismatch"
            )
        bound = await self._bound_start(row, now=occurred_at)
        if bound.application.lifecycle_state is not AutonomousCampaignLifecycle.ADMITTED:
            await self._fail_before_io(
                bound,
                reason_code=(
                    f"admission_start_{bound.application.lifecycle_state.value.lower()}_before_io"
                ),
                occurred_at=occurred_at,
                expired=(
                    bound.application.lifecycle_state
                    is AutonomousCampaignLifecycle.EXPIRED
                ),
            )
            return False
        if occurred_at >= min(
            bound.start["expires_at"],
            bound.admission_receipt.expires_at,
            bound.reservation["lease_expires_at"],
        ):
            # CRITICAL: claim validity is rechecked in a fresh transaction immediately
            # before Temporal; otherwise an expired claim could create a late Workflow.
            await self._fail_before_io(
                bound,
                reason_code="admission_start_expired_before_io",
                occurred_at=occurred_at,
                expired=True,
            )
            return False
        return True

    async def record_admission_start_bridge_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: AutonomousCampaignStartBridgeFailure,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> None:
        event = _required("start_bridge_relay_event", event_id, 64)
        owner = _required("start_bridge_relay_claim_owner", claim_owner, 100)
        error = _required("start_bridge_relay_error", last_error, 500)
        _aware(occurred_at)
        if not isinstance(failure, AutonomousCampaignStartBridgeFailure):
            raise ValueError("start_bridge_relay_failure_invalid")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 10:
            raise ValueError("start_bridge_relay_max_attempts_invalid")
        await self._tenant_context()
        row = await self._claimed_outbox(event, owner, None)
        bound = await self._bound_start(row, now=occurred_at)
        reconciling = (
            bound.start["start_state"] == "reconciliation_required"
        )
        if failure is AutonomousCampaignStartBridgeFailure.ABSENT_CONFIRMED:
            if not reconciling:
                raise AdmissionStartBridgeRelayConflict(
                    "start_bridge_relay_absence_without_reconciliation"
                )
            await self._fail_before_io(
                bound,
                reason_code="start_bridge_workflow_absent",
                occurred_at=occurred_at,
                expired=False,
            )
            return
        if failure is AutonomousCampaignStartBridgeFailure.UNKNOWN_START:
            if reconciling:
                if int(row["attempt_count"]) >= max_attempts:
                    await self._record_ambiguous_state(
                        bound,
                        target=AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
                        start_state=AutonomousCampaignAdmissionStartState.MANUAL_REVIEW_REQUIRED,
                        reason_code="start_reconciliation_attempt_budget_exhausted",
                        delivery_state=OutboxDeliveryState.RECONCILIATION_REQUIRED,
                        reconciliation_state="manual_review_required",
                        occurred_at=occurred_at,
                    )
                else:
                    await self._requeue_reconciliation(
                        bound,
                        reason_code=error,
                        occurred_at=occurred_at,
                    )
                return
            await self._record_ambiguous_state(
                bound,
                target=AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
                start_state=AutonomousCampaignAdmissionStartState.RECONCILIATION_REQUIRED,
                reason_code=error,
                delivery_state=OutboxDeliveryState.RECONCILIATION_REQUIRED,
                reconciliation_state="start_outcome_unknown",
                occurred_at=occurred_at,
            )
            return
        if failure is AutonomousCampaignStartBridgeFailure.BINDING_MISMATCH:
            await self._record_ambiguous_state(
                bound,
                target=AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
                start_state=AutonomousCampaignAdmissionStartState.MANUAL_REVIEW_REQUIRED,
                reason_code=error,
                delivery_state=OutboxDeliveryState.RECONCILIATION_REQUIRED,
                reconciliation_state="manual_review_required",
                occurred_at=occurred_at,
            )
            return

        decision = apply_relay_failure(
            attempt_count=int(row["attempt_count"]),
            failure=RelayFailure.TRANSIENT,
            now=occurred_at,
            max_attempts=max_attempts,
        )
        if decision.delivery_state is OutboxDeliveryState.PENDING:
            outbox = metadata.tables["outbox_events"]
            changed = await self.session.execute(
                update(outbox)
                .where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.id == row["id"],
                    outbox.c.version == row["version"],
                )
                .values(
                    delivery_state="pending",
                    reconciliation_state="none",
                    available_at=decision.available_at,
                    claim_owner=None,
                    claim_expires_at=None,
                    last_error=error,
                    version=outbox.c.version + 1,
                    updated_at=occurred_at,
                )
            )
            _require_single_row(changed, "start_bridge_relay_retry_conflict")
            return
        await self._fail_before_io(
            bound,
            reason_code="admission_start_attempt_budget_exhausted",
            occurred_at=occurred_at,
            expired=False,
        )

    async def _requeue_reconciliation(
        self,
        bound: _BoundStart,
        *,
        reason_code: str,
        occurred_at: datetime,
    ) -> None:
        outbox = metadata.tables["outbox_events"]
        delay_seconds = min(300, 2 ** int(bound.outbox["attempt_count"]))
        changed = await self.session.execute(
            update(outbox)
            .where(
                outbox.c.tenant_id == self.tenant_id,
                outbox.c.id == bound.outbox["id"],
                outbox.c.version == bound.outbox["version"],
                outbox.c.delivery_state == "claimed",
            )
            .values(
                delivery_state="reconciliation_required",
                reconciliation_state="start_outcome_unknown",
                available_at=occurred_at + timedelta(seconds=delay_seconds),
                claim_owner=None,
                claim_expires_at=None,
                last_error=reason_code[:100],
                version=outbox.c.version + 1,
                updated_at=occurred_at,
            )
        )
        _require_single_row(changed, "start_bridge_reconciliation_retry_conflict")

    async def _bound_start(
        self,
        row: RowMapping,
        *,
        now: datetime,
        expected_reconciliation: bool | None = None,
    ) -> _BoundStart:
        starts = metadata.tables["autonomous_campaign_execution_starts"]
        applications = metadata.tables["autonomous_campaign_applications"]
        receipts = metadata.tables["plan_admission_receipts"]
        approvals = metadata.tables["autonomous_campaign_plan_approval_receipts"]
        reservations = metadata.tables["campaign_budget_reservations"]
        runs = metadata.tables["campaign_execution_runs"]
        expected_start_states = (
            ("reconciliation_required",)
            if expected_reconciliation is True
            else (
                ("start_pending",)
                if expected_reconciliation is False
                else ("start_pending", "reconciliation_required")
            )
        )
        expected_run_states = (
            ("reconciliation_required",)
            if expected_reconciliation is True
            else (
                ("start_pending",)
                if expected_reconciliation is False
                else ("start_pending", "reconciliation_required")
            )
        )
        start = (
            await self.session.execute(
                select(starts)
                .where(
                    starts.c.tenant_id == self.tenant_id,
                    starts.c.id == row["aggregate_id"],
                    starts.c.outbox_event_id == row["id"],
                    starts.c.outbox_event_type == ADMISSION_START_BRIDGE_EVENT_TYPE,
                    starts.c.start_state.in_(expected_start_states),
                    starts.c.workflow_run_id.is_(None),
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if start is None:
            raise AdmissionStartBridgeRelayConflict("start_bridge_relay_link_binding_mismatch")
        application_row = (
            await self.session.execute(
                select(applications)
                .where(
                    applications.c.tenant_id == self.tenant_id,
                    applications.c.id == start["application_id"],
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        receipt_row = (
            await self.session.execute(
                select(receipts).where(
                    receipts.c.tenant_id == self.tenant_id,
                    receipts.c.id == start["admission_receipt_id"],
                    receipts.c.campaign_id == start["application_id"],
                    receipts.c.receipt_sha256 == start["admission_receipt_sha256"],
                    receipts.c.outcome == "admitted",
                )
            )
        ).mappings().one_or_none()
        approval_row = (
            await self.session.execute(
                select(approvals).where(
                    approvals.c.tenant_id == self.tenant_id,
                    approvals.c.id == start["approval_receipt_id"],
                    approvals.c.application_id == start["application_id"],
                    approvals.c.receipt_sha256 == start["approval_receipt_sha256"],
                )
            )
        ).mappings().one_or_none()
        reservation = (
            await self.session.execute(
                select(reservations)
                .where(
                    reservations.c.tenant_id == self.tenant_id,
                    reservations.c.id == start["reservation_id"],
                    reservations.c.campaign_id == start["application_id"],
                    reservations.c.reservation_state == "reserved",
                    reservations.c.effect_started.is_(False),
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        execution_run = (
            await self.session.execute(
                select(runs)
                .where(
                    runs.c.tenant_id == self.tenant_id,
                    runs.c.id == start["execution_run_id"],
                    runs.c.campaign_id == start["application_id"],
                    runs.c.admission_receipt_id == start["admission_receipt_id"],
                    runs.c.reservation_id == start["reservation_id"],
                    runs.c.input_sha256 == start["input_sha256"],
                    runs.c.run_state.in_(expected_run_states),
                    runs.c.workflow_run_id.is_(None),
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if (
            application_row is None
            or receipt_row is None
            or approval_row is None
            or reservation is None
            or execution_run is None
        ):
            raise AdmissionStartBridgeRelayConflict("start_bridge_relay_durable_binding_mismatch")
        application = _state_from_row(application_row)
        normal_application_states = {
            AutonomousCampaignLifecycle.ADMITTED,
            AutonomousCampaignLifecycle.DENIED,
            AutonomousCampaignLifecycle.EXPIRED,
            AutonomousCampaignLifecycle.REVOKED,
            AutonomousCampaignLifecycle.FAILED_CONTAINED,
        }
        start_is_reconciliation = (
            start["start_state"] == "reconciliation_required"
        )
        if start_is_reconciliation:
            state_pair_valid = (
                application.lifecycle_state
                is AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED
                and execution_run["run_state"] == "reconciliation_required"
                and application.aggregate_revision
                == int(start["admitted_revision"]) + 1
            )
        else:
            expected_application_revision = int(start["admitted_revision"])
            if application.lifecycle_state is not AutonomousCampaignLifecycle.ADMITTED:
                expected_application_revision += 1
            state_pair_valid = (
                application.lifecycle_state in normal_application_states
                and execution_run["run_state"] == "start_pending"
                and application.aggregate_revision == expected_application_revision
            )
        if not state_pair_valid:
            raise AdmissionStartBridgeRelayConflict(
                "start_bridge_relay_lifecycle_binding_mismatch"
            )
        receipt = _receipt_from_payload(receipt_row["receipt_payload"])
        approval = _verified_receipt_from_payload(
            approval_row["receipt_payload"], str(approval_row["receipt_sha256"])
        )
        outbox_payload = _json_object(
            row["payload"], "start_bridge_relay_outbox_payload_invalid"
        )
        start_payload = _json_object(
            start["workflow_input_payload"], "start_bridge_relay_input_payload_invalid"
        )
        request = workflow_input_from_admission_start_payload(outbox_payload)
        if (
            outbox_payload != start_payload
            or request.tenant_id != self.tenant_id
            or request.campaign_id != start["application_id"]
            or request.execution_run_id != start["execution_run_id"]
            or request.input_sha256 != start["input_sha256"]
            or request.approval_receipt_sha256 != start["approval_receipt_sha256"]
            or request.admission_receipt_sha256 != start["admission_receipt_sha256"]
            or start["workflow_id"]
            != deterministic_admission_start_bridge_workflow_id(
                request.tenant_id, request.execution_run_id
            )
            or start["workflow_request_sha256"]
            != admission_start_bridge_request_sha256(request)
            or receipt.reservation_id != start["reservation_id"]
            or receipt.receipt_sha256 != start["admission_receipt_sha256"]
            or execution_run["admission_receipt_sha256"]
            != start["admission_receipt_sha256"]
            or execution_run["plan_sha256"] != start["plan_sha256"]
            or execution_run["authority_sha256"] != start["authority_sha256"]
            or execution_run["domain_sha256"] != start["domain_sha256"]
            or execution_run["certificate_sha256"] != start["certificate_sha256"]
            or execution_run["reserved_budget_sha256"]
            != start["reserved_budget_sha256"]
        ):
            raise AdmissionStartBridgeRelayConflict("start_bridge_relay_material_mismatch")
        return _BoundStart(
            outbox=row,
            start=start,
            application=application,
            admission_receipt=receipt,
            approval_receipt=approval,
            reservation=reservation,
            execution_run=execution_run,
        )

    async def _claimed_outbox(
        self,
        event_id: str,
        owner: str,
        occurred_at: datetime | None,
    ) -> RowMapping:
        outbox = metadata.tables["outbox_events"]
        conditions = [
            outbox.c.tenant_id == self.tenant_id,
            outbox.c.id == event_id,
            outbox.c.event_type == ADMISSION_START_BRIDGE_EVENT_TYPE,
            outbox.c.aggregate_type == "autonomous_campaign_start",
            outbox.c.delivery_state == "claimed",
            outbox.c.claim_owner == owner,
        ]
        if occurred_at is not None:
            conditions.append(outbox.c.claim_expires_at > occurred_at)
        row = (
            await self.session.execute(
                select(outbox).where(*conditions).with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            raise AdmissionStartBridgeRelayConflict("start_bridge_relay_claim_conflict")
        return row

    async def _record_ambiguous_state(
        self,
        bound: _BoundStart,
        *,
        target: AutonomousCampaignLifecycle,
        start_state: AutonomousCampaignAdmissionStartState,
        reason_code: str,
        delivery_state: OutboxDeliveryState,
        reconciliation_state: str,
        occurred_at: datetime,
    ) -> None:
        bounded_reason = reason_code[:100]
        starts = metadata.tables["autonomous_campaign_execution_starts"]
        runs = metadata.tables["campaign_execution_runs"]
        run_state = (
            "reconciliation_required"
            if target is AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED
            else "manual_review_required"
        )
        changed_start = await self.session.execute(
            update(starts)
            .where(
                starts.c.tenant_id == self.tenant_id,
                starts.c.id == bound.start["id"],
                starts.c.version == bound.start["version"],
            )
            .values(
                start_state=start_state.value,
                reason_code=bounded_reason,
                version=starts.c.version + 1,
                updated_at=occurred_at,
            )
        )
        _require_single_row(changed_start, "start_bridge_relay_link_failure_conflict")
        changed_run = await self.session.execute(
            update(runs)
            .where(
                runs.c.tenant_id == self.tenant_id,
                runs.c.id == bound.execution_run["id"],
                runs.c.version == bound.execution_run["version"],
                runs.c.run_state == bound.execution_run["run_state"],
            )
            .values(
                run_state=run_state,
                terminal_reason=bounded_reason,
                version=runs.c.version + 1,
                updated_at=occurred_at,
            )
        )
        _require_single_row(changed_run, "start_bridge_relay_run_failure_conflict")
        await self._close_outbox(
            bound.outbox,
            delivery_state=delivery_state.value,
            reconciliation_state=reconciliation_state,
            last_error=bounded_reason,
            dead_lettered_at=None,
            occurred_at=occurred_at,
        )
        await _transition_application(
            self.session,
            current=bound.application,
            target=target,
            operation=_FAILURE_OPERATION,
            event_type=f"autonomous_campaign.{start_state.value}.v1",
            actor_user_id=self.actor_user_id,
            correlation_id=self.correlation_id,
            request_sha256=str(bound.start["request_sha256"]),
            policy_reference=bound.approval_receipt.policy_reference,
            event_payload={
                "start_id": str(bound.start["id"]),
                "execution_run_id": str(bound.start["execution_run_id"]),
                "reason_code": bounded_reason,
            },
            occurred_at=occurred_at,
            attention_reason=bounded_reason,
        )

    async def _fail_before_io(
        self,
        bound: _BoundStart,
        *,
        reason_code: str,
        occurred_at: datetime,
        expired: bool,
    ) -> None:
        target_reservation = (
            CampaignReservationState.EXPIRED
            if expired
            else CampaignReservationState.RELEASED
        )
        budget_owner = await transition_repository_for_run(
            self.session,
            run=bound.execution_run,
            actor_user_id=self.actor_user_id,
            correlation_id=self.correlation_id,
            now=occurred_at,
        )
        await budget_owner.transition_reservation(
            reservation_id=str(bound.start["reservation_id"]),
            target=target_reservation,
            effect_started=False,
            reconciliation_code=(
                None
                if target_reservation is CampaignReservationState.EXPIRED
                else "not_started"
            ),
            now=occurred_at,
        )
        starts = metadata.tables["autonomous_campaign_execution_starts"]
        runs = metadata.tables["campaign_execution_runs"]
        nodes = metadata.tables["campaign_execution_nodes"]
        changed_start = await self.session.execute(
            update(starts)
            .where(
                starts.c.tenant_id == self.tenant_id,
                starts.c.id == bound.start["id"],
                starts.c.version == bound.start["version"],
                starts.c.start_state == bound.start["start_state"],
            )
            .values(
                start_state="failed_before_io",
                reason_code=reason_code,
                version=starts.c.version + 1,
                updated_at=occurred_at,
            )
        )
        _require_single_row(changed_start, "start_bridge_relay_link_failure_conflict")
        changed_run = await self.session.execute(
            update(runs)
            .where(
                runs.c.tenant_id == self.tenant_id,
                runs.c.id == bound.execution_run["id"],
                runs.c.version == bound.execution_run["version"],
                runs.c.run_state == bound.execution_run["run_state"],
            )
            .values(
                run_state="failed_before_io",
                terminal_reason=reason_code,
                completed_at=occurred_at,
                version=runs.c.version + 1,
                updated_at=occurred_at,
            )
        )
        _require_single_row(changed_run, "start_bridge_relay_run_failure_conflict")
        changed_nodes = await self.session.execute(
            update(nodes)
            .where(
                nodes.c.tenant_id == self.tenant_id,
                nodes.c.execution_run_id == bound.execution_run["id"],
                nodes.c.node_state == "pending",
            )
            .values(
                node_state="failed",
                version=nodes.c.version + 1,
                updated_at=occurred_at,
            )
        )
        _require_at_least_one_row(
            changed_nodes,
            "start_bridge_relay_nodes_failure_conflict",
        )
        await self._close_outbox(
            bound.outbox,
            delivery_state="dead_letter",
            reconciliation_state="none",
            last_error=reason_code,
            dead_lettered_at=occurred_at,
            occurred_at=occurred_at,
        )
        if bound.application.lifecycle_state in {
            AutonomousCampaignLifecycle.ADMITTED,
            AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
        }:
            target = (
                AutonomousCampaignLifecycle.EXPIRED
                if expired
                else AutonomousCampaignLifecycle.FAILED_CONTAINED
            )
            await _transition_application(
                self.session,
                current=bound.application,
                target=target,
                operation=_FAILURE_OPERATION,
                event_type="autonomous_campaign.failed_before_io.v1",
                actor_user_id=self.actor_user_id,
                correlation_id=self.correlation_id,
                request_sha256=str(bound.start["request_sha256"]),
                policy_reference=bound.approval_receipt.policy_reference,
                event_payload={
                    "start_id": str(bound.start["id"]),
                    "execution_run_id": str(bound.start["execution_run_id"]),
                    "reason_code": reason_code,
                    "reservation_state": target_reservation.value,
                },
                occurred_at=occurred_at,
            )

    async def _deliver_outbox(
        self,
        row: RowMapping,
        *,
        occurred_at: datetime,
        reconciliation_state: str,
    ) -> None:
        await self._close_outbox(
            row,
            delivery_state="delivered",
            reconciliation_state=reconciliation_state,
            last_error=None,
            dead_lettered_at=None,
            occurred_at=occurred_at,
            published=True,
        )

    async def _close_outbox(
        self,
        row: RowMapping,
        *,
        delivery_state: str,
        reconciliation_state: str,
        last_error: str | None,
        dead_lettered_at: datetime | None,
        occurred_at: datetime,
        published: bool = False,
    ) -> None:
        outbox = metadata.tables["outbox_events"]
        changed = await self.session.execute(
            update(outbox)
            .where(
                outbox.c.tenant_id == self.tenant_id,
                outbox.c.id == row["id"],
                outbox.c.version == row["version"],
            )
            .values(
                published=published,
                delivery_state=delivery_state,
                delivered_at=occurred_at if published else None,
                reconciliation_state=reconciliation_state,
                claim_owner=None,
                claim_expires_at=None,
                last_error=last_error,
                dead_lettered_at=dead_lettered_at,
                version=metadata.tables["outbox_events"].c.version + 1,
                updated_at=occurred_at,
            )
        )
        if getattr(changed, "rowcount", None) != 1:
            raise AdmissionStartBridgeRelayConflict("start_bridge_relay_outbox_conflict")

    async def _tenant_context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )


class PostgresAutonomousCampaignStartBridgeRelayRepository:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_prefix: str,
        child_lineage_verifier: ChildLineageVerifier | None = None,
    ) -> None:
        self._sessions = sessions
        self._child_lineage_verifier = child_lineage_verifier
        self._tenant_id = _required("start_bridge_relay_tenant", tenant_id, 64)
        self._actor_user_id = _required("start_bridge_relay_actor", actor_user_id, 64)
        self._correlation_prefix = _required(
            "start_bridge_relay_correlation", correlation_prefix, 80
        )

    async def claim_admission_start_bridges(
        self,
        *,
        claim_owner: str,
        now: datetime,
        lease_seconds: int,
        limit: int,
    ) -> list[ClaimedAutonomousCampaignStartBridgeV1]:
        async with self._sessions() as session, session.begin():
            return await self._repository(session, "claim").claim_admission_start_bridges(
                claim_owner=claim_owner,
                now=now,
                lease_seconds=lease_seconds,
                limit=limit,
            )

    async def confirm_admission_start_bridge_ready(
        self,
        *,
        event_id: str,
        claim_owner: str,
        payload: dict[str, object],
        occurred_at: datetime,
    ) -> bool:
        async with self._sessions() as session, session.begin():
            return await self._repository(
                session,
                "preflight",
            ).confirm_admission_start_bridge_ready(
                event_id=event_id,
                claim_owner=claim_owner,
                payload=payload,
                occurred_at=occurred_at,
            )

    async def acknowledge_admission_start_bridge(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> None:
        async with self._sessions() as session, session.begin():
            await self._repository(session, "ack").acknowledge_admission_start_bridge(
                event_id=event_id,
                claim_owner=claim_owner,
                workflow_run_id=workflow_run_id,
                occurred_at=occurred_at,
                duplicate_confirmed=duplicate_confirmed,
            )

    async def record_admission_start_bridge_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: AutonomousCampaignStartBridgeFailure,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> None:
        async with self._sessions() as session, session.begin():
            await self._repository(session, "failure").record_admission_start_bridge_failure(
                event_id=event_id,
                claim_owner=claim_owner,
                failure=failure,
                last_error=last_error,
                occurred_at=occurred_at,
                max_attempts=max_attempts,
            )

    def _repository(
        self, session: AsyncSession, phase: str
    ) -> CampaignAdmissionStartBridgeRelayRepository:
        return CampaignAdmissionStartBridgeRelayRepository(
            session,
            tenant_id=self._tenant_id,
            actor_user_id=self._actor_user_id,
            correlation_id=f"{self._correlation_prefix}-{phase}",
            child_lineage_verifier=self._child_lineage_verifier,
        )


def _required(name: str, value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name}_invalid")
    return value


def _json_object(value: object, reason: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise AdmissionStartBridgeRelayConflict(reason)
    return value


def _aware(value: datetime) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("start_bridge_relay_now_timezone_required")


def _require_single_row(result: object, reason: str) -> None:
    if getattr(result, "rowcount", None) != 1:
        raise AdmissionStartBridgeRelayConflict(reason)


def _require_at_least_one_row(result: object, reason: str) -> None:
    rowcount = getattr(result, "rowcount", None)
    if not isinstance(rowcount, int) or rowcount < 1:
        raise AdmissionStartBridgeRelayConflict(reason)
