"""Transaction owner for tenant-partitioned DAG workflow-start outbox delivery."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import and_, insert, or_, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode

from redagent_platform.campaign_service.dag_execution_contracts import (
    dag_workflow_request_sha256,
    deterministic_dag_workflow_id,
)
from redagent_platform.campaign_service.relay import RelayFailure, apply_relay_failure
from redagent_platform.campaign_service.repository import ClaimedWorkflowStart
from redagent_platform.orchestration.dag_execution_gateway import (
    workflow_input_from_dag_start_payload,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.campaign_service.owned_execution_store import project_owned_execution


class DagRelayConflict(RuntimeError):
    """The claimed event no longer binds the exact admitted execution run."""


class CampaignDagRelayRepository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        self.session = session
        self.tenant_id = _required("dag_relay_tenant", tenant_id, 64)
        self.actor_user_id = _required("dag_relay_actor", actor_user_id, 64)
        self.correlation_id = _required("dag_relay_correlation", correlation_id, 100)

    async def claim_dag_workflow_starts(
        self,
        *,
        claim_owner: str,
        now: datetime,
        lease_seconds: int,
        limit: int,
    ) -> list[ClaimedWorkflowStart]:
        await self._tenant_context()
        owner = _required("dag_relay_claim_owner", claim_owner, 100)
        _aware(now)
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("dag_relay_lease_seconds_invalid")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("dag_relay_claim_limit_invalid")
        outbox = metadata.tables["outbox_events"]
        rows = (
            await self.session.execute(
                select(outbox)
                .where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.event_type == "campaign.dag.start.requested.v1",
                    outbox.c.aggregate_type == "campaign_execution",
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
        claimed: list[ClaimedWorkflowStart] = []
        for row in rows:
            request = workflow_input_from_dag_start_payload(dict(row["payload"]))
            if request.tenant_id != self.tenant_id or request.execution_run_id != row["aggregate_id"]:
                raise DagRelayConflict("dag_relay_outbox_binding_mismatch")
            attempt_count = int(row["attempt_count"]) + 1
            if attempt_count > 10:
                continue
            updated = (
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
            if updated is not None:
                claimed.append(
                    ClaimedWorkflowStart(
                        event_id=str(updated["id"]),
                        campaign_id=str(updated["aggregate_id"]),
                        aggregate_sequence=int(updated["aggregate_sequence"]),
                        attempt_count=int(updated["attempt_count"]),
                        claim_owner=str(updated["claim_owner"]),
                        claim_expires_at=updated["claim_expires_at"],
                        payload=dict(updated["payload"]),
                        # CRITICAL: an expired claim may have lost a committed start response.
                        # Query its existing identity; reclaiming must never grant another start.
                        reconciliation_only=(row["delivery_state"] != "pending"),
                    )
                )
        return claimed

    async def acknowledge_dag_workflow_start(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> None:
        await self._tenant_context()
        event = _required("dag_relay_event", event_id, 64)
        owner = _required("dag_relay_claim_owner", claim_owner, 100)
        run_id = _required("dag_relay_temporal_run", workflow_run_id, 100)
        _aware(occurred_at)
        if type(duplicate_confirmed) is not bool:
            raise ValueError("dag_relay_duplicate_flag_invalid")
        outbox = metadata.tables["outbox_events"]
        row = (
            await self.session.execute(
                select(outbox)
                .where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.id == event,
                    outbox.c.event_type == "campaign.dag.start.requested.v1",
                    outbox.c.aggregate_type == "campaign_execution",
                    outbox.c.delivery_state == "claimed",
                    outbox.c.claim_owner == owner,
                    outbox.c.claim_expires_at > occurred_at,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            raise DagRelayConflict("dag_relay_claim_conflict")
        request = workflow_input_from_dag_start_payload(dict(row["payload"]))
        expected_workflow_id = deterministic_dag_workflow_id(
            request.tenant_id, request.execution_run_id
        )
        expected_request_sha256 = dag_workflow_request_sha256(request)
        runs = metadata.tables["campaign_execution_runs"]
        current_run = (await self.session.execute(select(runs).where(
            runs.c.tenant_id == self.tenant_id, runs.c.id == row["aggregate_id"],
            runs.c.workflow_id == expected_workflow_id, runs.c.request_sha256 == expected_request_sha256,
        ).with_for_update())).mappings().one_or_none()
        if current_run is None or current_run["workflow_run_id"] is not None:
            raise DagRelayConflict("dag_relay_run_ack_conflict")
        # CRITICAL: the workflow may advance PostgreSQL before its start response is attached.
        # Bind the one run ID without resetting execution progress or containment.
        run = (
            await self.session.execute(
                update(runs)
                .where(
                    runs.c.tenant_id == self.tenant_id,
                    runs.c.id == row["aggregate_id"],
                    runs.c.workflow_id == expected_workflow_id,
                    runs.c.request_sha256 == expected_request_sha256,
                    runs.c.workflow_run_id.is_(None),
                    runs.c.version == current_run["version"],
                )
                .values(
                    workflow_run_id=run_id,
                    run_state=("running" if current_run["run_state"] == "start_pending" else current_run["run_state"]),
                    started_at=current_run["started_at"] or occurred_at,
                    version=runs.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(runs)
            )
        ).mappings().one_or_none()
        if run is None:
            raise DagRelayConflict("dag_relay_run_ack_conflict")
        await project_owned_execution(self.session, run, now=occurred_at, actor_user_id=self.actor_user_id)
        await self.session.execute(
            update(outbox)
            .where(
                outbox.c.tenant_id == self.tenant_id,
                outbox.c.id == event,
                outbox.c.version == row["version"],
            )
            .values(
                published=True,
                delivery_state="delivered",
                delivered_at=occurred_at,
                reconciliation_state=(
                    "duplicate_confirmed" if duplicate_confirmed else "none"
                ),
                claim_owner=None,
                claim_expires_at=None,
                version=outbox.c.version + 1,
                updated_at=occurred_at,
            )
        )
        await self._audit(
            action="campaign.dag.workflow_started",
            subject_id=str(run["id"]),
            details={
                "workflow_id": expected_workflow_id,
                "workflow_run_id": run_id,
                "request_sha256": expected_request_sha256,
                "duplicate_confirmed": duplicate_confirmed,
            },
            occurred_at=occurred_at,
        )

    async def record_dag_workflow_start_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: RelayFailure,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> None:
        await self._tenant_context()
        event = _required("dag_relay_event", event_id, 64)
        owner = _required("dag_relay_claim_owner", claim_owner, 100)
        error = _required("dag_relay_error", last_error, 500)
        _aware(occurred_at)
        if not isinstance(failure, RelayFailure):
            raise ValueError("dag_relay_failure_invalid")
        outbox = metadata.tables["outbox_events"]
        row = (
            await self.session.execute(
                select(outbox)
                .where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.id == event,
                    outbox.c.event_type == "campaign.dag.start.requested.v1",
                    outbox.c.delivery_state == "claimed",
                    outbox.c.claim_owner == owner,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            raise DagRelayConflict("dag_relay_claim_conflict")
        decision = apply_relay_failure(
            attempt_count=int(row["attempt_count"]),
            failure=failure,
            now=occurred_at,
            max_attempts=max_attempts,
        )
        reconciliation_state = decision.reconciliation_state
        if failure is RelayFailure.AMBIGUOUS_START and error == "duplicate_query_unavailable" and int(row["attempt_count"]) < max_attempts:
            reconciliation_state = "start_outcome_unknown"
        await self.session.execute(
            update(outbox)
            .where(
                outbox.c.tenant_id == self.tenant_id,
                outbox.c.id == event,
                outbox.c.version == row["version"],
            )
            .values(
                delivery_state=decision.delivery_state.value,
                reconciliation_state=reconciliation_state,
                available_at=decision.available_at or row["available_at"],
                claim_owner=None,
                claim_expires_at=None,
                last_error=error,
                dead_lettered_at=decision.dead_lettered_at,
                version=outbox.c.version + 1,
                updated_at=occurred_at,
            )
        )
        await self._project_start_failure(
            row, reconciliation_state=reconciliation_state,
            terminal=decision.delivery_state.value != "pending" and reconciliation_state != "start_outcome_unknown",
            error=error, occurred_at=occurred_at,
        )
        await self._audit(
            action="campaign.dag.workflow_start_delivery_failed",
            subject_id=str(row["aggregate_id"]),
            details={
                "event_id": event,
                "delivery_state": decision.delivery_state.value,
                "reconciliation_state": reconciliation_state,
                "attempt_count": decision.attempt_count,
                "error_code": error,
            },
            occurred_at=occurred_at,
        )

    async def _project_start_failure(
        self, row: RowMapping, *, reconciliation_state: str, terminal: bool, error: str,
        occurred_at: datetime,
    ) -> None:
        if reconciliation_state == "none" and not terminal:
            return
        request = workflow_input_from_dag_start_payload(dict(row["payload"]))
        runs = metadata.tables["campaign_execution_runs"]
        applications = metadata.tables["autonomous_campaign_applications"]
        run = (await self.session.execute(select(runs).join(applications, and_(
            applications.c.tenant_id == runs.c.tenant_id,
            applications.c.id == runs.c.campaign_id,
        )).where(
            runs.c.tenant_id == self.tenant_id, runs.c.id == request.execution_run_id,
            runs.c.workflow_id == deterministic_dag_workflow_id(request.tenant_id, request.execution_run_id),
            runs.c.request_sha256 == dag_workflow_request_sha256(request),
            applications.c.mode == AutonomousCampaignMode.OWNED_LOOPBACK_AUTO.value,
        ).with_for_update(of=runs))).mappings().one_or_none()
        if run is None or run["run_state"] not in {"start_pending", "running", "reconciliation_required"}:
            return
        # CRITICAL: start ambiguity is operator-visible in the same transaction as recovery.
        # Exhausted queries stop future effects without claiming containment or cleanup.
        updated = (await self.session.execute(update(runs).where(
            runs.c.tenant_id == self.tenant_id, runs.c.id == run["id"], runs.c.version == run["version"],
        ).values(
            run_state="manual_review_required" if terminal else "reconciliation_required",
            stop_requested=bool(run["stop_requested"]) or terminal,
            terminal_reason=error, version=runs.c.version + 1, updated_at=occurred_at,
        ).returning(runs))).mappings().one()
        await project_owned_execution(self.session, updated, now=occurred_at, actor_user_id=self.actor_user_id)

    async def _audit(
        self,
        *,
        action: str,
        subject_id: str,
        details: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=str(uuid4()),
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=action,
                subject_type="campaign_execution",
                subject_id=subject_id,
                correlation_id=self.correlation_id,
                details=details,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )

    async def _tenant_context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )


class PostgresDagWorkflowRelayRepository:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_prefix: str,
    ) -> None:
        self._sessions = sessions
        self._tenant_id = tenant_id
        self._actor_user_id = actor_user_id
        self._correlation_prefix = correlation_prefix

    async def claim_dag_workflow_starts(
        self,
        *,
        claim_owner: str,
        now: datetime,
        lease_seconds: int,
        limit: int,
    ) -> list[ClaimedWorkflowStart]:
        async with self._sessions() as session, session.begin():
            return await self._repository(session, "claim").claim_dag_workflow_starts(
                claim_owner=claim_owner,
                now=now,
                lease_seconds=lease_seconds,
                limit=limit,
            )

    async def acknowledge_dag_workflow_start(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> None:
        async with self._sessions() as session, session.begin():
            await self._repository(session, "ack").acknowledge_dag_workflow_start(
                event_id=event_id,
                claim_owner=claim_owner,
                workflow_run_id=workflow_run_id,
                occurred_at=occurred_at,
                duplicate_confirmed=duplicate_confirmed,
            )

    async def record_dag_workflow_start_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: RelayFailure,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> None:
        async with self._sessions() as session, session.begin():
            await self._repository(session, "failure").record_dag_workflow_start_failure(
                event_id=event_id,
                claim_owner=claim_owner,
                failure=failure,
                last_error=last_error,
                occurred_at=occurred_at,
                max_attempts=max_attempts,
            )

    def _repository(self, session: AsyncSession, phase: str) -> CampaignDagRelayRepository:
        return CampaignDagRelayRepository(
            session,
            tenant_id=self._tenant_id,
            actor_user_id=self._actor_user_id,
            correlation_id=f"{self._correlation_prefix}-{phase}",
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


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("dag_relay_now_timezone_required")
