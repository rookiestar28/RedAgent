"""Canonical containment invocation and durable DAG terminal projection."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.activity_store import ActivityContainmentOwner
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagContainActivityInputV1,
    DagExecutionSnapshotV1,
    DagRunState,
    dag_workflow_request_sha256,
)
from redagent_platform.persistence.models import metadata


class DagContainmentConflict(RuntimeError):
    """The current execution no longer matches the stop projection request."""


class PostgresDagContainmentOwner:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        containment: ActivityContainmentOwner,
        *,
        correlation_prefix: str,
    ) -> None:
        self._sessions = sessions
        self._containment = containment
        self._correlation_prefix = _required(
            "dag_containment_correlation", correlation_prefix, 60
        )

    async def contain(
        self, request: DagContainActivityInputV1, *, now: datetime
    ) -> DagExecutionSnapshotV1:
        if not isinstance(request, DagContainActivityInputV1):
            raise ValueError("dag_containment_input_invalid")
        _aware(now)
        workflow = request.request
        correlation_id = f"{self._correlation_prefix}-{request.stop.signal_id}"[:100]
        campaign_id = await self._read_campaign_id(request)
        outcome, reason = await self._containment.contain(
            tenant_id=workflow.tenant_id,
            campaign_id=campaign_id,
            signal_id=request.stop.signal_id,
            actor_user_id=request.stop.actor_user_id,
            reason_sha256=request.stop.reason_sha256,
            now=now,
            correlation_id=correlation_id,
        )
        if outcome not in {
            "contained",
            "manual_review_required",
            "containment_failed",
        }:
            raise ValueError("dag_containment_outcome_invalid")
        async with self._sessions() as session, session.begin():
            await _set_tenant(session, workflow.tenant_id)
            runs = metadata.tables["campaign_execution_runs"]
            run = (
                await session.execute(
                    select(runs)
                    .where(
                        runs.c.tenant_id == workflow.tenant_id,
                        runs.c.id == workflow.execution_run_id,
                    )
                    .with_for_update()
                )
            ).mappings().one_or_none()
            if run is None:
                raise DagContainmentConflict("dag_containment_run_missing")
            replay = _terminal_replay(request, run)
            if replay is not None:
                return replay
            if (
                run["campaign_id"] != campaign_id
                or run["request_sha256"] != dag_workflow_request_sha256(workflow)
                or run["input_sha256"] != workflow.input_sha256
                or run["plan_sha256"] != workflow.plan_sha256
                or int(run["version"]) != request.expected_revision
                or str(run["run_state"])
                not in {"running", "stopping", "reconciliation_required"}
            ):
                raise DagContainmentConflict("dag_containment_binding_conflict")
            if outcome == "contained":
                run_state = "contained"
                node_state = "contained"
                active_concurrency = 0
            else:
                # CRITICAL: a request or failed cleanup is not proof of completed containment.
                run_state = "manual_review_required"
                node_state = "manual_review_required"
                active_concurrency = int(run["active_concurrency"])
            nodes = metadata.tables["campaign_execution_nodes"]
            await session.execute(
                update(nodes)
                .where(
                    nodes.c.tenant_id == workflow.tenant_id,
                    nodes.c.execution_run_id == workflow.execution_run_id,
                    nodes.c.node_state.not_in(("confirmed", "skipped", "contained")),
                )
                .values(
                    node_state=node_state,
                    version=nodes.c.version + 1,
                    updated_at=now,
                )
            )
            updated = (
                await session.execute(
                    update(runs)
                    .where(
                        runs.c.tenant_id == workflow.tenant_id,
                        runs.c.id == workflow.execution_run_id,
                        runs.c.version == run["version"],
                    )
                    .values(
                        run_state=run_state,
                        stop_requested=True,
                        terminal_reason=reason,
                        active_concurrency=active_concurrency,
                        completed_at=now,
                        version=runs.c.version + 1,
                        updated_at=now,
                    )
                    .returning(runs)
                )
            ).mappings().one_or_none()
            if updated is None:
                raise DagContainmentConflict("dag_containment_projection_conflict")
            await session.execute(
                insert(metadata.tables["audit_events"]).values(
                    id=str(uuid4()),
                    tenant_id=workflow.tenant_id,
                    actor_user_id=request.stop.actor_user_id,
                    action="campaign.dag.containment_recorded",
                    subject_type="campaign_execution",
                    subject_id=workflow.execution_run_id,
                    correlation_id=correlation_id,
                    details={
                        "signal_id": request.stop.signal_id,
                        "outcome": outcome,
                        "terminal_reason": reason,
                        "reason_sha256": request.stop.reason_sha256,
                    },
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            return _snapshot(request, updated)

    async def _read_campaign_id(self, request: DagContainActivityInputV1) -> str:
        workflow = request.request
        async with self._sessions() as session, session.begin():
            await _set_tenant(session, workflow.tenant_id)
            runs = metadata.tables["campaign_execution_runs"]
            row = (
                await session.execute(
                    select(runs.c.campaign_id).where(
                        runs.c.tenant_id == workflow.tenant_id,
                        runs.c.id == workflow.execution_run_id,
                        runs.c.request_sha256 == dag_workflow_request_sha256(workflow),
                        runs.c.input_sha256 == workflow.input_sha256,
                        runs.c.plan_sha256 == workflow.plan_sha256,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                raise DagContainmentConflict("dag_containment_run_missing")
            return str(row)


def _terminal_replay(
    request: DagContainActivityInputV1, run: Any
) -> DagExecutionSnapshotV1 | None:
    state = DagRunState(str(run["run_state"]))
    if state not in {
        DagRunState.CONTAINED,
        DagRunState.MANUAL_REVIEW_REQUIRED,
        DagRunState.FAILED,
    }:
        return None
    if not bool(run["stop_requested"]):
        raise DagContainmentConflict("dag_containment_terminal_without_stop")
    return _snapshot(request, run)


def _snapshot(
    request: DagContainActivityInputV1, run: Any
) -> DagExecutionSnapshotV1:
    workflow = request.request
    return DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id=workflow.execution_run_id,
        workflow_request_sha256=dag_workflow_request_sha256(workflow),
        state=DagRunState(str(run["run_state"])),
        revision=int(run["version"]),
        transition_count=int(run["transition_count"]),
        current_node_id=None,
        current_node_state=None,
        stop_requested=True,
        terminal_reason=(
            None
            if run["terminal_reason"] is None
            else str(run["terminal_reason"])
        ),
    )


async def _set_tenant(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
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
        raise ValueError("dag_containment_time_invalid")
