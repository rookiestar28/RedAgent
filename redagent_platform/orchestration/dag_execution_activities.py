"""Temporal Activity adapters for one transaction-owned DAG transition."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Protocol

from temporalio import activity
from temporalio.exceptions import ApplicationError

from redagent_platform.campaign_service.dag_execution_activity import (
    DagExecutionActivity,
    DagExecutionActivityStateOwner,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagContainActivityInputV1,
    DagExecutionSnapshotV1,
    DagWorkflowInputV1,
)


class DagContainmentOwner(Protocol):
    async def contain(
        self, request: DagContainActivityInputV1, *, now: datetime
    ) -> DagExecutionSnapshotV1: ...


class DagExecutionTemporalActivities:
    def __init__(
        self,
        state: DagExecutionActivityStateOwner,
        application: DagExecutionActivity,
        containment: DagContainmentOwner,
    ) -> None:
        self._state = state
        self._application = application
        self._containment = containment

    @activity.defn(name="redagent.campaign-dag.reconcile.v1")
    async def reconcile(self, request: DagWorkflowInputV1) -> DagExecutionSnapshotV1:
        try:
            material = await self._state.prepare(request, now=_activity_now())
        except (ValueError, RuntimeError) as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        return material.snapshot

    @activity.defn(name="redagent.campaign-dag.dispatch.v1")
    async def dispatch(self, request: DagWorkflowInputV1) -> DagExecutionSnapshotV1:
        task = asyncio.create_task(
            self._application.execute(request, now=_activity_now())
        )
        heartbeat_task = (
            asyncio.create_task(_dispatch_heartbeats(request.execution_run_id))
            if activity.in_activity()
            else None
        )
        try:
            if heartbeat_task is not None:
                completed, _ = await asyncio.wait(
                    (task, heartbeat_task), return_when=asyncio.FIRST_COMPLETED
                )
                if heartbeat_task in completed:
                    await heartbeat_task
            return await task
        except asyncio.CancelledError:
            # CRITICAL: cancellation must reach the effect coordinator before containment proceeds.
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
        except ValueError as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        except RuntimeError as exc:
            raise _permanent("DispatchDenied", exc) from exc
        finally:
            # CRITICAL: keep dispatch alive below the heartbeat timeout and await its
            # cleanup before containment; a timed-out live attempt can race recovery.
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                await asyncio.gather(heartbeat_task, return_exceptions=True)

    @activity.defn(name="redagent.campaign-dag.contain.v1")
    async def contain(
        self, request: DagContainActivityInputV1
    ) -> DagExecutionSnapshotV1:
        try:
            return await self._containment.contain(request, now=_activity_now())
        except ValueError as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        except RuntimeError as exc:
            raise _permanent("ContainmentFailed", exc) from exc


def _activity_now() -> datetime:
    return datetime.now(timezone.utc)


async def _dispatch_heartbeats(execution_run_id: str) -> None:
    timeout = activity.info().heartbeat_timeout
    interval = min(1.0, timeout.total_seconds() / 3) if timeout is not None else 1.0
    while True:
        activity.heartbeat(execution_run_id)
        await asyncio.sleep(interval)


def _permanent(error_type: str, exc: Exception) -> ApplicationError:
    return ApplicationError(str(exc), type=error_type, non_retryable=True)
