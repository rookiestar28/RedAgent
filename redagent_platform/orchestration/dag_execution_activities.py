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
        try:
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


def _permanent(error_type: str, exc: Exception) -> ApplicationError:
    return ApplicationError(str(exc), type=error_type, non_retryable=True)
