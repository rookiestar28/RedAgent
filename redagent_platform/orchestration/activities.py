"""Database-only Temporal Activities for compat_096 durable reconciliation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from temporalio import activity
from temporalio.exceptions import ApplicationError

from redagent_platform.orchestration.contracts import (
    ActivityCommand,
    ActivityResult,
    CampaignActivityResult,
    CampaignWorkflowInput,
    ContainmentActivityCommand,
    ContainmentActivityResult,
    JobWorkflowInput,
    RunnerDispatchCommand,
    RunnerDispatchResult,
    ClosedLoopContainActivityCommand,
    ClosedLoopContainActivityResult,
    ClosedLoopDispatchActivityCommand,
    ClosedLoopDispatchActivityResult,
    ClosedLoopReconcileActivityCommand,
    ClosedLoopReconcileActivityResult,
)
from redagent_platform.persistence.repository import (
    ActivityAuthorizationError,
    ConcurrencyConflict,
    ControlPlaneRepository,
    IdempotencyConflict,
    RecordConflict,
)


class WorkflowActivities:
    def __init__(
        self, sessions: async_sessionmaker[AsyncSession], *,
        runner_dispatcher=None, containment_dispatcher=None, r123_coordinator=None,
    ) -> None:
        self._sessions = sessions
        self._runner_dispatcher = runner_dispatcher
        self._containment_dispatcher = containment_dispatcher
        self._r123_coordinator = r123_coordinator

    @activity.defn(name="r096_admit_job")
    async def admit_job(self, request: JobWorkflowInput) -> ActivityResult:
        info = activity.info()
        run_id = _required_run_id(info.workflow_run_id)
        try:
            async with self._sessions() as session, session.begin():
                return await ControlPlaneRepository(
                    session,
                    tenant_id=request.tenant_id,
                    actor_user_id="redagent-workflow",
                    correlation_id=_correlation(info.workflow_id, run_id),
                ).admit_workflow_job(
                    request,
                    workflow_run_id=run_id,
                    occurred_at=datetime.now(timezone.utc),
                )
        except ActivityAuthorizationError as exc:
            raise _permanent("AuthorizationDenied", exc) from exc
        except RecordConflict as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        except ConcurrencyConflict as exc:
            raise _permanent("WorkflowVersionConflict", exc) from exc

    @activity.defn(name="r096_apply_command")
    async def apply_command(self, command: ActivityCommand) -> ActivityResult:
        return await self._apply(command)

    @activity.defn(name="r096_record_system_state")
    async def record_system_state(self, command: ActivityCommand) -> ActivityResult:
        if command.actor_user_id != "redagent-workflow" or command.action not in {
            "approval_timeout", "dispatch_started", "containment_completed",
            "containment_completed_with_residual_risk", "containment_failed",
        }:
            raise _permanent("AuthorizationDenied", ActivityAuthorizationError("workflow_system_actor_required"))
        return await self._apply(command)

    @activity.defn(name="r096_admit_campaign")
    async def admit_campaign(self, request: CampaignWorkflowInput) -> CampaignActivityResult:
        info = activity.info()
        run_id = _required_run_id(info.workflow_run_id)
        try:
            async with self._sessions() as session, session.begin():
                return await ControlPlaneRepository(
                    session,
                    tenant_id=request.tenant_id,
                    actor_user_id="redagent-workflow",
                    correlation_id=_correlation(info.workflow_id, run_id),
                ).admit_campaign_workflow(
                    request,
                    workflow_run_id=run_id,
                    occurred_at=datetime.now(timezone.utc),
                )
        except ActivityAuthorizationError as exc:
            raise _permanent("AuthorizationDenied", exc) from exc
        except (RecordConflict, ValueError) as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        except ConcurrencyConflict as exc:
            raise _permanent("WorkflowVersionConflict", exc) from exc

    @activity.defn(name="r100_dispatch_synthetic_job")
    async def dispatch_synthetic_job(self, request: RunnerDispatchCommand) -> RunnerDispatchResult:
        if self._runner_dispatcher is None:
            raise _permanent("UnsupportedCapability", RuntimeError("runner_dispatcher_unavailable"))
        info = activity.info()
        run_id = _required_run_id(info.workflow_run_id)
        dispatch_task = asyncio.create_task(self._runner_dispatcher.dispatch(
            request,
            occurred_at=datetime.now(timezone.utc),
            correlation_id=_correlation(info.workflow_id, run_id),
        ))
        try:
            while not dispatch_task.done():
                activity.heartbeat({"phase": "runner_dispatch", "job_id": request.job_id})
                await asyncio.wait({dispatch_task}, timeout=0.5)
            result = await dispatch_task
        except asyncio.CancelledError:
            # CRITICAL: propagate cancellation only after the runner task receives teardown cancellation.
            dispatch_task.cancel()
            done, _ = await asyncio.wait({dispatch_task}, timeout=5)
            for completed in done:
                try:
                    completed.result()
                except BaseException:  # noqa: BLE001
                    pass
            raise
        except ValueError as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        except RuntimeError as exc:
            error_type = "PolicyDenied" if "policy" in str(exc) else "UnsupportedCapability"
            raise _permanent(error_type, exc) from exc
        if not isinstance(result, RunnerDispatchResult) or result.job_id != request.job_id:
            raise _permanent("InvalidWorkflowInput", ValueError("runner_dispatch_result_invalid"))
        return result

    @activity.defn(name="r101_contain_synthetic_job")
    async def contain_synthetic_job(self, request: ContainmentActivityCommand) -> ContainmentActivityResult:
        if self._containment_dispatcher is None:
            raise _permanent("ContainmentUnavailable", RuntimeError("containment_dispatcher_unavailable"))
        info = activity.info()
        run_id = _required_run_id(info.workflow_run_id)
        containment_task = asyncio.create_task(self._containment_dispatcher.contain(
            request,
            occurred_at=datetime.now(timezone.utc),
            correlation_id=_correlation(info.workflow_id, run_id),
        ))
        try:
            while not containment_task.done():
                activity.heartbeat({"phase": "containment", "job_id": request.job_id})
                await asyncio.wait({containment_task}, timeout=0.5)
            result = await containment_task
        except asyncio.CancelledError:
            containment_task.cancel()
            done, _ = await asyncio.wait({containment_task}, timeout=5)
            for completed in done:
                try:
                    completed.result()
                except BaseException:  # noqa: BLE001
                    pass
            raise
        except ValueError as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        except RuntimeError as exc:
            raise _permanent("ContainmentFailed", exc) from exc
        if not isinstance(result, ContainmentActivityResult) or result.job_id != request.job_id:
            raise _permanent("InvalidWorkflowInput", ValueError("containment_activity_result_invalid"))
        return result

    @activity.defn(name="redagent.r123.reconcile-level.v1")
    async def reconcile_closed_loop_level(
        self, request: ClosedLoopReconcileActivityCommand
    ) -> ClosedLoopReconcileActivityResult:
        if self._r123_coordinator is None:
            raise _permanent("ExecutionDisabled", RuntimeError("r123_coordinator_unavailable"))
        info = activity.info()
        run_id = _required_run_id(info.workflow_run_id)
        try:
            result = await self._r123_coordinator.reconcile(
                request,
                occurred_at=datetime.now(timezone.utc),
                correlation_id=_correlation(info.workflow_id, run_id),
            )
        except (ValueError, RuntimeError) as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        if (
            not isinstance(result, ClosedLoopReconcileActivityResult)
            or result.campaign_id != request.campaign_id
            or result.strategy_revision_id != request.strategy_revision_id
        ):
            raise _permanent(
                "InvalidWorkflowInput", ValueError("r123_reconcile_result_invalid")
            )
        return result

    @activity.defn(name="redagent.r123.dispatch-effect.v1")
    async def dispatch_closed_loop_effect(
        self, request: ClosedLoopDispatchActivityCommand
    ) -> ClosedLoopDispatchActivityResult:
        if self._r123_coordinator is None:
            raise _permanent("ExecutionDisabled", RuntimeError("r123_coordinator_unavailable"))
        info = activity.info()
        run_id = _required_run_id(info.workflow_run_id)
        dispatch_task = asyncio.create_task(
            self._r123_coordinator.dispatch(
                request,
                occurred_at=datetime.now(timezone.utc),
                correlation_id=_correlation(info.workflow_id, run_id),
            )
        )
        try:
            while not dispatch_task.done():
                activity.heartbeat({"phase": "r123_dispatch", "effect_id": request.effect_id})
                await asyncio.wait({dispatch_task}, timeout=0.5)
            result = await dispatch_task
        except asyncio.CancelledError:
            # CRITICAL: stop cannot complete until the coordinator observes cancellation/cleanup.
            dispatch_task.cancel()
            done, _ = await asyncio.wait({dispatch_task}, timeout=5)
            for completed in done:
                try:
                    completed.result()
                except BaseException:  # noqa: BLE001
                    pass
            raise
        except (ValueError, RuntimeError) as exc:
            raise _permanent("DispatchDenied", exc) from exc
        if (
            not isinstance(result, ClosedLoopDispatchActivityResult)
            or result.campaign_id != request.campaign_id
            or result.effect_id != request.effect_id
        ):
            raise _permanent(
                "InvalidWorkflowInput", ValueError("r123_dispatch_result_invalid")
            )
        return result

    @activity.defn(name="redagent.r123.contain.v1")
    async def contain_campaign(
        self, request: ClosedLoopContainActivityCommand
    ) -> ClosedLoopContainActivityResult:
        if self._r123_coordinator is None:
            raise _permanent("ContainmentUnavailable", RuntimeError("r123_coordinator_unavailable"))
        info = activity.info()
        run_id = _required_run_id(info.workflow_run_id)
        try:
            result = await self._r123_coordinator.contain(
                request,
                occurred_at=datetime.now(timezone.utc),
                correlation_id=_correlation(info.workflow_id, run_id),
            )
        except (ValueError, RuntimeError) as exc:
            raise _permanent("ContainmentFailed", exc) from exc
        if not isinstance(result, ClosedLoopContainActivityResult) or result.campaign_id != request.campaign_id:
            raise _permanent(
                "InvalidWorkflowInput", ValueError("r123_containment_result_invalid")
            )
        return result

    async def _apply(self, command: ActivityCommand) -> ActivityResult:
        info = activity.info()
        run_id = _required_run_id(info.workflow_run_id)
        try:
            async with self._sessions() as session, session.begin():
                return await ControlPlaneRepository(
                    session,
                    tenant_id=command.tenant_id,
                    actor_user_id=command.actor_user_id,
                    correlation_id=_correlation(info.workflow_id, run_id),
                ).apply_workflow_command(command, occurred_at=datetime.now(timezone.utc))
        except ActivityAuthorizationError as exc:
            error_type = "PolicyDenied" if "policy" in str(exc) else "AuthorizationDenied"
            raise _permanent(error_type, exc) from exc
        except RecordConflict as exc:
            raise _permanent("InvalidWorkflowInput", exc) from exc
        except (ConcurrencyConflict, IdempotencyConflict) as exc:
            raise _permanent("WorkflowVersionConflict", exc) from exc


def _permanent(error_type: str, exc: Exception) -> ApplicationError:
    return ApplicationError(str(exc), type=error_type, non_retryable=True)


def _required_run_id(value: str | None) -> str:
    if not value or len(value) > 64:
        raise _permanent("InvalidWorkflowInput", ValueError("workflow_run_id_invalid"))
    return value


def _correlation(workflow_id: str | None, run_id: str) -> str:
    value = f"temporal:{workflow_id or 'unknown'}:{run_id}"
    return value[:100]
