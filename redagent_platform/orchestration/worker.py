"""Fail-closed construction for the compat_096 database-only Temporal worker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
import inspect
import os
from pathlib import Path
from typing import Mapping

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from temporalio.client import Client
from temporalio.worker import Worker

from redagent_platform.orchestration.activities import WorkflowActivities
from redagent_platform.orchestration.config import TemporalSettings, load_temporal_settings
from redagent_platform.orchestration.gateway import (
    TemporalOrchestrationGateway,
    connect_temporal,
)
from redagent_platform.orchestration.workflow import (
    CampaignLifecycleWorkflow,
    JobLifecycleWorkflow,
    ClosedLoopWorkflow,
)
from redagent_platform.persistence.database import async_engine_options, load_database_settings
from redagent_platform.campaign_service.registry import (
    StrategyLoopMode,
    load_strategy_loop_mode,
)


@dataclass(frozen=True, slots=True)
class WorkerRegistration:
    workflow_names: tuple[str, ...]
    activity_names: tuple[str, ...]
    max_concurrent_workflow_tasks: int
    max_concurrent_activities: int
    max_workflow_polls: int
    max_activity_polls: int
    runner_capability: bool


def worker_registration() -> WorkerRegistration:
    return WorkerRegistration(
        workflow_names=(
            "redagent.r096.job-lifecycle.v1",
            "redagent.r096.campaign-lifecycle.v1",
            "redagent.r123.campaign-closed-loop.v1",
        ),
        activity_names=(
            "r096_admit_job",
            "r096_apply_command",
            "r096_record_system_state",
            "r096_admit_campaign",
            "r100_dispatch_synthetic_job",
            "r101_contain_synthetic_job",
            "redagent.r123.reconcile-level.v1",
            "redagent.r123.dispatch-effect.v1",
            "redagent.r123.contain.v1",
        ),
        max_concurrent_workflow_tasks=20,
        max_concurrent_activities=10,
        max_workflow_polls=4,
        max_activity_polls=4,
        runner_capability=True,
    )


def validate_strategy_loop_worker_dependencies(
    env: Mapping[str, str],
    *,
    r123_coordinator=None,
    r123_coordinator_factory=None,
    r123_relay_factory=None,
):
    """Prevent a ready worker from silently exposing an unbound compat_123 execution path."""
    mode = load_strategy_loop_mode(env)
    if r123_coordinator is not None and r123_coordinator_factory is not None:
        raise ValueError("r123_coordinator_ambiguous")
    selected = r123_coordinator or r123_coordinator_factory
    if mode is StrategyLoopMode.TWO_CAPABILITY and selected is None:
        raise ValueError("r123_coordinator_required")
    if mode is StrategyLoopMode.TWO_CAPABILITY and r123_relay_factory is None:
        raise ValueError("r123_relay_required")
    if mode is StrategyLoopMode.DISABLED and selected is not None:
        raise ValueError("r123_coordinator_forbidden_when_disabled")
    if mode is StrategyLoopMode.DISABLED and r123_relay_factory is not None:
        raise ValueError("r123_relay_forbidden_when_disabled")
    return selected, r123_relay_factory


def build_workflow_worker(
    client: Client,
    sessions: async_sessionmaker[AsyncSession],
    settings: TemporalSettings,
    *,
    graceful_shutdown_seconds: int,
    runner_dispatcher=None,
    containment_dispatcher=None,
    r123_coordinator=None,
) -> Worker:
    if isinstance(graceful_shutdown_seconds, bool) or not 1 <= graceful_shutdown_seconds <= 300:
        raise ValueError("worker_graceful_shutdown_invalid")
    registration = worker_registration()
    activities = WorkflowActivities(
        sessions, runner_dispatcher=runner_dispatcher,
        containment_dispatcher=containment_dispatcher,
        r123_coordinator=r123_coordinator,
    )
    return Worker(
        client,
        task_queue=settings.task_queue,
        workflows=[JobLifecycleWorkflow, CampaignLifecycleWorkflow, ClosedLoopWorkflow],
        activities=[
            activities.admit_job,
            activities.apply_command,
            activities.record_system_state,
            activities.admit_campaign,
            activities.dispatch_synthetic_job,
            activities.contain_synthetic_job,
            activities.reconcile_closed_loop_level,
            activities.dispatch_closed_loop_effect,
            activities.contain_campaign,
        ],
        max_concurrent_workflow_tasks=registration.max_concurrent_workflow_tasks,
        max_concurrent_activities=registration.max_concurrent_activities,
        max_concurrent_workflow_task_polls=registration.max_workflow_polls,
        max_concurrent_activity_task_polls=registration.max_activity_polls,
        graceful_shutdown_timeout=timedelta(seconds=graceful_shutdown_seconds),
    )


async def run_workflow_worker(
    workspace: Path,
    *,
    env: Mapping[str, str] | None = None,
    graceful_shutdown_seconds: int = 30,
    runner_dispatcher=None,
    containment_dispatcher=None,
    r123_coordinator=None,
    r123_coordinator_factory=None,
    r123_relay_factory=None,
    readiness_event: asyncio.Event | None = None,
) -> None:
    values = dict(os.environ if env is None else env)
    selected_r123, selected_relay = validate_strategy_loop_worker_dependencies(
        values,
        r123_coordinator=r123_coordinator,
        r123_coordinator_factory=r123_coordinator_factory,
        r123_relay_factory=r123_relay_factory,
    )
    database = load_database_settings(workspace, env=values)
    temporal = load_temporal_settings(workspace, env=values)
    engine = create_async_engine(database.url, **async_engine_options(database))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        client = await connect_temporal(temporal)
        if r123_coordinator is None and selected_r123 is not None:
            if getattr(
                selected_r123,
                "_redagent_temporal_readiness_factory",
                False,
            ):
                created = selected_r123(
                    sessions,
                    TemporalOrchestrationGateway(client, temporal),
                )
            else:
                created = selected_r123(sessions)
            r123_coordinator = await created if inspect.isawaitable(created) else created
        worker = build_workflow_worker(
            client,
            sessions,
            temporal,
            graceful_shutdown_seconds=graceful_shutdown_seconds,
            runner_dispatcher=runner_dispatcher,
            containment_dispatcher=containment_dispatcher,
            r123_coordinator=r123_coordinator,
        )
        relay = None
        if selected_relay is not None:
            created_relay = selected_relay(sessions, client, temporal)
            relay = (
                await created_relay
                if inspect.isawaitable(created_relay)
                else created_relay
            )
            if not callable(getattr(relay, "run", None)):
                raise ValueError("r123_relay_factory_result_invalid")
        if readiness_event is not None:
            readiness_event.set()
        if relay is None:
            await worker.run()
        else:
            await _run_worker_with_relay(worker, relay)
    finally:
        if readiness_event is not None:
            readiness_event.clear()
        await engine.dispose()


async def _run_worker_with_relay(worker: object, relay: object) -> None:
    """Keep relay and Temporal polling one fail-closed process lifecycle."""
    stop = asyncio.Event()

    async def run_worker() -> None:
        try:
            await worker.run()
        finally:
            stop.set()

    async def run_relay() -> None:
        await relay.run(stop)
        if not stop.is_set():
            raise RuntimeError("r123_relay_stopped_unexpectedly")

    tasks = {
        asyncio.create_task(run_worker()),
        asyncio.create_task(run_relay()),
    }
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            await task
    finally:
        stop.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
