"""Fail-closed construction for the compat_096 database-only Temporal worker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
import inspect
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from temporalio.client import Client
from temporalio.worker import Worker

from redagent_platform.orchestration.activities import WorkflowActivities
from redagent_platform.orchestration.dag_execution_workflow import (
    CampaignDagExecutionWorkflow,
)
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
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagExecutionMode,
    load_dag_execution_mode,
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


def worker_registration(*, dag_execution_enabled: bool = False) -> WorkerRegistration:
    if type(dag_execution_enabled) is not bool:
        raise ValueError("dag_execution_registration_flag_invalid")
    dag_workflows = (
        ("redagent.campaign-dag-execution.v1",) if dag_execution_enabled else ()
    )
    dag_activities = (
        (
            "redagent.campaign-dag.reconcile.v1",
            "redagent.campaign-dag.dispatch.v1",
            "redagent.campaign-dag.contain.v1",
        )
        if dag_execution_enabled
        else ()
    )
    return WorkerRegistration(
        workflow_names=(
            "redagent.r096.job-lifecycle.v1",
            "redagent.r096.campaign-lifecycle.v1",
            "redagent.r123.campaign-closed-loop.v1",
        )
        + dag_workflows,
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
        )
        + dag_activities,
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


def validate_dag_execution_worker_dependencies(
    env: Mapping[str, str],
    *,
    dag_activities=None,
    dag_activities_factory=None,
    dag_relay_factory=None,
):
    """Expose the DAG workflow only with its exact Activity and relay owners."""
    mode = load_dag_execution_mode(env)
    if dag_activities is not None and dag_activities_factory is not None:
        raise ValueError("dag_activities_ambiguous")
    selected = (
        dag_activities if dag_activities is not None else dag_activities_factory
    )
    if mode is DagExecutionMode.OWNED_LOOPBACK and selected is None:
        raise ValueError("dag_activities_required")
    if mode is DagExecutionMode.OWNED_LOOPBACK and dag_relay_factory is None:
        raise ValueError("dag_relay_required")
    if mode is DagExecutionMode.DISABLED and selected is not None:
        raise ValueError("dag_activities_forbidden_when_disabled")
    if mode is DagExecutionMode.DISABLED and dag_relay_factory is not None:
        raise ValueError("dag_relay_forbidden_when_disabled")
    return selected, dag_relay_factory


def build_workflow_worker(
    client: Client,
    sessions: async_sessionmaker[AsyncSession],
    settings: TemporalSettings,
    *,
    graceful_shutdown_seconds: int,
    runner_dispatcher=None,
    containment_dispatcher=None,
    r123_coordinator=None,
    dag_activities=None,
) -> Worker:
    if isinstance(graceful_shutdown_seconds, bool) or not 1 <= graceful_shutdown_seconds <= 300:
        raise ValueError("worker_graceful_shutdown_invalid")
    registration = worker_registration(dag_execution_enabled=dag_activities is not None)
    activities = WorkflowActivities(
        sessions, runner_dispatcher=runner_dispatcher,
        containment_dispatcher=containment_dispatcher,
        r123_coordinator=r123_coordinator,
    )
    workflows = [JobLifecycleWorkflow, CampaignLifecycleWorkflow, ClosedLoopWorkflow]
    registered_activities: list[Callable[..., Any]] = [
        activities.admit_job,
        activities.apply_command,
        activities.record_system_state,
        activities.admit_campaign,
        activities.dispatch_synthetic_job,
        activities.contain_synthetic_job,
        activities.reconcile_closed_loop_level,
        activities.dispatch_closed_loop_effect,
        activities.contain_campaign,
    ]
    if dag_activities is not None:
        workflows.append(CampaignDagExecutionWorkflow)
        registered_activities.extend(
            [
                dag_activities.reconcile,
                dag_activities.dispatch,
                dag_activities.contain,
            ]
        )
    return Worker(
        client,
        task_queue=settings.task_queue,
        workflows=workflows,
        activities=registered_activities,
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
    dag_activities=None,
    dag_activities_factory=None,
    dag_relay_factory=None,
    readiness_event: asyncio.Event | None = None,
) -> None:
    values = dict(os.environ if env is None else env)
    selected_r123, selected_relay = validate_strategy_loop_worker_dependencies(
        values,
        r123_coordinator=r123_coordinator,
        r123_coordinator_factory=r123_coordinator_factory,
        r123_relay_factory=r123_relay_factory,
    )
    selected_dag, selected_dag_relay = validate_dag_execution_worker_dependencies(
        values,
        dag_activities=dag_activities,
        dag_activities_factory=dag_activities_factory,
        dag_relay_factory=dag_relay_factory,
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
        if dag_activities is None and selected_dag is not None:
            if getattr(
                selected_dag,
                "_redagent_temporal_readiness_factory",
                False,
            ):
                created_dag = selected_dag(
                    sessions,
                    TemporalOrchestrationGateway(client, temporal),
                )
            else:
                created_dag = selected_dag(sessions)
            dag_activities = (
                await created_dag if inspect.isawaitable(created_dag) else created_dag
            )
        worker = build_workflow_worker(
            client,
            sessions,
            temporal,
            graceful_shutdown_seconds=graceful_shutdown_seconds,
            runner_dispatcher=runner_dispatcher,
            containment_dispatcher=containment_dispatcher,
            r123_coordinator=r123_coordinator,
            dag_activities=dag_activities,
        )
        relays = []
        if selected_relay is not None:
            created_relay = selected_relay(sessions, client, temporal)
            relay = (
                await created_relay
                if inspect.isawaitable(created_relay)
                else created_relay
            )
            if not callable(getattr(relay, "run", None)):
                raise ValueError("r123_relay_factory_result_invalid")
            relays.append(relay)
        if selected_dag_relay is not None:
            created_dag_relay = selected_dag_relay(sessions, client, temporal)
            dag_relay = (
                await created_dag_relay
                if inspect.isawaitable(created_dag_relay)
                else created_dag_relay
            )
            if not callable(getattr(dag_relay, "run", None)):
                raise ValueError("dag_relay_factory_result_invalid")
            relays.append(dag_relay)
        if readiness_event is not None:
            readiness_event.set()
        if not relays:
            await worker.run()
        else:
            await _run_worker_with_relays(worker, tuple(relays))
    finally:
        if readiness_event is not None:
            readiness_event.clear()
        await engine.dispose()


async def _run_worker_with_relay(worker: object, relay: object) -> None:
    """Keep relay and Temporal polling one fail-closed process lifecycle."""
    await _run_worker_with_relays(worker, (relay,))


async def _run_worker_with_relays(worker: object, relays: tuple[object, ...]) -> None:
    """Keep every enabled relay and Temporal polling in one fail-closed lifecycle."""
    if not relays:
        raise ValueError("worker_relays_required")
    stop = asyncio.Event()

    async def run_worker() -> None:
        try:
            await worker.run()
        finally:
            stop.set()

    async def run_relay(relay: object) -> None:
        await relay.run(stop)
        if not stop.is_set():
            raise RuntimeError("workflow_relay_stopped_unexpectedly")

    tasks = {asyncio.create_task(run_worker())}
    tasks.update(asyncio.create_task(run_relay(relay)) for relay in relays)
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
