from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from temporalio.worker import Worker

from redagent_platform.containment_service.contracts import ContainmentPhase, ControlScope, ControlScopeKind, StopRequest
from redagent_platform.containment_service.repository import ContainmentRepository
from redagent_platform.containment_service.runtime import PersistentContainmentDispatcher
from redagent_platform.identity.repository import IdentityRepository
from redagent_platform.orchestration.activities import WorkflowActivities
from redagent_platform.orchestration.config import TemporalSettings
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION, CommandAction, EmergencyStopSignal, JobSnapshot,
    JobWorkflowInput, OperatorCommand, WorkflowState, deterministic_job_workflow_id,
)
from redagent_platform.orchestration.gateway import TemporalOrchestrationGateway, connect_temporal
from redagent_platform.orchestration.workflow import CampaignLifecycleWorkflow, JobLifecycleWorkflow
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from tests.integration.runtime_coordinates import persisted_temporal_target


ROOT = Path(__file__).resolve().parents[2]


def test_live_temporal_cancels_heartbeating_dispatch_and_persists_all_containment_phases() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    database = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(database.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant, operator, approver = f"tenant-r101-live-{suffix}", f"operator-{suffix}", f"approver-{suffix}"
    engagement, roe, job = f"eng-{suffix}", f"roe-{suffix}", f"job-{suffix}"
    workflow_id = deterministic_job_workflow_id(tenant, job)
    started, cancelled = asyncio.Event(), asyncio.Event()

    class Dispatcher:
        async def dispatch(self, request, *, occurred_at, correlation_id):
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

    class PhaseBackend:
        async def execute_phase(self, phase: ContainmentPhase) -> str:
            if phase in {ContainmentPhase.RUNNER_ACK, ContainmentPhase.WORKLOAD_STOP}:
                await asyncio.wait_for(cancelled.wait(), timeout=2)
            return f"{phase.value}_verified"

    temporal = TemporalSettings(
        target=persisted_temporal_target(ROOT), namespace="redagent-local",
        task_queue=f"redagent-r101-live-{suffix}", codec_key_id=f"r101-{suffix}",
        codec_key_path=ROOT / ".local" / "synthetic-r101-key", codec_key=b"c" * 32,
        tls=False, profile="local",
    )
    client = await connect_temporal(temporal)
    gateway = TemporalOrchestrationGateway(client, temporal)
    containment = PersistentContainmentDispatcher(sessions, backend_factory=lambda command: PhaseBackend())
    activities = WorkflowActivities(
        sessions, runner_dispatcher=Dispatcher(), containment_dispatcher=containment,
    )
    worker = Worker(
        client, task_queue=temporal.task_queue,
        workflows=[JobLifecycleWorkflow, CampaignLifecycleWorkflow],
        activities=[
            activities.admit_job, activities.apply_command, activities.record_system_state,
            activities.admit_campaign, activities.dispatch_synthetic_job, activities.contain_synthetic_job,
        ],
        max_concurrent_workflow_tasks=5, max_concurrent_activities=5,
        max_concurrent_workflow_task_polls=2, max_concurrent_activity_task_polls=2,
    )
    worker_task = asyncio.create_task(worker.run())
    try:
        await _bootstrap(sessions, tenant, operator, approver, engagement, roe, job, workflow_id, suffix)
        await gateway.start_job(JobWorkflowInput(
            CONTRACT_SCHEMA_VERSION, tenant, job, engagement, roe,
            "policy:compat_101:1", 1, 3600, 1, True,
        ))
        await _wait_state(gateway, workflow_id, WorkflowState.AWAITING_APPROVAL)
        await gateway.command_job(workflow_id, OperatorCommand(
            CONTRACT_SCHEMA_VERSION, f"approve-{suffix}", CommandAction.APPROVE,
            approver, 2, "policy:compat_101:1", "Approve bounded compat_101 cancellation fixture",
        ))
        await asyncio.wait_for(started.wait(), timeout=10)
        requested_at = datetime.now(timezone.utc)
        stop_request = StopRequest(
            schema_version="1.0", stop_id=f"stop-{suffix}", tenant_id=tenant,
            scope=ControlScope(ControlScopeKind.JOB, job), initiated_by=operator,
            reason="Stop bounded compat_101 synthetic fixture", requested_at=requested_at,
            expected_version=1, idempotency_key=f"stop-{suffix}",
        )
        async with sessions() as session, session.begin():
            control = await ContainmentRepository(
                session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"stop-{suffix}",
            ).request_stop(stop_request)
        await gateway.stop_job(workflow_id, EmergencyStopSignal(
            CONTRACT_SCHEMA_VERSION, stop_request.stop_id, operator, "policy:compat_101:1",
            "Stop bounded compat_101 synthetic fixture", str(control["id"]),
        ))
        terminal = await asyncio.wait_for(
            client.get_workflow_handle(workflow_id, result_type=JobSnapshot).result(), timeout=20,
        )
        assert terminal.state == WorkflowState.CANCELLED.value
        assert terminal.current_gate == "containment_verified"
        assert cancelled.is_set()

        async with sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
            actions = metadata.tables["containment_job_actions"]
            phases = metadata.tables["containment_phase_receipts"]
            action = (await session.execute(select(actions).where(actions.c.tenant_id == tenant))).mappings().one()
            assert action["outcome"] == "contained"
            assert int(action["duration_ms"]) <= 10_000
            assert await session.scalar(select(func.count()).select_from(phases).where(phases.c.tenant_id == tenant)) == 8
    finally:
        await worker.shutdown()
        await asyncio.wait_for(worker_task, timeout=10)
        await engine.dispose()


async def _wait_state(gateway, workflow_id: str, state: WorkflowState) -> None:
    deadline = asyncio.get_running_loop().time() + 15
    while asyncio.get_running_loop().time() < deadline:
        if (await gateway.query_job(workflow_id)).state == state.value:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"r101_state_timeout:{state.value}")


async def _bootstrap(sessions, tenant, operator, approver, engagement, roe, job, workflow_id, suffix) -> None:
    now = datetime.now(timezone.utc)
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"bootstrap-{suffix}")
        await repo.bootstrap_tenant(name="compat_101 Live", occurred_at=now)
        await repo.bootstrap_user(user_id=operator, subject=operator, occurred_at=now)
        await repo.bootstrap_user(user_id=approver, subject=approver, occurred_at=now)
        identity = IdentityRepository(session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"identity-{suffix}")
        await identity.provision_membership(user_id=operator, roles=("operator",), occurred_at=now)
        await identity.provision_membership(user_id=approver, roles=("approver",), occurred_at=now)
        await repo.create_engagement(engagement_id=engagement, name="compat_101 Live", owner_user_id=operator, idempotency_key=f"eng-{suffix}", occurred_at=now)
        created = await repo.create_roe_version(
            roe_version_id=roe, engagement_id=engagement, revision=1,
            document={"active_testing": False}, policy_reference_id=f"policy-{suffix}",
            policy_name="r101-policy", policy_version="1", idempotency_key=f"roe-{suffix}", occurred_at=now,
        )
        await repo.approve_roe_version(
            roe_version_id=roe, approval_id=f"roe-approval-{suffix}",
            expected_version=int(created.resource["version"]), idempotency_key=f"roe-approval-{suffix}", occurred_at=now,
        )
        await repo.create_job(
            job_id=job, engagement_id=engagement, roe_version_id=roe,
            request={"capability": "synthetic-conformance", "approval_timeout_seconds": 3600, "max_activity_attempts": 1, "budget_reference": "budget:compat_101:live"},
            workflow_id=workflow_id, policy_reference="policy:compat_101:1", campaign_id=None,
            idempotency_key=f"job-{suffix}", occurred_at=now,
        )
