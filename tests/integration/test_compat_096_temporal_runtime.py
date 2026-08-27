from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from temporalio.service import RPCError, RPCStatusCode
from temporalio.worker import Replayer, Worker

from redagent_platform.api.app import create_app
from redagent_platform.identity.repository import IdentityRepository
from redagent_platform.orchestration.activities import WorkflowActivities
from redagent_platform.orchestration.config import TemporalSettings
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CommandAction,
    EmergencyStopSignal,
    JobWorkflowInput,
    OperatorCommand,
    WorkflowState,
    command_request_hash,
    deterministic_campaign_workflow_id,
    deterministic_job_workflow_id,
)
from redagent_platform.orchestration.gateway import (
    TemporalOrchestrationGateway,
    connect_temporal,
    temporal_data_converter,
)
from redagent_platform.orchestration.workflow import CampaignLifecycleWorkflow, JobLifecycleWorkflow
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.persistence.models import metadata
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from tests.integration.runtime_coordinates import persisted_temporal_target


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 13, 0, tzinfo=timezone.utc)
WORKFLOW_CLEANUP_TIMEOUT_SECONDS = 5.0


def test_real_temporal_encrypted_history_worker_restart_update_signal_and_replay() -> None:
    asyncio.run(_scenario())


def test_real_api_job_and_campaign_lifecycle_uses_temporal_and_postgres() -> None:
    asyncio.run(_api_scenario())


def test_temporal_test_cleanup_terminates_every_unique_tracked_workflow() -> None:
    calls: list[tuple[str, str]] = []

    class FakeHandle:
        def __init__(self, workflow_id: str) -> None:
            self.workflow_id = workflow_id

        async def terminate(self, reason: str) -> None:
            calls.append((self.workflow_id, reason))

    class FakeClient:
        def get_workflow_handle(self, workflow_id: str) -> FakeHandle:
            return FakeHandle(workflow_id)

    asyncio.run(
        _terminate_workflows(
            FakeClient(),  # type: ignore[arg-type]
            ["job-main", "campaign-parent", "job-main", "campaign-child"],
            "compat_096 integration cleanup",
        )
    )

    assert calls == [
        ("job-main", "compat_096 integration cleanup"),
        ("campaign-parent", "compat_096 integration cleanup"),
        ("campaign-child", "compat_096 integration cleanup"),
    ]


def test_temporal_test_cleanup_ignores_only_closed_or_missing_and_aggregates_failures() -> None:
    calls: list[str] = []

    class FakeHandle:
        def __init__(self, workflow_id: str) -> None:
            self.workflow_id = workflow_id

        async def terminate(self, reason: str) -> None:
            calls.append(self.workflow_id)
            if self.workflow_id == "missing":
                raise RPCError("missing", RPCStatusCode.NOT_FOUND, b"")
            if self.workflow_id == "closed":
                raise RPCError(
                    "workflow execution already completed",
                    RPCStatusCode.FAILED_PRECONDITION,
                    b"",
                )
            if self.workflow_id == "broken":
                raise RuntimeError("unexpected cleanup failure")

    class FakeClient:
        def get_workflow_handle(self, workflow_id: str) -> FakeHandle:
            return FakeHandle(workflow_id)

    with pytest.raises(AssertionError, match="broken:RuntimeError"):
        asyncio.run(
            _terminate_workflows(
                FakeClient(),  # type: ignore[arg-type]
                ["missing", "broken", "closed", "after-broken"],
                "compat_096 integration cleanup",
            )
        )

    assert calls == ["missing", "broken", "closed", "after-broken"]


def test_temporal_test_cleanup_bounds_each_termination_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeHandle:
        def __init__(self, workflow_id: str) -> None:
            self.workflow_id = workflow_id

        async def terminate(self, reason: str) -> None:
            calls.append(self.workflow_id)
            if self.workflow_id == "stalled":
                await asyncio.Future()

    class FakeClient:
        def get_workflow_handle(self, workflow_id: str) -> FakeHandle:
            return FakeHandle(workflow_id)

    monkeypatch.setitem(globals(), "WORKFLOW_CLEANUP_TIMEOUT_SECONDS", 0.02)
    with pytest.raises(AssertionError, match="stalled:timeout"):
        asyncio.run(
            asyncio.wait_for(
                _terminate_workflows(
                    FakeClient(),  # type: ignore[arg-type]
                    ["stalled", "after-stalled"],
                    "compat_096 integration cleanup",
                ),
                timeout=0.2,
            )
        )

    assert calls == ["stalled", "after-stalled"]


async def _scenario() -> None:
    database = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(database.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex
    tenant = f"tenant-temporal-{suffix}"
    operator = f"operator-temporal-{suffix}"
    approver = f"approver-temporal-{suffix}"
    engagement = f"eng-temporal-{suffix}"
    roe = f"roe-temporal-{suffix}"
    job = f"job-temporal-{suffix}"
    workflow_id = deterministic_job_workflow_id(tenant, job)
    queue = f"redagent-r096-test-{suffix[:12]}"
    settings = TemporalSettings(
        target=persisted_temporal_target(ROOT),
        namespace="default",
        task_queue=queue,
        codec_key_id=f"test-{suffix[:16]}",
        codec_key_path=ROOT / ".local" / "synthetic-test-key",
        codec_key=b"r" * 32,
        tls=False,
        profile="local",
    )
    client = await connect_temporal(settings)
    gateway = TemporalOrchestrationGateway(client, settings)
    activities = WorkflowActivities(sessions)
    first_worker: Worker | None = None
    first_task: asyncio.Task[None] | None = None
    second_worker: Worker | None = None
    second_task: asyncio.Task[None] | None = None
    started_workflow_ids: list[str] = []
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            operator=operator,
            approver=approver,
            engagement=engagement,
            roe=roe,
            job=job,
            workflow_id=workflow_id,
            suffix=suffix,
        )
        first_worker, first_task = _start_worker(client, queue, activities)
        request = JobWorkflowInput(
            CONTRACT_SCHEMA_VERSION,
            tenant,
            job,
            engagement,
            roe,
            "policy:compat_096:1",
            1,
            3600,
            3,
        )
        started_workflow_ids.append(workflow_id)
        reference = await gateway.start_job(request)
        started_workflow_ids.append(reference.workflow_id)
        assert reference.workflow_id == workflow_id and reference.run_id
        awaiting = await _wait_for_state(gateway, workflow_id, WorkflowState.AWAITING_APPROVAL)
        assert awaiting.revision == 2

        # Prove recovery by removing every worker before a versioned command is accepted.
        await _stop_worker(first_worker, first_task)
        first_worker = None
        first_task = None
        second_worker, second_task = _start_worker(client, queue, activities)
        command = OperatorCommand(
            CONTRACT_SCHEMA_VERSION,
            f"approve-{suffix}",
            CommandAction.APPROVE,
            approver,
            2,
            "policy:compat_096:1",
            "Approved encrypted synthetic Temporal workflow",
        )
        first = await gateway.command_job(workflow_id, command)
        duplicate = await gateway.command_job(workflow_id, command)
        assert first.snapshot.state == WorkflowState.READY.value
        assert duplicate.snapshot == first.snapshot

        history_before_stop = await client.get_workflow_handle(workflow_id).fetch_history()
        serialized = history_before_stop.to_json()
        assert tenant not in serialized
        assert job not in serialized
        assert "synthetic-noop" not in serialized
        assert "budget:compat_096:canary" not in serialized
        assert command_request_hash(command) not in serialized
        await Replayer(
            workflows=[JobLifecycleWorkflow, CampaignLifecycleWorkflow],
            data_converter=temporal_data_converter(settings),
        ).replay_workflow(history_before_stop)

        stop = EmergencyStopSignal(
            CONTRACT_SCHEMA_VERSION,
            f"stop-{suffix}",
            operator,
            "policy:compat_096:1",
            "Stop encrypted synthetic Temporal workflow now",
        )
        await gateway.stop_job(workflow_id, stop)
        stopped = await _wait_for_state(gateway, workflow_id, WorkflowState.STOP_REQUESTED)
        assert stopped.current_gate == "containment_owned_by_r101"
        assert stopped.stop_requested is True and stopped.dispatch_blocked is True
        history = await client.get_workflow_handle(workflow_id).fetch_history()
        await Replayer(
            workflows=[JobLifecycleWorkflow, CampaignLifecycleWorkflow],
            data_converter=temporal_data_converter(settings),
        ).replay_workflow(history)
        await _stop_worker(second_worker, second_task)
        second_worker = None
        second_task = None

        async with sessions() as session, session.begin():
            persisted = await ControlPlaneRepository(
                session,
                tenant_id=tenant,
                actor_user_id=operator,
                correlation_id=f"verify-{suffix}",
            ).get_job(job)
        assert persisted is not None
        assert persisted["orchestration_state"] == "stop_requested"
        assert persisted["stop_requested"] is True
        assert persisted["dispatch_blocked"] is True
        assert persisted["current_gate"] == "containment_owned_by_r101"
    finally:
        try:
            await _terminate_workflows(
                client,
                started_workflow_ids,
                "compat_096 encrypted-history integration cleanup",
            )
        finally:
            for worker, task in ((first_worker, first_task), (second_worker, second_task)):
                if worker is not None and task is not None:
                    try:
                        await _stop_worker(worker, task)
                    except TimeoutError:
                        task.cancel()
            await engine.dispose()


async def _api_scenario() -> None:
    database = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(database.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex
    tenant = f"tenant-api96-{suffix}"
    operator = f"operator-api96-{suffix}"
    approver = f"approver-api96-{suffix}"
    engagement = f"eng-api96-{suffix}"
    roe = f"roe-api96-{suffix}"
    seed_job = f"seed-api96-{suffix}"
    job = f"job-api96-{suffix}"
    campaign = f"campaign-api96-{suffix}"
    queue = f"redagent-r096-api-{suffix[:12]}"
    settings = TemporalSettings(
        target=persisted_temporal_target(ROOT),
        namespace="redagent-local",
        task_queue=queue,
        codec_key_id=f"api-{suffix[:16]}",
        codec_key_path=ROOT / ".local" / "synthetic-api-key",
        codec_key=b"a" * 32,
        tls=False,
        profile="local",
    )
    client = await connect_temporal(settings)
    gateway = TemporalOrchestrationGateway(client, settings)
    activities = WorkflowActivities(sessions)
    worker, worker_task = _start_worker(client, queue, activities)
    started_workflow_ids: list[str] = []
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            operator=operator,
            approver=approver,
            engagement=engagement,
            roe=roe,
            job=seed_job,
            workflow_id=deterministic_job_workflow_id(tenant, seed_job),
            suffix=suffix,
        )
        app = create_app(
            test_issuer_enabled=True,
            database_settings=database,
            orchestration_gateway=gateway,
            policy_provider=DeterministicFakePolicyProvider(revision="synthetic-r099-v1"),
            policy_required_revision="synthetic-r099-v1",
        )
        app.exception_handlers.pop(Exception, None)
        operator_headers = {
            "X-RedAgent-Test-Subject": operator,
            "X-RedAgent-Test-Tenant": tenant,
            "X-RedAgent-Test-Permissions": "job:create,job:read,job:update,job:stop,campaign:create,campaign:read",
            "X-RedAgent-Policy-Reference": "policy:compat_096:1",
            "X-RedAgent-ROE-Version": roe,
        }
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
                base_url="http://testserver",
            ) as api:
                ready = await api.get("/health/ready")
                assert ready.status_code == 200, ready.text
                job_workflow_id = deterministic_job_workflow_id(tenant, job)
                started_workflow_ids.append(job_workflow_id)
                created = await api.post(
                    "/api/v1/jobs",
                    headers={**operator_headers, "Idempotency-Key": f"create-{suffix}"},
                    json={
                        "job_id": job,
                        "engagement_id": engagement,
                        "roe_version_id": roe,
                        "request": {
                            "capability": "synthetic-noop",
                            "approval_timeout_seconds": 3600,
                            "max_activity_attempts": 3,
                            "budget_reference": "budget:compat_096:api",
                        },
                    },
                )
                assert created.status_code == 201, created.text
                created_job_workflow_id = str(created.json()["data"]["workflow_id"])
                started_workflow_ids.append(created_job_workflow_id)
                assert created_job_workflow_id == job_workflow_id
                await _wait_api_job(api, job, operator_headers, "awaiting_approval")

                sod = await api.post(
                    f"/api/v1/jobs/{job}/commands",
                    headers={
                        **operator_headers,
                        "X-RedAgent-Test-Permissions": "job:approve",
                        "Idempotency-Key": f"sod-{suffix}",
                    },
                    json={
                        "command_id": f"sod-{suffix}",
                        "action": "approve",
                        "expected_revision": 2,
                        "reason": "Creator must not approve own workflow",
                    },
                )
                assert sod.status_code == 403 and sod.json()["error"]["code"] == "separation_of_duties_required"
                approved = await api.post(
                    f"/api/v1/jobs/{job}/commands",
                    headers={
                        **operator_headers,
                        "X-RedAgent-Test-Subject": approver,
                        "X-RedAgent-Test-Permissions": "job:approve,job:read",
                        "Idempotency-Key": f"approve-{suffix}",
                    },
                    json={
                        "command_id": f"approve-{suffix}",
                        "action": "approve",
                        "expected_revision": 2,
                        "reason": "Distinct approver accepts synthetic workflow",
                    },
                )
                assert approved.status_code == 200, approved.text
                assert approved.json()["data"]["orchestration_state"] == "ready"

                stopped = await api.post(
                    f"/api/v1/jobs/{job}/emergency-stop",
                    headers={**operator_headers, "Idempotency-Key": f"stop-{suffix}"},
                    json={"signal_id": f"stop-{suffix}", "reason": "Stop synthetic API workflow now"},
                )
                assert stopped.status_code == 202, stopped.text
                stop_data = stopped.json()["data"]
                assert stop_data["job_id"] == job
                assert stop_data["workflow_id"] == deterministic_job_workflow_id(tenant, job)
                assert stop_data["stop_id"] == f"stop-{suffix}"
                assert stop_data["control_id"].startswith("containment-")
                assert stop_data["state"] == "stop_requested"
                assert not stop_data["containment_complete"]
                assert stop_data["completion_owner"] == "R101"
                containment_status = await api.get(
                    f"/api/v1/jobs/{job}/containment",
                    headers=operator_headers,
                )
                assert containment_status.status_code == 200, containment_status.text
                assert containment_status.json()["data"]["control_id"] == stop_data["control_id"]
                assert containment_status.json()["data"]["action_state"] == "not_started"
                assert not containment_status.json()["data"]["containment_complete"]
                await _wait_api_job(api, job, operator_headers, "stop_requested")

                broad = await api.post(
                    "/api/v1/containment-controls",
                    headers={**operator_headers, "Idempotency-Key": f"broad-stop-{suffix}"},
                    json={
                        "stop_id": f"broad-stop-{suffix}",
                        "scope_kind": "capability",
                        "scope_id": "synthetic-absent",
                        "expected_version": 1,
                        "reason": "Activate bounded capability containment control",
                    },
                )
                assert broad.status_code == 202, broad.text
                broad_data = broad.json()["data"]
                assert broad_data["control_state"] == "pending_approval"
                same_actor = await api.post(
                    f"/api/v1/containment-controls/{broad_data['control_id']}/approve",
                    headers={
                        **operator_headers,
                        "X-RedAgent-Test-Permissions": "job:approve",
                        "Idempotency-Key": f"broad-same-{suffix}",
                    },
                    json={
                        "approval_id": f"broad-same-{suffix}",
                        "request_hash": broad_data["request_hash"],
                        "expected_version": 1,
                    },
                )
                assert same_actor.status_code == 409
                broad_approved = await api.post(
                    f"/api/v1/containment-controls/{broad_data['control_id']}/approve",
                    headers={
                        **operator_headers,
                        "X-RedAgent-Test-Subject": approver,
                        "X-RedAgent-Test-Permissions": "job:approve",
                        "Idempotency-Key": f"broad-approve-{suffix}",
                    },
                    json={
                        "approval_id": f"broad-approve-{suffix}",
                        "request_hash": broad_data["request_hash"],
                        "expected_version": 1,
                    },
                )
                assert broad_approved.status_code == 200, broad_approved.text
                assert broad_approved.json()["data"]["control_state"] == "active"
                broad_recovered = await api.post(
                    f"/api/v1/containment-controls/{broad_data['control_id']}/recover",
                    headers={
                        **operator_headers,
                        "X-RedAgent-Test-Subject": f"reviewer-{suffix}",
                        "X-RedAgent-Test-Permissions": "audit:read",
                        "Idempotency-Key": f"broad-recover-{suffix}",
                    },
                    json={"review_id": f"broad-recover-{suffix}", "expected_version": 2},
                )
                assert broad_recovered.status_code == 200, broad_recovered.text
                assert broad_recovered.json()["data"]["control_state"] == "recovered"
                controls = await api.get("/api/v1/containment-controls", headers=operator_headers)
                assert controls.status_code == 200 and controls.json()["page"]["returned"] >= 2
                quota_status = await api.get("/api/v1/quotas/status", headers=operator_headers)
                assert quota_status.status_code == 200 and quota_status.json()["data"] == []

                campaign_workflow_id = deterministic_campaign_workflow_id(tenant, campaign)
                started_workflow_ids.extend(
                    [
                        campaign_workflow_id,
                        deterministic_job_workflow_id(tenant, f"child-a-{suffix}"),
                        deterministic_job_workflow_id(tenant, f"child-b-{suffix}"),
                    ]
                )
                created_campaign = await api.post(
                    "/api/v1/campaigns",
                    headers={
                        **operator_headers,
                        "X-RedAgent-Test-Subject": f"service:r096-recovery-{suffix}",
                        "Idempotency-Key": f"campaign-{suffix}",
                    },
                    json={
                        "campaign_id": campaign,
                        "engagement_id": engagement,
                        "roe_version_id": roe,
                        "name": "Synthetic API campaign",
                        "jobs": [
                            {
                                "job_id": f"child-a-{suffix}",
                                "request": {
                                    "capability": "synthetic-noop",
                                    "approval_timeout_seconds": 3600,
                                    "max_activity_attempts": 3,
                                    "budget_reference": "budget:compat_096:campaign",
                                },
                            },
                            {
                                "job_id": f"child-b-{suffix}",
                                "request": {
                                    "capability": "synthetic-noop",
                                    "approval_timeout_seconds": 3600,
                                    "max_activity_attempts": 3,
                                    "budget_reference": "budget:compat_096:campaign",
                                },
                            },
                        ],
                    },
                )
                assert created_campaign.headers["deprecation"] == "true"
                assert created_campaign.headers["x-redagent-remove-by"] == "2026-09-23"
                assert created_campaign.headers["x-redagent-compatibility-path"] == "r096-caller-id-m2m"
                assert created_campaign.status_code == 201, created_campaign.text
                created_campaign_workflow_id = str(created_campaign.json()["data"]["workflow_id"])
                started_workflow_ids.append(created_campaign_workflow_id)
                assert created_campaign_workflow_id == campaign_workflow_id
                await _wait_api_campaign(api, campaign, operator_headers)
                child_states = await _wait_api_campaign_children(api, campaign, operator_headers)
                assert child_states == {
                    f"child-a-{suffix}": "awaiting_approval",
                    f"child-b-{suffix}": "awaiting_approval",
                }
        async with sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
            workflow_receipts = await session.scalar(
                select(func.count()).select_from(metadata.tables["policy_boundary_receipts"]).where(
                    metadata.tables["policy_boundary_receipts"].c.tenant_id == tenant,
                    metadata.tables["policy_boundary_receipts"].c.boundary == "workflow",
                )
            )
            assert workflow_receipts >= 5
    finally:
        try:
            await _terminate_workflows(
                client,
                started_workflow_ids,
                "compat_096 API integration cleanup",
            )
        finally:
            await _stop_worker(worker, worker_task)
            await engine.dispose()


def _start_worker(client, queue: str, activities: WorkflowActivities) -> tuple[Worker, asyncio.Task[None]]:
    worker = Worker(
        client,
        task_queue=queue,
        workflows=[JobLifecycleWorkflow, CampaignLifecycleWorkflow],
        activities=[
            activities.admit_job,
            activities.apply_command,
            activities.record_system_state,
            activities.admit_campaign,
        ],
        max_concurrent_workflow_tasks=5,
        max_concurrent_activities=5,
        max_concurrent_workflow_task_polls=2,
        max_concurrent_activity_task_polls=2,
    )
    return worker, asyncio.create_task(worker.run())


async def _terminate_workflows(client, workflow_ids: list[str], reason: str) -> None:
    # IMPORTANT: integration runs must not leave workflow executions on abandoned unique task queues.
    failures: list[str] = []
    for workflow_id in dict.fromkeys(workflow_ids):
        try:
            await asyncio.wait_for(
                client.get_workflow_handle(workflow_id).terminate(reason),
                timeout=WORKFLOW_CLEANUP_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            failures.append(f"{workflow_id}:timeout")
        except RPCError as exc:
            already_closed = (
                exc.status == RPCStatusCode.FAILED_PRECONDITION
                and "already completed" in exc.message.lower()
            )
            if exc.status != RPCStatusCode.NOT_FOUND and not already_closed:
                failures.append(f"{workflow_id}:RPCError:{exc.status.name}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{workflow_id}:{type(exc).__name__}")
    if failures:
        raise AssertionError(f"temporal_test_cleanup_failed:{','.join(failures)}")


async def _stop_worker(worker: Worker, task: asyncio.Task[None]) -> None:
    await asyncio.wait_for(worker.shutdown(), timeout=10)
    await asyncio.wait_for(task, timeout=10)


async def _wait_for_state(
    gateway: TemporalOrchestrationGateway,
    workflow_id: str,
    expected: WorkflowState,
) -> object:
    deadline = asyncio.get_running_loop().time() + 20
    last = None
    while asyncio.get_running_loop().time() < deadline:
        last = await gateway.query_job(workflow_id)
        if last.state == expected.value:
            return last
        await asyncio.sleep(0.05)
    raise AssertionError(f"workflow_state_timeout:expected={expected!r}:observed={last!r}")


async def _wait_api_job(api, job_id: str, headers: dict[str, str], expected: str) -> dict[str, object]:
    deadline = asyncio.get_running_loop().time() + 20
    last: dict[str, object] | None = None
    while asyncio.get_running_loop().time() < deadline:
        response = await api.get(f"/api/v1/jobs/{job_id}", headers=headers)
        assert response.status_code == 200, response.text
        last = response.json()["data"]
        if last["orchestration_state"] == expected:
            return last
        await asyncio.sleep(0.05)
    raise AssertionError(f"api_job_state_timeout:{expected}:{last}")


async def _wait_api_campaign(api, campaign_id: str, headers: dict[str, str]) -> dict[str, object]:
    deadline = asyncio.get_running_loop().time() + 20
    last: dict[str, object] | None = None
    while asyncio.get_running_loop().time() < deadline:
        response = await api.get(f"/api/v1/campaigns/{campaign_id}", headers=headers)
        assert response.status_code == 200, response.text
        last = response.json()["data"]
        if last["status"] == "children_started":
            return last
        await asyncio.sleep(0.05)
    raise AssertionError(f"api_campaign_state_timeout:{last}")


async def _wait_api_campaign_children(api, campaign_id: str, headers: dict[str, str]) -> dict[str, str]:
    deadline = asyncio.get_running_loop().time() + 20
    last: dict[str, str] = {}
    while asyncio.get_running_loop().time() < deadline:
        response = await api.get("/api/v1/jobs", headers=headers)
        assert response.status_code == 200, response.text
        last = {
            row["job_id"]: row["orchestration_state"]
            for row in response.json()["data"]
            if row["campaign_id"] == campaign_id
        }
        if last and set(last.values()) == {"awaiting_approval"}:
            return last
        await asyncio.sleep(0.05)
    raise AssertionError(f"api_campaign_children_timeout:{last}")


async def _bootstrap(
    sessions,
    *,
    tenant: str,
    operator: str,
    approver: str,
    engagement: str,
    roe: str,
    job: str,
    workflow_id: str,
    suffix: str,
) -> None:
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"bootstrap-{suffix}")
        await repo.bootstrap_tenant(name="Temporal Tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=operator, subject=operator, occurred_at=NOW)
        await repo.bootstrap_user(user_id=approver, subject=approver, occurred_at=NOW)
        await repo.create_engagement(engagement_id=engagement, name="Temporal synthetic", owner_user_id=operator, idempotency_key=f"eng-{suffix}", occurred_at=NOW)
        created_roe = await repo.create_roe_version(
            roe_version_id=roe,
            engagement_id=engagement,
            revision=1,
            document={"active_testing": False},
            policy_reference_id=f"policy-{suffix}",
            policy_name="r096-policy",
            policy_version="1",
            idempotency_key=f"roe-{suffix}",
            occurred_at=NOW,
        )
        await repo.approve_roe_version(
            roe_version_id=roe,
            approval_id=f"approval-{suffix}",
            expected_version=int(created_roe.resource["version"]),
            idempotency_key=f"approve-{suffix}",
            occurred_at=NOW,
        )
        identity = IdentityRepository(session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"identity-{suffix}")
        await identity.provision_membership(user_id=operator, roles=("operator",), occurred_at=NOW)
        await identity.provision_membership(user_id=approver, roles=("approver",), occurred_at=NOW)
        await repo.create_job(
            job_id=job,
            engagement_id=engagement,
            roe_version_id=roe,
            request={
                "capability": "synthetic-noop",
                "approval_timeout_seconds": 3600,
                "max_activity_attempts": 3,
                "budget_reference": "budget:compat_096:canary",
            },
            workflow_id=workflow_id,
            policy_reference="policy:compat_096:1",
            campaign_id=None,
            idempotency_key=f"job-{suffix}",
            occurred_at=NOW,
        )
