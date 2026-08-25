from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from temporalio.common import WorkflowIDReusePolicy

from redagent_platform.orchestration import gateway as gateway_module
from redagent_platform.orchestration.config import TemporalSettings
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CommandAction,
    EmergencyStopSignal,
    JobSnapshot,
    JobWorkflowInput,
    OperatorCommand,
    WorkflowState,
    deterministic_job_workflow_id,
)
from redagent_platform.orchestration.gateway import OrchestrationUnavailable, TemporalOrchestrationGateway
from redagent_platform.orchestration.state import CommandDecision


class FakeHandle:
    def __init__(self, workflow_id: str) -> None:
        self.id = workflow_id
        self.run_id = "run-1"
        self.updates: list[tuple[object, tuple[object, ...], dict[str, object]]] = []
        self.signals: list[tuple[object, tuple[object, ...], dict[str, object]]] = []

    async def query(self, query: object, *args: object, **kwargs: object) -> JobSnapshot:
        return JobSnapshot(CONTRACT_SCHEMA_VERSION, "job-1", WorkflowState.AWAITING_APPROVAL, 2, "operator_approval_required", None, 0, True, False, None)

    async def execute_update(self, update: object, *args: object, **kwargs: object):
        self.updates.append((update, args, kwargs))
        return {"accepted": True}

    async def signal(self, signal: object, *args: object, **kwargs: object) -> None:
        self.signals.append((signal, args, kwargs))


class FakeClient:
    def __init__(self) -> None:
        self.starts: list[tuple[object, tuple[object, ...], dict[str, object]]] = []
        self.handles: dict[str, FakeHandle] = {}

    async def start_workflow(self, workflow: object, *args: object, **kwargs: object) -> FakeHandle:
        self.starts.append((workflow, args, kwargs))
        handle = FakeHandle(str(kwargs["id"]))
        self.handles[handle.id] = handle
        return handle

    def get_workflow_handle(self, workflow_id: str) -> FakeHandle:
        return self.handles.setdefault(workflow_id, FakeHandle(workflow_id))


def _settings() -> TemporalSettings:
    return TemporalSettings(
        target="127.0.0.1:57233",
        namespace="redagent-local",
        task_queue="redagent-r096-v1",
        codec_key_id="test-r096-v1",
        codec_key_path=Path("ignored"),
        codec_key=b"k" * 32,
        tls=False,
        profile="local",
    )


def _input() -> JobWorkflowInput:
    return JobWorkflowInput(CONTRACT_SCHEMA_VERSION, "tenant-1", "job-1", "engagement-1", "roe-1", "policy:compat_096:1", 1, 3600, 3)


def test_gateway_uses_deterministic_id_fixed_queue_and_no_workflow_retry_policy() -> None:
    async def scenario() -> None:
        client = FakeClient()
        gateway = TemporalOrchestrationGateway(client, _settings())  # type: ignore[arg-type]
        reference = await gateway.start_job(_input())

        assert reference.workflow_id == deterministic_job_workflow_id("tenant-1", "job-1")
        assert reference.run_id == "run-1"
        _, args, options = client.starts[0]
        assert args == (_input(),)
        assert options["id"] == reference.workflow_id
        assert options["task_queue"] == "redagent-r096-v1"
        assert options["id_reuse_policy"] is WorkflowIDReusePolicy.REJECT_DUPLICATE
        assert "retry_policy" not in options

    asyncio.run(scenario())


def test_gateway_propagates_command_id_query_and_stop_signal_without_arbitrary_names() -> None:
    async def scenario() -> None:
        client = FakeClient()
        gateway = TemporalOrchestrationGateway(client, _settings())  # type: ignore[arg-type]
        workflow_id = deterministic_job_workflow_id("tenant-1", "job-1")
        handle = client.get_workflow_handle(workflow_id)
        command = OperatorCommand(CONTRACT_SCHEMA_VERSION, "command-1", CommandAction.APPROVE, "approver-1", 2, "policy:compat_096:1", "Approved bounded synthetic workflow")
        stop = EmergencyStopSignal(CONTRACT_SCHEMA_VERSION, "stop-1", "operator-1", "policy:compat_096:1", "Stop bounded synthetic workflow now")

        snapshot = await gateway.query_job(workflow_id)
        await gateway.command_job(workflow_id, command)
        await gateway.stop_job(workflow_id, stop)

        assert snapshot.revision == 2
        assert handle.updates == [
            ("approve", (command,), {"id": "command-1", "result_type": CommandDecision})
        ]
        assert handle.signals == [("emergency_stop", (stop,), {})]

    asyncio.run(scenario())


def test_gateway_waits_for_authoritative_workflow_revision_before_update() -> None:
    class LaggingHandle(FakeHandle):
        def __init__(self, workflow_id: str) -> None:
            super().__init__(workflow_id)
            self.query_calls = 0

        async def query(self, query: object, *args: object, **kwargs: object) -> JobSnapshot:
            self.query_calls += 1
            revision = 1 if self.query_calls == 1 else 2
            state = WorkflowState.DISPATCH_PENDING if revision == 1 else WorkflowState.AWAITING_APPROVAL
            return JobSnapshot(
                CONTRACT_SCHEMA_VERSION,
                "job-1",
                state,
                revision,
                "temporal_dispatch_pending" if revision == 1 else "operator_approval_required",
                None,
                0,
                True,
                False,
                None,
            )

        async def execute_update(self, update: object, *args: object, **kwargs: object):
            assert self.query_calls >= 2, "update executed before workflow revision catch-up"
            return await super().execute_update(update, *args, **kwargs)

    async def scenario() -> None:
        client = FakeClient()
        workflow_id = deterministic_job_workflow_id("tenant-1", "job-1")
        handle = LaggingHandle(workflow_id)
        client.handles[workflow_id] = handle
        gateway = TemporalOrchestrationGateway(client, _settings())  # type: ignore[arg-type]
        command = OperatorCommand(
            CONTRACT_SCHEMA_VERSION,
            "command-lagging-revision",
            CommandAction.APPROVE,
            "approver-1",
            2,
            "policy:compat_096:1",
            "Approve after durable workflow projection catches up",
        )

        result = await gateway.command_job(workflow_id, command)

        assert result == {"accepted": True}
        assert handle.query_calls == 2
        assert handle.updates == [
            ("approve", (command,), {"id": command.command_id, "result_type": CommandDecision})
        ]

    asyncio.run(scenario())


def test_gateway_revision_preflight_bounds_a_stalled_authoritative_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StalledHandle(FakeHandle):
        async def query(self, query: object, *args: object, **kwargs: object) -> JobSnapshot:
            await asyncio.Future()
            raise AssertionError("unreachable")

        async def execute_update(self, update: object, *args: object, **kwargs: object):
            raise AssertionError("update must not execute without an authoritative revision")

    async def scenario() -> None:
        client = FakeClient()
        workflow_id = deterministic_job_workflow_id("tenant-1", "job-1")
        client.handles[workflow_id] = StalledHandle(workflow_id)
        gateway = TemporalOrchestrationGateway(client, _settings())  # type: ignore[arg-type]
        command = OperatorCommand(
            CONTRACT_SCHEMA_VERSION,
            "command-stalled-query",
            CommandAction.APPROVE,
            "approver-1",
            2,
            "policy:compat_096:1",
            "Fail closed when authoritative revision cannot be read",
        )

        with pytest.raises(OrchestrationUnavailable, match="temporal_command_revision_sync_timeout"):
            await asyncio.wait_for(gateway.command_job(workflow_id, command), timeout=0.2)

    monkeypatch.setattr(gateway_module, "COMMAND_REVISION_SYNC_TIMEOUT_SECONDS", 0.02)
    asyncio.run(scenario())
