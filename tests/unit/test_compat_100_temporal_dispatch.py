from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from redagent_platform.orchestration.activities import WorkflowActivities
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    JobWorkflowInput,
    RunnerDispatchCommand,
    RunnerDispatchResult,
    WorkflowState,
)
from redagent_platform.orchestration.state import LifecycleReducer
from redagent_platform.orchestration.worker import worker_registration


NOW = datetime(2026, 7, 10, 16, 30, tzinfo=timezone.utc)


def test_dispatch_contract_is_history_safe_and_rejects_sensitive_or_failed_success() -> None:
    command = RunnerDispatchCommand(
        schema_version=CONTRACT_SCHEMA_VERSION, tenant_id="tenant-1", job_id="job-1",
        engagement_id="engagement-1", roe_version_id="roe-1",
        policy_reference="policy:compat_099:1", expected_revision=3,
        dispatch_id="r100-job-1-3",
    )
    result = RunnerDispatchResult(
        schema_version=CONTRACT_SCHEMA_VERSION, job_id="job-1",
        execution_id="execution-1", manifest_sha256="a" * 64,
        evidence_ids=("evidence-1",), state="succeeded", cleanup_completed=True,
        failure_code=None,
    )
    assert command.dispatch_id == "r100-job-1-3"
    assert result.state == "succeeded"
    with pytest.raises(ValueError, match="runner_dispatch_reference_invalid"):
        RunnerDispatchCommand(
            schema_version=CONTRACT_SCHEMA_VERSION, tenant_id="tenant-1", job_id="job-1",
            engagement_id="engagement-1", roe_version_id="roe-1",
            policy_reference="secret=forbidden", expected_revision=3,
            dispatch_id="r100-job-1-3",
        )
    with pytest.raises(ValueError, match="runner_dispatch_success_cleanup_required"):
        RunnerDispatchResult(
            schema_version=CONTRACT_SCHEMA_VERSION, job_id="job-1",
            execution_id="execution-1", manifest_sha256="a" * 64,
            evidence_ids=(), state="succeeded", cleanup_completed=False,
            failure_code=None,
        )


def test_lifecycle_reducer_owns_r100_dispatch_terminal_transition() -> None:
    reducer = LifecycleReducer("job-1")
    reducer.admit()
    from redagent_platform.orchestration.contracts import OperatorCommand

    reducer.apply(OperatorCommand(
        CONTRACT_SCHEMA_VERSION, "approve-1", "approve", "approver-1", 2,
        "policy:compat_099:1", "Approve bounded synthetic runner dispatch",
    ))
    dispatching = reducer.begin_dispatch()
    assert WorkflowState(dispatching.state) is WorkflowState.DISPATCHING
    assert not dispatching.dispatch_blocked
    completed = reducer.complete_dispatch()
    assert WorkflowState(completed.state) is WorkflowState.SUCCEEDED
    assert completed.current_gate == "runner_evidence_finalized"


def test_worker_registers_versioned_runner_dispatch_activity() -> None:
    registration = worker_registration()
    assert "r100_dispatch_synthetic_job" in registration.activity_names
    assert registration.runner_capability


def test_activity_dispatcher_is_required_and_returns_metadata_only_result(monkeypatch) -> None:
    command = RunnerDispatchCommand(
        schema_version=CONTRACT_SCHEMA_VERSION, tenant_id="tenant-1", job_id="job-1",
        engagement_id="engagement-1", roe_version_id="roe-1",
        policy_reference="policy:compat_099:1", expected_revision=3,
        dispatch_id="r100-job-1-3",
    )

    class Dispatcher:
        async def dispatch(self, request, *, occurred_at, correlation_id):
            assert request == command
            assert occurred_at.tzinfo is not None and correlation_id.startswith("temporal:")
            return RunnerDispatchResult(
                schema_version=CONTRACT_SCHEMA_VERSION, job_id="job-1",
                execution_id="execution-1", manifest_sha256="b" * 64,
                evidence_ids=("evidence-1",), state="succeeded",
                cleanup_completed=True, failure_code=None,
            )

    class Info:
        workflow_run_id = "run-1"
        workflow_id = "workflow-1"

    monkeypatch.setattr("redagent_platform.orchestration.activities.activity.info", lambda: Info())
    monkeypatch.setattr("redagent_platform.orchestration.activities.activity.heartbeat", lambda *details: None)
    activities = WorkflowActivities(object(), runner_dispatcher=Dispatcher())
    result = asyncio.run(activities.dispatch_synthetic_job(command))
    assert result.execution_id == "execution-1"
    assert not hasattr(result, "manifest")
