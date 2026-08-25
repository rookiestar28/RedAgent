from __future__ import annotations

import asyncio
import inspect

from temporalio import workflow
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner

from redagent_platform.orchestration.workflow import (
    CampaignLifecycleWorkflow,
    JobLifecycleWorkflow,
    activity_retry_policy,
)


def test_job_workflow_is_default_sandboxed_with_query_updates_and_stop_signal() -> None:
    definition = workflow._Definition.must_from_class(JobLifecycleWorkflow)

    assert definition.name == "redagent.r096.job-lifecycle.v1"
    assert definition.sandboxed is True
    assert set(definition.queries) == {"status"}
    assert set(definition.signals) == {"emergency_stop"}
    assert set(definition.updates) == {"approve", "pause", "resume", "retry", "cancel"}
    assert all(update.validator is not None for update in definition.updates.values())
    asyncio.run(_prepare(definition))


def test_campaign_workflow_is_sandboxed_and_owns_child_work_only() -> None:
    definition = workflow._Definition.must_from_class(CampaignLifecycleWorkflow)

    assert definition.name == "redagent.r096.campaign-lifecycle.v1"
    assert definition.sandboxed is True
    assert set(definition.queries) == {"status"}
    asyncio.run(_prepare(definition))


def test_activity_retry_policy_is_bounded_and_classifies_permanent_failures() -> None:
    policy = activity_retry_policy(3)

    assert policy.maximum_attempts == 3
    assert policy.backoff_coefficient == 2.0
    assert policy.maximum_interval.total_seconds() == 10
    assert set(policy.non_retryable_error_types or ()) == {
        "AuthorizationDenied",
        "InvalidWorkflowInput",
        "PolicyDenied",
        "ScopeDenied",
        "UnsupportedCapability",
        "WorkflowVersionConflict",
    }


def test_workflow_module_has_no_direct_side_effect_or_nondeterministic_imports() -> None:
    source = inspect.getsource(__import__("redagent_platform.orchestration.workflow", fromlist=["*"]))
    lowered = source.lower()

    for forbidden in (
        "sqlalchemy",
        "redagent_platform.persistence",
        "import os",
        "import random",
        "import socket",
        "datetime.now",
        "time.time",
        "open(",
        "sandbox_unrestricted",
        "unsandboxedworkflowrunner",
        "sandboxed=false",
    ):
        assert forbidden not in lowered
    assert '"r096_admit_job"' in source
    assert '"r096_apply_command"' in source
    assert "workflow.start_child_workflow" in source


async def _prepare(definition: workflow._Definition) -> None:
    SandboxedWorkflowRunner().prepare_workflow(definition)
