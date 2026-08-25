from __future__ import annotations

import asyncio

import httpx
from pydantic import ValidationError
import pytest

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import (
    CampaignCreateRequest,
    JobCreateRequest,
    JobLifecycleCommandRequest,
)


R096_ROUTES = {
    "/api/v1/campaigns",
    "/api/v1/campaigns/{campaign_id}",
    "/api/v1/jobs",
    "/api/v1/jobs/{job_id}",
    "/api/v1/jobs/{job_id}/commands",
    "/api/v1/jobs/{job_id}/emergency-stop",
}


def test_r096_live_lifecycle_routes_and_response_models_are_in_openapi() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()

    assert R096_ROUTES <= set(schema["paths"])
    for model_name in (
        "CampaignCreateRequest",
        "JobCreateRequest",
        "JobLifecycleCommandRequest",
        "JobEmergencyStopRequest",
    ):
        assert schema["components"]["schemas"][model_name]["additionalProperties"] is False
    job = schema["components"]["schemas"]["JobData"]["properties"]
    assert {
        "workflow_id",
        "workflow_run_id",
        "orchestration_state",
        "orchestration_revision",
        "current_gate",
        "failure_code",
        "retry_count",
        "dispatch_blocked",
        "stop_requested",
    } <= set(job)


def test_job_and_campaign_inputs_are_typed_bounded_and_not_arbitrary_payloads() -> None:
    job = JobCreateRequest.model_validate(
        {
            "job_id": "job-1",
            "engagement_id": "engagement-1",
            "roe_version_id": "roe-1",
            "request": {
                "capability": "synthetic-noop",
                "approval_timeout_seconds": 3600,
                "max_activity_attempts": 3,
                "budget_reference": "budget:compat_096:1",
            },
        }
    )
    assert job.request.capability == "synthetic-noop"
    runner_job = JobCreateRequest.model_validate({
        **job.model_dump(),
        "request": {**job.request.model_dump(), "capability": "synthetic-conformance"},
    })
    assert runner_job.request.capability == "synthetic-conformance"
    with pytest.raises(ValidationError):
        JobCreateRequest.model_validate(
            {
                **job.model_dump(),
                "request": {**job.request.model_dump(), "shell": "echo unsafe"},
            }
        )
    with pytest.raises(ValidationError):
        JobCreateRequest.model_validate(
            {
                **job.model_dump(),
                "request": {**job.request.model_dump(), "credential": "blocked"},
            }
        )

    campaign = CampaignCreateRequest.model_validate(
        {
            "campaign_id": "campaign-1",
            "engagement_id": "engagement-1",
            "roe_version_id": "roe-1",
            "name": "Synthetic campaign",
            "jobs": [{"job_id": "job-1", "request": job.request.model_dump()}],
        }
    )
    assert campaign.jobs[0].job_id == "job-1"


def test_lifecycle_command_schema_separates_actions_and_requires_bounded_reason() -> None:
    command = JobLifecycleCommandRequest(
        command_id="command-1",
        action="approve",
        expected_revision=2,
        reason="Approved bounded synthetic workflow",
    )
    assert command.action == "approve"
    with pytest.raises(ValidationError):
        JobLifecycleCommandRequest(
            command_id="command-2",
            action="execute",  # type: ignore[arg-type]
            expected_revision=2,
            reason="Attempt arbitrary execution",
        )


def test_approval_requires_distinct_permission_before_database_or_temporal_access() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "POST",
        "/api/v1/jobs/job-1/commands",
        headers={
            "X-RedAgent-Test-Subject": "operator-1",
            "X-RedAgent-Test-Tenant": "tenant-1",
            "X-RedAgent-Test-Permissions": "job:update",
            "X-RedAgent-Policy-Reference": "policy:compat_096:1",
            "X-RedAgent-ROE-Version": "roe-1",
            "Idempotency-Key": "command-1",
        },
        json={
            "command_id": "command-1",
            "action": "approve",
            "expected_revision": 2,
            "reason": "Operator cannot self-approve this workflow",
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())
