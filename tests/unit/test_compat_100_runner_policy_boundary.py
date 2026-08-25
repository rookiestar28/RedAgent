from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from redagent_platform.policy_service.boundaries import PolicyBoundarySDK
from redagent_platform.policy_service.contracts import PolicyBoundary


NOW = datetime(2026, 7, 10, 16, 0, tzinfo=timezone.utc)


class CapturingEnforcer:
    def __init__(self) -> None:
        self.calls = []

    async def enforce(self, request, *, required_revision, operation, now):
        self.calls.append((request, required_revision, operation, now))
        return object()


def test_runner_sdk_builds_closed_current_facts_for_each_execution_gate() -> None:
    enforcer = CapturingEnforcer()
    sdk = PolicyBoundarySDK(enforcer, required_revision="r099-v1")

    for action, permission, manifest_state, lease_state, sandbox_status in (
        ("runner.manifest.issue", "runner:issue", "draft", "absent", "certified"),
        ("runner.manifest.claim", "runner:claim", "issued", "absent", "certified"),
        ("runner.secret.resolve", "runner:secret", "claimed", "claimed", "verified"),
        ("runner.execute", "runner:execute", "claimed", "claimed", "verified"),
        ("runner.evidence.submit", "runner:evidence", "running", "claimed", "verified"),
    ):
        asyncio.run(sdk.enforce_runner(
            tenant_id="tenant-1", subject_id="runner-1", action=action,
            permissions=(permission,), job_id="job-1", registration_state="active",
            capability_status="certified", artifact_status="verified",
            manifest_state=manifest_state, lease_state=lease_state, identity_generation=2,
            runner_generation=2, sandbox_status=sandbox_status, cleanup_required=True,
            policy_reference="policy:compat_099:1",
            roe_version_id="roe-1", correlation_id=f"correlation-{permission[7:]}",
            requested_at=NOW,
        ))

    assert all(call[0].boundary is PolicyBoundary.RUNNER for call in enforcer.calls)
    assert [call[0].action for call in enforcer.calls] == [
        "runner.manifest.issue", "runner.manifest.claim", "runner.secret.resolve",
        "runner.execute", "runner.evidence.submit",
    ]
    assert enforcer.calls[0][0].attributes == {
        "registration_state": "active", "capability_status": "certified",
        "artifact_status": "verified", "manifest_state": "draft",
        "lease_state": "absent", "identity_generation": 2,
        "runner_generation": 2, "sandbox_status": "certified",
        "cleanup_required": True,
    }
