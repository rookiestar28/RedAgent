from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from redagent_platform.policy_service.boundaries import PolicyBoundarySDK
from redagent_platform.policy_service.contracts import PolicyBoundary


NOW = datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc)


class Enforcer:
    def __init__(self) -> None:
        self.calls = []

    async def enforce(self, request, *, required_revision, operation, now):
        self.calls.append((request, required_revision, operation, now))
        return object()


def test_sdk_builds_closed_current_facts_for_all_r099_boundaries() -> None:
    enforcer = Enforcer()
    sdk = PolicyBoundarySDK(enforcer, required_revision="r099-v1")
    asyncio.run(sdk.enforce_api(
        tenant_id="tenant-1", subject_id="operator-1", roles=("operator",),
        permissions=("job:create",), action="job:create", resource_type="job",
        resource_id="job-1", resource_version=1, policy_reference="policy:compat_099:1",
        roe_version_id="roe-1", correlation_id="api-correlation-1", requested_at=NOW,
    ))
    asyncio.run(sdk.enforce_workflow(
        tenant_id="tenant-1", subject_id="operator-1", action="job.command",
        job_id="job-1", job_status="pending", expected_version=1,
        dispatch_blocked=False, policy_reference="policy:compat_099:1", roe_version_id="roe-1",
        roe_status="current", correlation_id="workflow-correlation-1", requested_at=NOW,
    ))
    asyncio.run(sdk.enforce_evidence(
        tenant_id="tenant-1", subject_id="operator-1", action="evidence.write",
        artifact_id="artifact-1", artifact_class="redacted", classification="restricted",
        legal_hold=False, policy_reference="policy:compat_099:1", roe_version_id="roe-1",
        correlation_id="evidence-correlation-1", requested_at=NOW,
    ))
    asyncio.run(sdk.enforce_secret(
        tenant_id="tenant-1", subject_id="operator-1", action="secret.lease",
        lease_id="lease-1", reference_status="active", lease_state="pending",
        renewable=True, revoke_pending=False, permission_digest="a" * 64,
        permission_count=1, workload_client_status="active", policy_reference="policy:compat_099:1",
        roe_version_id="roe-1", correlation_id="secret-correlation-1", requested_at=NOW,
    ))
    assert [call[0].boundary for call in enforcer.calls] == [
        PolicyBoundary.API, PolicyBoundary.WORKFLOW, PolicyBoundary.EVIDENCE,
        PolicyBoundary.SECRET,
    ]
    assert all(call[1] == "r099-v1" for call in enforcer.calls)
    assert enforcer.calls[1][0].attributes["expected_version"] == 1
    assert enforcer.calls[2][0].attributes["classification"] == "restricted"
    assert enforcer.calls[3][0].attributes["permission_digest"] == "a" * 64
