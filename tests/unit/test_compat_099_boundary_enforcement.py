from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.policy_service.contracts import (
    PolicyBoundary,
    PolicyDecision,
    PolicyDecisionInput,
    PolicyObligation,
    policy_input_hash,
)
from redagent_platform.policy_service.enforcement import (
    PolicyBoundaryEnforcer,
    PolicyEnforcementError,
)


NOW = datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc)


class Provider:
    def __init__(self, *, allowed: bool = True, revision: str = "r099-v1") -> None:
        self.allowed = allowed
        self.revision = revision

    async def decide(self, request, *, required_revision, now):
        return PolicyDecision(
            decision_id=f"decision-{request.boundary.value}", bundle_revision=self.revision,
            input_hash=policy_input_hash(request), allowed=self.allowed,
            reason_code="boundary_authorized" if self.allowed else "boundary_denied",
            obligations=(PolicyObligation.AUDIT,), issued_at=NOW,
            valid_until=NOW + timedelta(seconds=30),
        )


class Recorder:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.receipts = []

    async def persist_decision_and_receipt(self, request, decision, *, operation):
        if self.fail:
            raise RuntimeError("database unavailable with sensitive detail")
        self.receipts.append((request, decision, operation))
        return f"receipt-{request.boundary.value}"


@pytest.mark.parametrize("boundary", tuple(PolicyBoundary))
def test_every_current_boundary_rechecks_and_persists_decision_reference(boundary: PolicyBoundary) -> None:
    recorder = Recorder()
    result = asyncio.run(PolicyBoundaryEnforcer(Provider(), recorder).enforce(
        _request(boundary), required_revision="r099-v1", operation=f"{boundary.value}.mutation", now=NOW,
    ))
    assert result.receipt_id == f"receipt-{boundary.value}"
    assert result.decision_id == f"decision-{boundary.value}"
    assert recorder.receipts[0][0].boundary is boundary


def test_denial_stale_revision_and_audit_failure_all_fail_closed() -> None:
    cases = (
        (Provider(allowed=False), Recorder(), "policy_boundary_denied:boundary_denied"),
        (Provider(revision="r099-stale"), Recorder(), "policy_decision_invalid"),
        (Provider(), Recorder(fail=True), "policy_decision_persistence_failed"),
    )
    for provider, recorder, reason in cases:
        with pytest.raises(PolicyEnforcementError, match=reason) as captured:
            asyncio.run(PolicyBoundaryEnforcer(provider, recorder).enforce(
                _request(PolicyBoundary.API), required_revision="r099-v1", operation="api.mutation", now=NOW,
            ))
        assert "sensitive detail" not in str(captured.value)


def _request(boundary: PolicyBoundary) -> PolicyDecisionInput:
    action_permissions = {
        PolicyBoundary.API: ("job.create", "job:create", {"job_status": "pending"}),
        PolicyBoundary.WORKFLOW: ("job.command", "workflow:command", {"roe_status": "current", "dispatch_blocked": False}),
        PolicyBoundary.EVIDENCE: ("evidence.write", "evidence:write", {"classification": "restricted"}),
        PolicyBoundary.SECRET: ("secret.lease", "secret:lease", {"reference_status": "active", "revoke_pending": False}),
        PolicyBoundary.RUNNER: (
            "runner.execute", "runner:execute",
            {
                "registration_state": "active", "capability_status": "certified",
                "artifact_status": "verified", "manifest_state": "claimed",
                "lease_state": "claimed", "identity_generation": 1,
                "runner_generation": 1,
            },
        ),
    }
    action, permission, attributes = action_permissions[boundary]
    return PolicyDecisionInput(
        boundary=boundary, action=action, tenant_id="tenant-1", subject_id="operator-1",
        roles=("operator",), permissions=(permission,), resource_type="job", resource_id="job-1",
        policy_reference="policy:compat_099:1", roe_version_id="roe-1", correlation_id="correlation-1",
        requested_at=NOW, attributes=attributes,
    )
