from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.containment_service.contracts import ControlScope, ControlScopeKind, QuotaDimension, QuotaPolicy
from redagent_platform.containment_service.quota import QuotaDecision, evaluate_quota


NOW = datetime(2026, 7, 10, 18, 0, tzinfo=timezone.utc)
POLICY = QuotaPolicy(
    policy_id="quota-1", tenant_id="tenant-1", revision=1,
    dimension=QuotaDimension.EVIDENCE_BYTES,
    scope=ControlScope(ControlScopeKind.JOB, "job-1"),
    hard_limit=10, window_seconds=60,
    active_from=NOW - timedelta(minutes=1), active_until=NOW + timedelta(minutes=1),
    extension_name=None,
)


def test_hard_quota_allows_exact_limit_and_breach_requires_containment() -> None:
    exact = evaluate_quota(POLICY, reserved=4, consumed=5, requested=1, occurred_at=NOW)
    assert exact == QuotaDecision(True, "quota_reserved", 0, False)
    breach = evaluate_quota(POLICY, reserved=4, consumed=5, requested=2, occurred_at=NOW)
    assert not breach.allowed
    assert breach.reason_code == "hard_quota_exceeded"
    assert breach.containment_required
    assert breach.remaining == 1


def test_missing_stale_or_invalid_quota_never_authorizes_side_effect() -> None:
    with pytest.raises(ValueError, match="quota_policy_required"):
        evaluate_quota(None, reserved=0, consumed=0, requested=1, occurred_at=NOW)
    stale = QuotaPolicy(**{**POLICY.__dict__, "active_until": NOW})
    decision = evaluate_quota(stale, reserved=0, consumed=0, requested=1, occurred_at=NOW)
    assert not decision.allowed and decision.reason_code == "quota_policy_inactive"
    with pytest.raises(ValueError, match="quota_request_invalid"):
        evaluate_quota(POLICY, reserved=0, consumed=0, requested=1.5, occurred_at=NOW)  # type: ignore[arg-type]
