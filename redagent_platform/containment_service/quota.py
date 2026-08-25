"""Fail-closed deterministic hard-quota decision logic."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from redagent_platform.containment_service.contracts import QuotaPolicy


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    reason_code: str
    remaining: int
    containment_required: bool


def evaluate_quota(
    policy: QuotaPolicy | None,
    *,
    reserved: int,
    consumed: int,
    requested: int,
    occurred_at: datetime,
) -> QuotaDecision:
    """Evaluate one already-locked policy row without granting on ambiguity."""
    if policy is None:
        raise ValueError("quota_policy_required")
    for value in (reserved, consumed):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("quota_usage_invalid")
    if isinstance(requested, bool) or not isinstance(requested, int) or requested <= 0:
        raise ValueError("quota_request_invalid")
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ValueError("timezone_required")
    current = reserved + consumed
    remaining = max(policy.hard_limit - current, 0)
    if not policy.active_from <= occurred_at < policy.active_until:
        return QuotaDecision(False, "quota_policy_inactive", remaining, True)
    if current > policy.hard_limit or requested > remaining:
        return QuotaDecision(False, "hard_quota_exceeded", remaining, True)
    return QuotaDecision(True, "quota_reserved", remaining - requested, False)
