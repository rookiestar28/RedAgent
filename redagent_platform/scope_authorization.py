"""Engagement scope authorization engine.

This module is non-executing. It decides whether a future job request is
authorized by RBAC plus an approved engagement scope record.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from redagent_platform.domain import AuthorizationStatus, PolicyDecisionOutcome, TargetType, TestMode
from redagent_platform.rbac import (
    Action,
    AuthorizationRequest,
    Resource,
    ResourceType,
    Subject,
    decide as decide_rbac,
)


@dataclass(frozen=True, kw_only=True)
class ScopeTarget:
    target_type: TargetType
    value: str

    def normalized(self) -> "ScopeTarget":
        return ScopeTarget(target_type=self.target_type, value=normalize_target_value(self.value))


@dataclass(frozen=True, kw_only=True)
class EngagementScope:
    engagement_id: str
    organization_id: str
    authorization_status: AuthorizationStatus
    approved_by_user_id: str | None
    allowed_targets: tuple[ScopeTarget, ...]
    forbidden_targets: tuple[ScopeTarget, ...]
    allowed_modes: tuple[TestMode, ...]
    window_start: datetime
    window_end: datetime
    max_interactions: int
    max_rate_per_second: float
    emergency_contact_method: str | None


@dataclass(frozen=True, kw_only=True)
class JobScopeRequest:
    target: ScopeTarget
    mode: TestMode
    requested_at: datetime
    projected_interactions: int


@dataclass(frozen=True, kw_only=True)
class ScopeDecision:
    outcome: PolicyDecisionOutcome
    reason: str

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyDecisionOutcome.ALLOW


def normalize_target_value(value: str) -> str:
    """Normalize exact-match target values without widening scope."""
    return value.strip().lower().rstrip("/")


def _deny(reason: str) -> ScopeDecision:
    return ScopeDecision(outcome=PolicyDecisionOutcome.DENY, reason=reason)


def _allow(reason: str) -> ScopeDecision:
    return ScopeDecision(outcome=PolicyDecisionOutcome.ALLOW, reason=reason)


def _contains_target(targets: tuple[ScopeTarget, ...], requested: ScopeTarget) -> bool:
    normalized_requested = requested.normalized()
    return any(target.normalized() == normalized_requested for target in targets)


def _has_timezone(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def decide_scope(scope: EngagementScope, request: JobScopeRequest) -> ScopeDecision:
    """Evaluate engagement scope only, without RBAC."""
    if scope.authorization_status is not AuthorizationStatus.APPROVED:
        return _deny("authorization_not_approved")
    if not scope.approved_by_user_id:
        return _deny("missing_approver")
    if not scope.emergency_contact_method:
        return _deny("missing_emergency_contact")
    if not scope.allowed_targets:
        return _deny("missing_target_allowlist")
    if not scope.allowed_modes:
        return _deny("missing_allowed_modes")
    if scope.max_interactions <= 0:
        return _deny("invalid_interaction_cap")
    if scope.max_rate_per_second <= 0:
        return _deny("invalid_rate_limit")
    if not (_has_timezone(scope.window_start) and _has_timezone(scope.window_end) and _has_timezone(request.requested_at)):
        return _deny("timezone_required")
    if scope.window_start > scope.window_end:
        return _deny("invalid_time_window")
    if not (scope.window_start <= request.requested_at <= scope.window_end):
        return _deny("outside_time_window")
    if _contains_target(scope.forbidden_targets, request.target):
        return _deny("target_forbidden")
    if not _contains_target(scope.allowed_targets, request.target):
        return _deny("target_not_in_allowlist")
    if request.mode not in scope.allowed_modes:
        return _deny("mode_not_allowed")
    if request.projected_interactions <= 0:
        return _deny("invalid_projected_interactions")
    if request.projected_interactions > scope.max_interactions:
        return _deny("interaction_cap_exceeded")
    return _allow("scope_authorized")


def decide_job_authorization(
    *,
    subject: Subject,
    scope: EngagementScope,
    request: JobScopeRequest,
) -> ScopeDecision:
    """Evaluate RBAC and engagement scope as a future job prerequisite."""
    rbac_decision = decide_rbac(
        AuthorizationRequest(
            subject=subject,
            action=Action.CREATE,
            resource=Resource(
                resource_type=ResourceType.JOB,
                resource_id=f"pending-job:{scope.engagement_id}",
                organization_id=scope.organization_id,
            ),
        )
    )
    if not rbac_decision.allowed:
        return _deny(f"rbac_{rbac_decision.reason}")
    return decide_scope(scope, request)
