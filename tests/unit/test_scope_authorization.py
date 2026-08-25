from datetime import datetime, timezone

from redagent_platform import domain
from redagent_platform.rbac import Subject
from redagent_platform.scope_authorization import (
    EngagementScope,
    JobScopeRequest,
    ScopeTarget,
    decide_job_authorization,
    decide_scope,
)


START = datetime(2026, 7, 8, 9, 0, tzinfo=timezone.utc)
END = datetime(2026, 7, 8, 17, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)


def operator_subject(organization_id: str = "org-1") -> Subject:
    return Subject(
        user_id="operator-1",
        organization_id=organization_id,
        roles=frozenset({domain.RoleName.OPERATOR}),
        authenticated=True,
    )


def scope(**overrides: object) -> EngagementScope:
    values = {
        "engagement_id": "eng-1",
        "organization_id": "org-1",
        "authorization_status": domain.AuthorizationStatus.APPROVED,
        "approved_by_user_id": "lead-1",
        "allowed_targets": (
            ScopeTarget(target_type=domain.TargetType.DOMAIN, value="agentique.io"),
            ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="www.agentique.io"),
        ),
        "forbidden_targets": (ScopeTarget(target_type=domain.TargetType.DOMAIN, value="admin.agentique.io"),),
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN,),
        "window_start": START,
        "window_end": END,
        "max_interactions": 50,
        "max_rate_per_second": 1.0,
        "emergency_contact_method": "email",
    }
    values.update(overrides)
    return EngagementScope(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> JobScopeRequest:
    values = {
        "target": ScopeTarget(target_type=domain.TargetType.DOMAIN, value="agentique.io"),
        "mode": domain.TestMode.PASSIVE_SCAN,
        "requested_at": NOW,
        "projected_interactions": 10,
    }
    values.update(overrides)
    return JobScopeRequest(**values)  # type: ignore[arg-type]


def test_approved_scope_allows_operator_job_prerequisite() -> None:
    decision = decide_job_authorization(
        subject=operator_subject(),
        scope=scope(),
        request=request(),
    )

    assert decision.allowed
    assert decision.reason == "scope_authorized"


def test_unapproved_authorization_fails_closed() -> None:
    decision = decide_scope(
        scope(authorization_status=domain.AuthorizationStatus.DRAFT),
        request(),
    )

    assert decision.outcome is domain.PolicyDecisionOutcome.DENY
    assert decision.reason == "authorization_not_approved"


def test_missing_emergency_contact_fails_closed() -> None:
    decision = decide_scope(scope(emergency_contact_method=None), request())

    assert decision.reason == "missing_emergency_contact"


def test_out_of_scope_target_fails_closed() -> None:
    decision = decide_scope(
        scope(),
        request(target=ScopeTarget(target_type=domain.TargetType.DOMAIN, value="api.agentique.io")),
    )

    assert decision.reason == "target_not_in_allowlist"


def test_forbidden_target_overrides_allowlist() -> None:
    decision = decide_scope(
        scope(
            allowed_targets=(
                ScopeTarget(target_type=domain.TargetType.DOMAIN, value="agentique.io"),
                ScopeTarget(target_type=domain.TargetType.DOMAIN, value="admin.agentique.io"),
            )
        ),
        request(target=ScopeTarget(target_type=domain.TargetType.DOMAIN, value="admin.agentique.io")),
    )

    assert decision.reason == "target_forbidden"


def test_expired_window_fails_closed() -> None:
    decision = decide_scope(
        scope(),
        request(requested_at=datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)),
    )

    assert decision.reason == "outside_time_window"


def test_naive_datetime_fails_closed() -> None:
    decision = decide_scope(
        scope(),
        request(requested_at=datetime(2026, 7, 8, 10, 0)),
    )

    assert decision.reason == "timezone_required"


def test_forbidden_mode_fails_closed() -> None:
    decision = decide_scope(scope(), request(mode=domain.TestMode.ACTIVE_SCAN))

    assert decision.reason == "mode_not_allowed"


def test_interaction_cap_fails_closed() -> None:
    decision = decide_scope(scope(), request(projected_interactions=51))

    assert decision.reason == "interaction_cap_exceeded"


def test_invalid_rate_limit_fails_closed() -> None:
    decision = decide_scope(scope(max_rate_per_second=0), request())

    assert decision.reason == "invalid_rate_limit"


def test_rbac_denial_blocks_scope_authorization() -> None:
    decision = decide_job_authorization(
        subject=operator_subject(organization_id="other-org"),
        scope=scope(),
        request=request(),
    )

    assert decision.reason == "rbac_cross_tenant_resource"
