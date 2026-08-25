import pytest

from redagent_platform.domain import PolicyDecisionOutcome, RoleName
from redagent_platform.rbac import (
    IDENTITY_AUDIT_EVENTS,
    PROTECTED_OBJECT_TYPES,
    ROLE_PERMISSIONS,
    SESSION_SECURITY_CONTROLS,
    Action,
    AuthorizationRequest,
    Resource,
    ResourceType,
    Subject,
    decide,
    require_allowed,
    role_names,
)


def subject(*roles: RoleName, organization_id: str = "org-1", authenticated: bool = True) -> Subject:
    return Subject(
        user_id="user-1" if authenticated else None,
        organization_id=organization_id,
        roles=frozenset(roles),
        authenticated=authenticated,
    )


def resource(resource_type: ResourceType, organization_id: str = "org-1") -> Resource:
    return Resource(
        resource_type=resource_type,
        resource_id=f"{resource_type.value}-1",
        organization_id=organization_id,
    )


def request(role: RoleName, action: Action, resource_type: ResourceType) -> AuthorizationRequest:
    return AuthorizationRequest(
        subject=subject(role),
        action=action,
        resource=resource(resource_type),
    )


def test_baseline_roles_cover_required_r005_roles() -> None:
    assert role_names() == {
        RoleName.ADMINISTRATOR,
        RoleName.SECURITY_LEAD,
        RoleName.OPERATOR,
        RoleName.REVIEWER,
        RoleName.READ_ONLY_AUDITOR,
        RoleName.SERVICE_RUNNER,
    }


def test_required_protected_objects_have_authorization_checks() -> None:
    assert PROTECTED_OBJECT_TYPES == {
        ResourceType.ENGAGEMENT,
        ResourceType.TARGET,
        ResourceType.JOB,
        ResourceType.FINDING,
        ResourceType.REPORT,
        ResourceType.EVIDENCE,
    }
    for resource_type in PROTECTED_OBJECT_TYPES:
        decision = decide(request(RoleName.ADMINISTRATOR, Action.READ, resource_type))
        assert decision.allowed, resource_type


def test_operator_can_create_jobs_but_not_approve_authorizations() -> None:
    assert decide(request(RoleName.OPERATOR, Action.CREATE, ResourceType.JOB)).allowed

    decision = decide(request(RoleName.OPERATOR, Action.APPROVE, ResourceType.AUTHORIZATION))

    assert decision.outcome is PolicyDecisionOutcome.DENY
    assert decision.reason == "missing_role_permission"


def test_reviewer_can_review_findings_but_not_execute_jobs() -> None:
    assert decide(request(RoleName.REVIEWER, Action.REVIEW, ResourceType.FINDING)).allowed

    decision = decide(request(RoleName.REVIEWER, Action.EXECUTE, ResourceType.JOB))

    assert decision.outcome is PolicyDecisionOutcome.DENY


def test_read_only_auditor_cannot_modify_reports() -> None:
    assert decide(request(RoleName.READ_ONLY_AUDITOR, Action.READ, ResourceType.REPORT)).allowed

    decision = decide(request(RoleName.READ_ONLY_AUDITOR, Action.UPDATE, ResourceType.REPORT))

    assert decision.outcome is PolicyDecisionOutcome.DENY


def test_service_runner_has_only_runner_callback_permissions() -> None:
    assert decide(request(RoleName.SERVICE_RUNNER, Action.SERVICE_CALLBACK, ResourceType.JOB)).allowed
    assert decide(request(RoleName.SERVICE_RUNNER, Action.CREATE, ResourceType.EVIDENCE)).allowed

    decision = decide(request(RoleName.SERVICE_RUNNER, Action.EXPORT, ResourceType.REPORT))

    assert decision.outcome is PolicyDecisionOutcome.DENY


def test_cross_tenant_access_fails_closed() -> None:
    decision = decide(
        AuthorizationRequest(
            subject=subject(RoleName.ADMINISTRATOR, organization_id="org-1"),
            action=Action.READ,
            resource=resource(ResourceType.EVIDENCE, organization_id="org-2"),
        )
    )

    assert decision.outcome is PolicyDecisionOutcome.DENY
    assert decision.reason == "cross_tenant_resource"


def test_unauthenticated_and_roleless_access_fail_closed() -> None:
    unauthenticated = decide(
        AuthorizationRequest(
            subject=subject(RoleName.ADMINISTRATOR, authenticated=False),
            action=Action.READ,
            resource=resource(ResourceType.ENGAGEMENT),
        )
    )
    roleless = decide(
        AuthorizationRequest(
            subject=subject(),
            action=Action.READ,
            resource=resource(ResourceType.ENGAGEMENT),
        )
    )

    assert unauthenticated.reason == "unauthenticated_subject"
    assert roleless.reason == "missing_subject_role"


def test_require_allowed_raises_permission_error_for_denial() -> None:
    with pytest.raises(PermissionError, match="missing_role_permission"):
        require_allowed(request(RoleName.REVIEWER, Action.EXECUTE, ResourceType.JOB))


def test_session_security_csrf_sso_and_audit_requirements_are_declared() -> None:
    assert "csrf_for_state_changing_browser_requests" in SESSION_SECURITY_CONTROLS
    assert "enterprise_sso_oidc_or_saml" in SESSION_SECURITY_CONTROLS
    assert "mfa_at_identity_provider" in SESSION_SECURITY_CONTROLS
    assert "login_success" in IDENTITY_AUDIT_EVENTS
    assert "policy_deny" in IDENTITY_AUDIT_EVENTS


def test_every_role_has_at_least_one_permission() -> None:
    for role in RoleName:
        assert ROLE_PERMISSIONS[role], role
