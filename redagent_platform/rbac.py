"""Fail-closed RBAC and tenant-boundary policy core."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from redagent_platform.domain import PolicyDecisionOutcome, RoleName


class Action(str, Enum):
    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    APPROVE = "approve"
    EXECUTE = "execute"
    REVIEW = "review"
    EXPORT = "export"
    MANAGE = "manage"
    SERVICE_CALLBACK = "service_callback"


class ResourceType(str, Enum):
    ORGANIZATION = "organization"
    USER = "user"
    ROLE = "role"
    ENGAGEMENT = "engagement"
    TARGET = "target"
    AUTHORIZATION = "authorization"
    TEST_DEFINITION = "test_definition"
    RUNNER = "runner"
    JOB = "job"
    EVIDENCE = "evidence"
    FINDING = "finding"
    REPORT = "report"
    AUDIT_EVENT = "audit_event"
    POLICY_DECISION = "policy_decision"


@dataclass(frozen=True, kw_only=True)
class Subject:
    user_id: str | None
    organization_id: str | None
    roles: frozenset[RoleName]
    authenticated: bool


@dataclass(frozen=True, kw_only=True)
class Resource:
    resource_type: ResourceType
    resource_id: str
    organization_id: str


@dataclass(frozen=True, kw_only=True)
class AuthorizationRequest:
    subject: Subject
    action: Action
    resource: Resource


@dataclass(frozen=True, kw_only=True)
class AuthorizationDecision:
    outcome: PolicyDecisionOutcome
    reason: str

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyDecisionOutcome.ALLOW


ALL_RESOURCE_TYPES: Final[frozenset[ResourceType]] = frozenset(ResourceType)

PROTECTED_OBJECT_TYPES: Final[frozenset[ResourceType]] = frozenset(
    {
        ResourceType.ENGAGEMENT,
        ResourceType.TARGET,
        ResourceType.JOB,
        ResourceType.FINDING,
        ResourceType.REPORT,
        ResourceType.EVIDENCE,
    }
)

SESSION_SECURITY_CONTROLS: Final[tuple[str, ...]] = (
    "authenticated_actor",
    "secure_cookie",
    "http_only_cookie",
    "same_site_cookie",
    "session_expiration",
    "session_rotation_after_login",
    "logout_invalidation",
    "csrf_for_state_changing_browser_requests",
    "enterprise_sso_oidc_or_saml",
    "mfa_at_identity_provider",
)

IDENTITY_AUDIT_EVENTS: Final[tuple[str, ...]] = (
    "login_success",
    "login_failure",
    "logout",
    "role_grant",
    "role_revoke",
    "policy_allow",
    "policy_deny",
)

READ_ALL: Final[frozenset[tuple[ResourceType, Action]]] = frozenset(
    (resource_type, Action.READ) for resource_type in ALL_RESOURCE_TYPES
)

ROLE_PERMISSIONS: Final[dict[RoleName, frozenset[tuple[ResourceType, Action]]]] = {
    RoleName.ADMINISTRATOR: frozenset(
        (resource_type, action)
        for resource_type in ALL_RESOURCE_TYPES
        for action in Action
        if action is not Action.SERVICE_CALLBACK
    ),
    RoleName.SECURITY_LEAD: READ_ALL
    | frozenset(
        {
            (ResourceType.ENGAGEMENT, Action.CREATE),
            (ResourceType.ENGAGEMENT, Action.UPDATE),
            (ResourceType.TARGET, Action.CREATE),
            (ResourceType.TARGET, Action.UPDATE),
            (ResourceType.AUTHORIZATION, Action.CREATE),
            (ResourceType.AUTHORIZATION, Action.UPDATE),
            (ResourceType.AUTHORIZATION, Action.APPROVE),
            (ResourceType.TEST_DEFINITION, Action.CREATE),
            (ResourceType.TEST_DEFINITION, Action.UPDATE),
            (ResourceType.JOB, Action.APPROVE),
            (ResourceType.REPORT, Action.EXPORT),
        }
    ),
    RoleName.OPERATOR: READ_ALL
    | frozenset(
        {
            (ResourceType.JOB, Action.CREATE),
            (ResourceType.JOB, Action.EXECUTE),
            (ResourceType.JOB, Action.UPDATE),
            (ResourceType.EVIDENCE, Action.CREATE),
        }
    ),
    RoleName.REVIEWER: READ_ALL
    | frozenset(
        {
            (ResourceType.FINDING, Action.REVIEW),
            (ResourceType.FINDING, Action.UPDATE),
            (ResourceType.REPORT, Action.CREATE),
            (ResourceType.REPORT, Action.UPDATE),
        }
    ),
    RoleName.READ_ONLY_AUDITOR: READ_ALL,
    RoleName.SERVICE_RUNNER: frozenset(
        {
            (ResourceType.JOB, Action.READ),
            (ResourceType.JOB, Action.SERVICE_CALLBACK),
            (ResourceType.EVIDENCE, Action.CREATE),
            (ResourceType.EVIDENCE, Action.SERVICE_CALLBACK),
        }
    ),
}


def role_names() -> frozenset[RoleName]:
    """Return all supported baseline roles."""
    return frozenset(ROLE_PERMISSIONS)


def is_cross_tenant(subject: Subject, resource: Resource) -> bool:
    """Return True when subject and resource organizations do not match."""
    return subject.organization_id != resource.organization_id


def decide(request: AuthorizationRequest) -> AuthorizationDecision:
    """Evaluate an authorization request with fail-closed defaults."""
    subject = request.subject
    resource = request.resource

    if not subject.authenticated or not subject.user_id:
        return AuthorizationDecision(
            outcome=PolicyDecisionOutcome.DENY,
            reason="unauthenticated_subject",
        )
    if not subject.organization_id:
        return AuthorizationDecision(
            outcome=PolicyDecisionOutcome.DENY,
            reason="missing_subject_organization",
        )
    if not subject.roles:
        return AuthorizationDecision(
            outcome=PolicyDecisionOutcome.DENY,
            reason="missing_subject_role",
        )
    if is_cross_tenant(subject, resource):
        return AuthorizationDecision(
            outcome=PolicyDecisionOutcome.DENY,
            reason="cross_tenant_resource",
        )

    permission = (resource.resource_type, request.action)
    for role in subject.roles:
        if permission in ROLE_PERMISSIONS.get(role, frozenset()):
            return AuthorizationDecision(
                outcome=PolicyDecisionOutcome.ALLOW,
                reason=f"allowed_by_{role.value}",
            )

    return AuthorizationDecision(
        outcome=PolicyDecisionOutcome.DENY,
        reason="missing_role_permission",
    )


def require_allowed(request: AuthorizationRequest) -> None:
    """Raise PermissionError when a request is denied."""
    decision = decide(request)
    if not decision.allowed:
        raise PermissionError(decision.reason)
