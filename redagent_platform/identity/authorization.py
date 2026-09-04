"""Deterministic durable-role, JIT-scope, and separation-of-duty policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable


class AuthorizationError(ValueError):
    """Raised when an authorization-state transition violates a hard invariant."""


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "operator": frozenset(
        {
            "engagement:read",
            "engagement:create",
            "engagement:update",
            "target:read",
            "target:create",
            "roe:read",
            "roe:create",
            "job:read",
            "job:create",
            "job:update",
            "job:stop",
            "runner:read",
            "campaign:read",
            "campaign:create",
            "campaign:admit",
            "campaign:inspect",
            "campaign:stop",
            "finding:ingest",
            "finding:read",
            "finding:comment",
            "finding:retest",
            "jit:read",
            "jit:request",
        }
    ),
    "approver": frozenset(
        {
            "engagement:read",
            "roe:read",
            "roe:approve",
            "job:read",
            "job:approve",
            "report:publish",
            "runner:read",
            "campaign:read",
            "campaign:inspect",
            "campaign:approve",
            "jit:read",
            "jit:approve",
        }
    ),
    "reviewer": frozenset(
        {"engagement:read", "roe:read", "audit:read", "jit:read", "jit:review", "break_glass:review", "runner:read",
         "campaign:read", "campaign:inspect", "campaign:evidence-export",
         "finding:read", "finding:review", "report:create", "report:review"}
    ),
    "tenant_admin": frozenset(
        {
            "engagement:read",
            "identity:manage",
            "membership:manage",
            "membership:read",
            "jit:read",
            "jit:revoke",
            "audit:read",
            "service_identity:manage",
            "session:revoke",
            "job:read",
            "job:stop",
            "runner:read",
            "campaign:read",
            "campaign:inspect",
            "campaign:stop",
            "campaign:evidence-export",
            "finding:read",
            "connector:deliver",
            "connector:manage",
            "report:publish",
        }
    ),
}
JIT_ONLY_PERMISSIONS = frozenset({"job:execute", "break_glass:execute"})


@dataclass(frozen=True)
class GrantState:
    role: str
    permission: str
    scope_type: str
    scope_id: str
    approved_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


def authorize_permission(
    *,
    roles: Iterable[str],
    permission: str,
    now: datetime,
    object_id: str | None,
    grants: Iterable[GrantState] = (),
) -> bool:
    """Deny by default; direct roles and active object-scoped grants are additive only."""

    normalized_roles = frozenset(roles)
    if not normalized_roles or any(role not in ROLE_PERMISSIONS for role in normalized_roles):
        return False
    if permission not in JIT_ONLY_PERMISSIONS and any(
        permission in ROLE_PERMISSIONS[role] for role in normalized_roles
    ):
        return True
    if object_id is None:
        return False
    for grant in grants:
        if (
            grant.role in normalized_roles
            and grant.permission == permission
            and grant.scope_type == "engagement"
            and grant.scope_id == object_id
            and grant.revoked_at is None
            and _aware(grant.approved_at)
            and _aware(grant.expires_at)
            and grant.approved_at <= now < grant.expires_at
        ):
            return True
    return False


def assert_separation_of_duties(
    *,
    requester_user_id: str,
    approver_user_id: str,
    reviewer_user_id: str | None,
    action: str,
) -> None:
    identities = (requester_user_id, approver_user_id)
    if any(not isinstance(value, str) or not value.strip() for value in identities):
        raise AuthorizationError("identity_required")
    if action == "jit_approval":
        if requester_user_id == approver_user_id:
            raise AuthorizationError("separation_of_duties_required")
        return
    if action == "break_glass_review":
        if (
            not isinstance(reviewer_user_id, str)
            or not reviewer_user_id.strip()
            or reviewer_user_id in {requester_user_id, approver_user_id}
        ):
            raise AuthorizationError("separation_of_duties_required")
        return
    raise AuthorizationError("separation_action_invalid")


def _aware(value: datetime) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None
