from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import UniqueConstraint

from redagent_platform.identity.authorization import (
    AuthorizationError,
    GrantState,
    ROLE_PERMISSIONS,
    assert_separation_of_duties,
    authorize_permission,
)
from redagent_platform.persistence.models import metadata


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)
IDENTITY_TABLES = {
    "identity_providers",
    "tenant_memberships",
    "role_assignments",
    "login_transactions",
    "browser_sessions",
    "identity_replay_records",
    "jit_grants",
    "break_glass_reviews",
    "service_identities",
}


def test_identity_schema_inventory_has_tenant_ownership_and_revocation_state() -> None:
    assert IDENTITY_TABLES <= set(metadata.tables)
    for name in IDENTITY_TABLES:
        columns = metadata.tables[name].columns
        assert {"tenant_id", "version", "created_at", "updated_at"} <= set(columns.keys())

    assert {"handle_hash", "csrf_hash", "idle_expires_at", "absolute_expires_at", "revoked_at"} <= set(
        metadata.tables["browser_sessions"].columns.keys()
    )
    assert {"state_hash", "nonce_hash", "nonce_ciphertext", "verifier_ciphertext", "consumed_at"} <= set(
        metadata.tables["login_transactions"].columns.keys()
    )
    assert {"secret_hash", "expires_at", "revoked_at", "generation"} <= set(
        metadata.tables["service_identities"].columns.keys()
    )
    assert {"requester_user_id", "approver_user_id", "scope_type", "scope_id", "expires_at", "revoked_at"} <= set(
        metadata.tables["jit_grants"].columns.keys()
    )
    for table_name, column_name in (
        ("tenant_memberships", "user_id"),
        ("role_assignments", "user_id"),
        ("browser_sessions", "user_id"),
        ("jit_grants", "requester_user_id"),
        ("jit_grants", "approver_user_id"),
        ("break_glass_reviews", "reviewer_user_id"),
    ):
        assert metadata.tables[table_name].c[column_name].foreign_keys


def test_identity_replay_and_principal_mappings_have_database_uniqueness() -> None:
    assert _has_unique(metadata.tables["identity_replay_records"], {"tenant_id", "replay_type", "replay_key_hash"})
    assert _has_unique(metadata.tables["tenant_memberships"], {"tenant_id", "user_id"})
    assert _has_unique(metadata.tables["role_assignments"], {"tenant_id", "user_id", "role"})
    assert _has_unique(metadata.tables["service_identities"], {"tenant_id", "client_id"})


def test_durable_role_permissions_deny_unknown_roles_and_require_jit_for_elevated_action() -> None:
    assert authorize_permission(
        roles=("operator",), permission="engagement:read", now=NOW, object_id="engagement-1"
    )
    assert not authorize_permission(
        roles=("unknown",), permission="engagement:read", now=NOW, object_id="engagement-1"
    )
    assert not authorize_permission(
        roles=("operator",), permission="job:execute", now=NOW, object_id="engagement-1"
    )
    grant = GrantState(
        role="operator",
        permission="job:execute",
        scope_type="engagement",
        scope_id="engagement-1",
        approved_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
        revoked_at=None,
    )
    assert authorize_permission(
        roles=("operator",), permission="job:execute", now=NOW, object_id="engagement-1", grants=(grant,)
    )
    assert not authorize_permission(
        roles=("operator",),
        permission="job:execute",
        now=NOW + timedelta(minutes=11),
        object_id="engagement-1",
        grants=(grant,),
    )


def test_r124_production_roles_expose_inspection_and_safety_recovery_permissions() -> None:
    assert {"campaign:read", "campaign:create", "campaign:inspect", "campaign:stop"}.issubset(
        ROLE_PERMISSIONS["operator"]
    )
    assert {"campaign:read", "campaign:inspect"}.issubset(ROLE_PERMISSIONS["approver"])
    assert {"campaign:read", "campaign:inspect"}.issubset(ROLE_PERMISSIONS["reviewer"])
    assert {"campaign:read", "campaign:inspect", "campaign:stop"}.issubset(
        ROLE_PERMISSIONS["tenant_admin"]
    )


@pytest.mark.parametrize(
    ("requester", "approver", "reviewer", "action"),
    [
        ("user-1", "user-1", "user-2", "jit_approval"),
        ("user-1", "user-2", "user-1", "break_glass_review"),
        ("user-1", "user-2", "user-2", "break_glass_review"),
    ],
)
def test_separation_of_duties_denies_self_or_non_independent_approval(
    requester: str, approver: str, reviewer: str, action: str
) -> None:
    with pytest.raises(AuthorizationError, match="separation_of_duties_required"):
        assert_separation_of_duties(
            requester_user_id=requester,
            approver_user_id=approver,
            reviewer_user_id=reviewer,
            action=action,
        )


def _has_unique(table, columns: set[str]) -> bool:
    return any(
        isinstance(constraint, UniqueConstraint) and {column.name for column in constraint.columns} == columns
        for constraint in table.constraints
    )
