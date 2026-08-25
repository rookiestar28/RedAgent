"""Tenant-scoped durable identity repository with atomic audit/outbox writes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
import hmac
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.identity.authorization import (
    ROLE_PERMISSIONS,
    GrantState,
    assert_separation_of_duties,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import IdempotencyConflict, MutationResult


class IdentityStateConflict(RuntimeError):
    """Durable identity transition was invalid, stale, replayed, or unauthorized."""


@dataclass(frozen=True)
class IdentityPrincipal:
    user_id: str
    tenant_id: str
    roles: tuple[str, ...]
    session_id: str
    session_generation: int
    csrf_hash: str = field(repr=False)


@dataclass(frozen=True)
class ConsumedLoginTransaction:
    transaction_id: str
    provider_id: str
    tenant_id: str
    nonce_ciphertext: str = field(repr=False)
    verifier_ciphertext: str = field(repr=False)
    redirect_uri: str


@dataclass(frozen=True)
class ServicePrincipal:
    service_identity_id: str
    tenant_id: str
    client_id: str
    roles: tuple[str, ...]
    generation: int


class IdentityRepository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        self.session = session
        self.tenant_id = _required("tenant_id", tenant_id, 64)
        self.actor_user_id = _required("actor_user_id", actor_user_id, 64)
        self.correlation_id = _required("correlation_id", correlation_id, 100)

    async def provision_membership(
        self,
        *,
        user_id: str,
        roles: tuple[str, ...],
        occurred_at: datetime,
    ) -> None:
        await self._tenant_context()
        _time(occurred_at)
        normalized_user = _required("user_id", user_id, 64)
        normalized_roles = _roles(roles)
        users = metadata.tables["users"]
        if await self.session.scalar(
            select(users.c.id).where(users.c.tenant_id == self.tenant_id, users.c.id == normalized_user)
        ) is None:
            raise IdentityStateConflict("identity_user_not_found")
        memberships = metadata.tables["tenant_memberships"]
        existing = (
            await self.session.execute(
                select(memberships).where(
                    memberships.c.tenant_id == self.tenant_id,
                    memberships.c.user_id == normalized_user,
                )
            )
        ).mappings().one_or_none()
        role_or_membership_changed = existing is None or existing["status"] != "active"
        if existing is None:
            await self.session.execute(
                insert(memberships).values(
                    id=str(uuid4()),
                    tenant_id=self.tenant_id,
                    user_id=normalized_user,
                    status="active",
                    generation=1,
                    last_validated_at=occurred_at,
                    version=1,
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
            )
        else:
            changed = existing["status"] != "active"
            await self.session.execute(
                update(memberships)
                .where(memberships.c.id == existing["id"], memberships.c.tenant_id == self.tenant_id)
                .values(
                    status="active",
                    generation=memberships.c.generation + (1 if changed else 0),
                    last_validated_at=occurred_at,
                    version=memberships.c.version + 1,
                    updated_at=occurred_at,
                )
            )
        assignments = metadata.tables["role_assignments"]
        existing_roles = {
            row["role"]: row
            for row in (
                await self.session.execute(
                    select(assignments).where(
                        assignments.c.tenant_id == self.tenant_id,
                        assignments.c.user_id == normalized_user,
                    )
                )
            ).mappings()
        }
        for role, row in existing_roles.items():
            should_be_active = role in normalized_roles
            if row["active"] != should_be_active:
                role_or_membership_changed = True
                await self.session.execute(
                    update(assignments)
                    .where(assignments.c.id == row["id"], assignments.c.tenant_id == self.tenant_id)
                    .values(
                        active=should_be_active,
                        generation=assignments.c.generation + 1,
                        version=assignments.c.version + 1,
                        updated_at=occurred_at,
                    )
                )
        for role in normalized_roles:
            if role not in existing_roles:
                role_or_membership_changed = True
                await self.session.execute(
                    insert(assignments).values(
                        id=str(uuid4()),
                        tenant_id=self.tenant_id,
                        user_id=normalized_user,
                        role=role,
                        active=True,
                        generation=1,
                        version=1,
                        created_at=occurred_at,
                        updated_at=occurred_at,
                    )
                )
        if existing is not None and role_or_membership_changed:
            # CRITICAL: privilege changes invalidate existing browser sessions; callers establish a rotated session.
            await self._revoke_sessions(user_id=normalized_user, occurred_at=occurred_at)
        await self._record(
            action="identity.membership.provisioned",
            subject_type="tenant_membership",
            subject_id=normalized_user,
            details={"role_count": len(normalized_roles)},
            occurred_at=occurred_at,
        )

    async def register_provider(
        self,
        *,
        provider_id: str,
        issuer: str,
        client_id: str,
        occurred_at: datetime,
    ) -> None:
        await self._tenant_context()
        _time(occurred_at)
        providers = metadata.tables["identity_providers"]
        normalized_id = _required("provider_id", provider_id, 64)
        row_id = _stable_id(self.tenant_id, normalized_id)
        row = (
            await self.session.execute(
                select(providers).where(
                    providers.c.tenant_id == self.tenant_id,
                    providers.c.id == row_id,
                )
            )
        ).mappings().one_or_none()
        normalized_issuer = _required("issuer", issuer, 500)
        normalized_client = _required("client_id", client_id, 200)
        if row is None:
            await self.session.execute(
                insert(providers).values(
                    id=row_id,
                    tenant_id=self.tenant_id,
                    issuer=normalized_issuer,
                    client_id=normalized_client,
                    enabled=True,
                    version=1,
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
            )
            await self._record(
                action="identity.provider.registered",
                subject_type="identity_provider",
                subject_id=normalized_id,
                details={"issuer_hash": _stable_id(normalized_issuer)},
                occurred_at=occurred_at,
            )
        elif row["issuer"] != normalized_issuer or row["client_id"] != normalized_client or not row["enabled"]:
            raise IdentityStateConflict("identity_provider_config_conflict")

    async def revoke_membership(self, *, user_id: str, occurred_at: datetime) -> None:
        await self._tenant_context()
        _time(occurred_at)
        normalized_user = _required("user_id", user_id, 64)
        memberships = metadata.tables["tenant_memberships"]
        result = await self.session.execute(
            update(memberships)
            .where(
                memberships.c.tenant_id == self.tenant_id,
                memberships.c.user_id == normalized_user,
                memberships.c.status == "active",
            )
            .values(
                status="revoked",
                generation=memberships.c.generation + 1,
                version=memberships.c.version + 1,
                updated_at=occurred_at,
            )
        )
        if result.rowcount != 1:
            raise IdentityStateConflict("membership_not_active")
        await self._revoke_sessions(user_id=normalized_user, occurred_at=occurred_at)
        await self._record(
            action="identity.membership.revoked",
            subject_type="tenant_membership",
            subject_id=normalized_user,
            details={"revoked": True},
            occurred_at=occurred_at,
        )

    async def create_session(
        self,
        *,
        session_id: str,
        provider_id: str,
        user_id: str,
        handle_hash: str,
        csrf_hash: str,
        oidc_session_id: str | None,
        idle_expires_at: datetime,
        absolute_expires_at: datetime,
        occurred_at: datetime,
    ) -> None:
        await self._tenant_context()
        for value in (occurred_at, idle_expires_at, absolute_expires_at):
            _time(value)
        if not occurred_at < idle_expires_at <= absolute_expires_at:
            raise ValueError("session_lifetime_invalid")
        normalized_user = _required("user_id", user_id, 64)
        if not await self._membership_active(normalized_user):
            raise IdentityStateConflict("membership_not_active")
        sessions = metadata.tables["browser_sessions"]
        await self.session.execute(
            insert(sessions).values(
                id=_required("session_id", session_id, 64),
                tenant_id=self.tenant_id,
                provider_id=_required("provider_id", provider_id, 64),
                user_id=normalized_user,
                handle_hash=_digest("handle_hash", handle_hash),
                csrf_hash=_digest("csrf_hash", csrf_hash),
                oidc_session_id=_optional("oidc_session_id", oidc_session_id, 200),
                last_seen_at=occurred_at,
                idle_expires_at=idle_expires_at,
                absolute_expires_at=absolute_expires_at,
                revoked_at=None,
                generation=1,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self._record(
            action="identity.session.created",
            subject_type="browser_session",
            subject_id=session_id,
            details={"provider_id": provider_id, "generation": 1},
            occurred_at=occurred_at,
        )

    async def create_login_transaction(
        self,
        *,
        transaction_id: str,
        provider_id: str,
        state_hash: str,
        nonce_hash: str,
        nonce_ciphertext: str,
        verifier_ciphertext: str,
        redirect_uri: str,
        expires_at: datetime,
        occurred_at: datetime,
    ) -> None:
        await self._tenant_context()
        _time(occurred_at)
        _time(expires_at)
        if expires_at <= occurred_at:
            raise ValueError("login_transaction_expiry_invalid")
        transactions = metadata.tables["login_transactions"]
        normalized_id = _required("transaction_id", transaction_id, 64)
        await self.session.execute(
            insert(transactions).values(
                id=normalized_id,
                tenant_id=self.tenant_id,
                provider_id=_required("provider_id", provider_id, 64),
                state_hash=_digest("state_hash", state_hash),
                nonce_hash=_digest("nonce_hash", nonce_hash),
                nonce_ciphertext=_required("nonce_ciphertext", nonce_ciphertext, 4096),
                verifier_ciphertext=_required("verifier_ciphertext", verifier_ciphertext, 4096),
                redirect_uri=_required("redirect_uri", redirect_uri, 600),
                expires_at=expires_at,
                consumed_at=None,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self._record(
            action="identity.login.started",
            subject_type="login_transaction",
            subject_id=normalized_id,
            details={"provider_id": provider_id},
            occurred_at=occurred_at,
        )

    async def consume_login_transaction(
        self,
        *,
        transaction_id: str,
        state_hash: str,
        now: datetime,
    ) -> ConsumedLoginTransaction:
        await self._tenant_context()
        _time(now)
        transactions = metadata.tables["login_transactions"]
        row = (
            await self.session.execute(
                select(transactions)
                .where(
                    transactions.c.tenant_id == self.tenant_id,
                    transactions.c.id == _required("transaction_id", transaction_id, 64),
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        supplied_hash = _digest("state_hash", state_hash)
        if (
            row is None
            or not hmac.compare_digest(str(row["state_hash"]), supplied_hash)
            or row["consumed_at"] is not None
            or row["expires_at"] <= now
        ):
            raise IdentityStateConflict("login_transaction_invalid")
        result = await self.session.execute(
            update(transactions)
            .where(
                transactions.c.id == row["id"],
                transactions.c.tenant_id == self.tenant_id,
                transactions.c.version == row["version"],
                transactions.c.consumed_at.is_(None),
            )
            .values(consumed_at=now, version=transactions.c.version + 1, updated_at=now)
        )
        if result.rowcount != 1:
            raise IdentityStateConflict("login_transaction_invalid")
        await self._record(
            action="identity.login.consumed",
            subject_type="login_transaction",
            subject_id=str(row["id"]),
            details={"provider_id": str(row["provider_id"])},
            occurred_at=now,
        )
        return ConsumedLoginTransaction(
            transaction_id=str(row["id"]),
            provider_id=str(row["provider_id"]),
            tenant_id=self.tenant_id,
            nonce_ciphertext=str(row["nonce_ciphertext"]),
            verifier_ciphertext=str(row["verifier_ciphertext"]),
            redirect_uri=str(row["redirect_uri"]),
        )

    async def resolve_browser_session(self, *, handle_hash: str, now: datetime) -> IdentityPrincipal | None:
        await self._tenant_context()
        _time(now)
        sessions = metadata.tables["browser_sessions"]
        row = (
            await self.session.execute(
                select(sessions).where(
                    sessions.c.tenant_id == self.tenant_id,
                    sessions.c.handle_hash == _digest("handle_hash", handle_hash),
                    sessions.c.revoked_at.is_(None),
                    sessions.c.idle_expires_at > now,
                    sessions.c.absolute_expires_at > now,
                )
            )
        ).mappings().one_or_none()
        if row is None or not await self._membership_active(str(row["user_id"])):
            return None
        assignments = metadata.tables["role_assignments"]
        roles = tuple(
            (
                await self.session.scalars(
                    select(assignments.c.role)
                    .where(
                        assignments.c.tenant_id == self.tenant_id,
                        assignments.c.user_id == row["user_id"],
                        assignments.c.active.is_(True),
                    )
                    .order_by(assignments.c.role)
                )
            ).all()
        )
        if not roles:
            return None
        next_idle = min(now + timedelta(minutes=30), row["absolute_expires_at"])
        await self.session.execute(
            update(sessions)
            .where(sessions.c.id == row["id"], sessions.c.tenant_id == self.tenant_id)
            .values(
                last_seen_at=now,
                idle_expires_at=next_idle,
                version=sessions.c.version + 1,
                updated_at=now,
            )
        )
        return IdentityPrincipal(
            user_id=str(row["user_id"]),
            tenant_id=self.tenant_id,
            roles=roles,
            session_id=str(row["id"]),
            session_generation=int(row["generation"]),
            csrf_hash=str(row["csrf_hash"]),
        )

    async def revoke_browser_session(self, *, handle_hash: str, occurred_at: datetime) -> bool:
        await self._tenant_context()
        _time(occurred_at)
        sessions = metadata.tables["browser_sessions"]
        result = await self.session.execute(
            update(sessions)
            .where(
                sessions.c.tenant_id == self.tenant_id,
                sessions.c.handle_hash == _digest("handle_hash", handle_hash),
                sessions.c.revoked_at.is_(None),
            )
            .values(
                revoked_at=occurred_at,
                generation=sessions.c.generation + 1,
                version=sessions.c.version + 1,
                updated_at=occurred_at,
            )
        )
        if result.rowcount:
            await self._record(
                action="identity.session.revoked",
                subject_type="browser_session",
                subject_id=_stable_id(handle_hash),
                details={"revoked": True},
                occurred_at=occurred_at,
            )
        return bool(result.rowcount)

    async def revoke_sessions_for_oidc_session(
        self,
        *,
        provider_id: str,
        oidc_session_id: str,
        occurred_at: datetime,
    ) -> int:
        await self._tenant_context()
        _time(occurred_at)
        sessions = metadata.tables["browser_sessions"]
        result = await self.session.execute(
            update(sessions)
            .where(
                sessions.c.tenant_id == self.tenant_id,
                sessions.c.provider_id == _required("provider_id", provider_id, 64),
                sessions.c.oidc_session_id == _required("oidc_session_id", oidc_session_id, 200),
                sessions.c.revoked_at.is_(None),
            )
            .values(
                revoked_at=occurred_at,
                generation=sessions.c.generation + 1,
                version=sessions.c.version + 1,
                updated_at=occurred_at,
            )
        )
        await self._record(
            action="identity.session.oidc_revoked",
            subject_type="oidc_session",
            subject_id=_stable_id(provider_id, oidc_session_id),
            details={"revoked_count": int(result.rowcount or 0)},
            occurred_at=occurred_at,
        )
        return int(result.rowcount or 0)

    async def request_jit_grant(
        self,
        *,
        grant_id: str,
        requester_user_id: str,
        role: str,
        permission: str,
        scope_type: str,
        scope_id: str,
        reason: str,
        expires_at: datetime,
        break_glass: bool,
        occurred_at: datetime,
        idempotency_key: str | None = None,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        _time(expires_at)
        operation = "identity.jit.requested"
        request = {
            "actor_user_id": self.actor_user_id,
            "requester_user_id": requester_user_id,
            "grant_id": grant_id,
            "role": role,
            "permission": permission,
            "scope_type": scope_type,
            "scope_id": scope_id,
            "reason": reason,
            "expires_at": expires_at.isoformat(),
            "break_glass": bool(break_glass),
        }
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay is not None:
            return replay
        if expires_at <= occurred_at or expires_at > occurred_at + timedelta(hours=24):
            raise ValueError("jit_expiry_invalid")
        requester = _required("requester_user_id", requester_user_id, 64)
        if not await self._membership_active(requester):
            raise IdentityStateConflict("membership_not_active")
        normalized_role = _role(role)
        engagements = metadata.tables["engagements"]
        if await self.session.scalar(
            select(engagements.c.id).where(
                engagements.c.tenant_id == self.tenant_id,
                engagements.c.id == _required("scope_id", scope_id, 64),
            )
        ) is None:
            raise IdentityStateConflict("jit_scope_not_found")
        grants = metadata.tables["jit_grants"]
        await self.session.execute(
            insert(grants).values(
                id=_required("grant_id", grant_id, 64),
                tenant_id=self.tenant_id,
                requester_user_id=requester,
                approver_user_id=None,
                role=normalized_role,
                permission=_required("permission", permission, 100),
                scope_type=_required("scope_type", scope_type, 64),
                scope_id=_required("scope_id", scope_id, 64),
                reason=_required("reason", reason, 500),
                approved_at=None,
                expires_at=expires_at,
                revoked_at=None,
                break_glass=bool(break_glass),
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        audit_id, outbox_id = await self._record(
            action=operation,
            subject_type="jit_grant",
            subject_id=grant_id,
            details={"permission": permission, "scope_type": scope_type, "break_glass": bool(break_glass)},
            occurred_at=occurred_at,
        )
        resource = await self.get_jit_grant(grant_id)
        if resource is None:
            raise IdentityStateConflict("jit_grant_not_found")
        return await self._complete_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            audit_id=audit_id,
            outbox_id=outbox_id,
            occurred_at=occurred_at,
            response_status=201,
        )

    async def approve_jit_grant(
        self,
        *,
        grant_id: str,
        approver_user_id: str,
        occurred_at: datetime,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        operation = "identity.jit.approved"
        request = {
            "actor_user_id": self.actor_user_id,
            "grant_id": grant_id,
            "expected_version": expected_version,
        }
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay is not None:
            return replay
        grants = metadata.tables["jit_grants"]
        row = (
            await self.session.execute(
                select(grants).where(
                    grants.c.tenant_id == self.tenant_id,
                    grants.c.id == _required("grant_id", grant_id, 64),
                ).with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            raise IdentityStateConflict("jit_grant_not_approvable")
        if expected_version is not None and row["version"] != expected_version:
            raise IdentityStateConflict("jit_grant_version_conflict")
        if row["approved_at"] is not None or row["revoked_at"] is not None or row["expires_at"] <= occurred_at:
            raise IdentityStateConflict("jit_grant_not_approvable")
        approver = _required("approver_user_id", approver_user_id, 64)
        try:
            assert_separation_of_duties(
                requester_user_id=str(row["requester_user_id"]),
                approver_user_id=approver,
                reviewer_user_id=None,
                action="jit_approval",
            )
        except ValueError as exc:
            raise IdentityStateConflict(str(exc)) from exc
        if not await self._has_role(approver, "approver"):
            raise IdentityStateConflict("jit_approver_role_required")
        await self.session.execute(
            update(grants)
            .where(grants.c.id == row["id"], grants.c.tenant_id == self.tenant_id, grants.c.version == row["version"])
            .values(
                approver_user_id=approver,
                approved_at=occurred_at,
                version=grants.c.version + 1,
                updated_at=occurred_at,
            )
        )
        audit_id, outbox_id = await self._record(
            action=operation,
            subject_type="jit_grant",
            subject_id=grant_id,
            details={"approver_user_id": approver},
            occurred_at=occurred_at,
        )
        resource = await self.get_jit_grant(grant_id)
        if resource is None:
            raise IdentityStateConflict("jit_grant_not_found")
        return await self._complete_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            audit_id=audit_id,
            outbox_id=outbox_id,
            occurred_at=occurred_at,
        )

    async def active_grants(
        self,
        *,
        user_id: str,
        permission: str,
        object_id: str,
        now: datetime,
    ) -> tuple[GrantState, ...]:
        await self._tenant_context()
        _time(now)
        normalized_user = _required("user_id", user_id, 64)
        if not await self._membership_active(normalized_user):
            return ()
        active_roles = await self._active_roles(normalized_user)
        grants = metadata.tables["jit_grants"]
        rows = (
            await self.session.execute(
                select(grants).where(
                    grants.c.tenant_id == self.tenant_id,
                    grants.c.requester_user_id == normalized_user,
                    grants.c.permission == _required("permission", permission, 100),
                    grants.c.scope_id == _required("object_id", object_id, 64),
                    grants.c.approved_at.is_not(None),
                    grants.c.revoked_at.is_(None),
                    grants.c.expires_at > now,
                ).order_by(grants.c.expires_at, grants.c.id).limit(100)
            )
        ).mappings().all()
        result: list[GrantState] = []
        for row in rows:
            if str(row["role"]) not in active_roles:
                continue
            result.append(
                GrantState(
                    role=str(row["role"]),
                    permission=str(row["permission"]),
                    scope_type=str(row["scope_type"]),
                    scope_id=str(row["scope_id"]),
                    approved_at=row["approved_at"],
                    expires_at=row["expires_at"],
                    revoked_at=row["revoked_at"],
                )
            )
        return tuple(result)

    async def list_memberships(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._tenant_context()
        _pagination(limit, offset)
        memberships = metadata.tables["tenant_memberships"]
        assignments = metadata.tables["role_assignments"]
        rows = (
            await self.session.execute(
                select(memberships)
                .where(memberships.c.tenant_id == self.tenant_id)
                .order_by(memberships.c.created_at, memberships.c.user_id)
                .limit(limit)
                .offset(offset)
            )
        ).mappings().all()
        user_ids = [str(row["user_id"]) for row in rows]
        role_map: dict[str, list[str]] = {user_id: [] for user_id in user_ids}
        if user_ids:
            role_rows = (
                await self.session.execute(
                    select(assignments.c.user_id, assignments.c.role)
                    .where(
                        assignments.c.tenant_id == self.tenant_id,
                        assignments.c.user_id.in_(user_ids),
                        assignments.c.active.is_(True),
                    )
                    .order_by(assignments.c.user_id, assignments.c.role)
                )
            ).all()
            for user_id, role in role_rows:
                role_map[str(user_id)].append(str(role))
        return [
            {
                "user_id": str(row["user_id"]),
                "status": str(row["status"]),
                "generation": int(row["generation"]),
                "roles": role_map[str(row["user_id"])],
                "version": int(row["version"]),
            }
            for row in rows
        ]

    async def list_jit_grants(
        self,
        *,
        requester_user_id: str,
        include_all: bool,
        limit: int,
        offset: int,
    ) -> list[dict[str, object]]:
        await self._tenant_context()
        _pagination(limit, offset)
        grants = metadata.tables["jit_grants"]
        statement = select(grants).where(grants.c.tenant_id == self.tenant_id)
        if not include_all:
            statement = statement.where(
                grants.c.requester_user_id == _required("requester_user_id", requester_user_id, 64)
            )
        rows = (
            await self.session.execute(
                statement.order_by(grants.c.created_at.desc(), grants.c.id).limit(limit).offset(offset)
            )
        ).mappings().all()
        return [_public_jit_grant(row) for row in rows]

    async def get_jit_grant(self, grant_id: str) -> dict[str, object] | None:
        await self._tenant_context()
        grants = metadata.tables["jit_grants"]
        row = (
            await self.session.execute(
                select(grants).where(
                    grants.c.tenant_id == self.tenant_id,
                    grants.c.id == _required("grant_id", grant_id, 64),
                )
            )
        ).mappings().one_or_none()
        return _public_jit_grant(row) if row else None

    async def list_activity(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._tenant_context()
        _pagination(limit, offset)
        audits = metadata.tables["audit_events"]
        rows = (
            await self.session.execute(
                select(audits)
                .where(audits.c.tenant_id == self.tenant_id)
                .order_by(audits.c.created_at.desc(), audits.c.id)
                .limit(limit)
                .offset(offset)
            )
        ).mappings().all()
        return [
            {
                "event_id": str(row["id"]),
                "actor_user_id": str(row["actor_user_id"]),
                "action": str(row["action"]),
                "subject_type": str(row["subject_type"]),
                "subject_id": str(row["subject_id"]),
                "correlation_id": str(row["correlation_id"]),
                "occurred_at": row["created_at"],
            }
            for row in rows
        ]

    async def revoke_jit_grant(
        self,
        *,
        grant_id: str,
        occurred_at: datetime,
        expected_version: int | None = None,
        reason: str | None = None,
        idempotency_key: str | None = None,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        operation = "identity.jit.revoked"
        request = {
            "actor_user_id": self.actor_user_id,
            "grant_id": grant_id,
            "expected_version": expected_version,
            "reason": reason,
        }
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay is not None:
            return replay
        grants = metadata.tables["jit_grants"]
        normalized_id = _required("grant_id", grant_id, 64)
        if expected_version is not None:
            current_version = await self.session.scalar(
                select(grants.c.version).where(
                    grants.c.tenant_id == self.tenant_id,
                    grants.c.id == normalized_id,
                    grants.c.revoked_at.is_(None),
                )
            )
            if current_version != expected_version:
                raise IdentityStateConflict("jit_grant_version_conflict")
        normalized_reason = _required("revoke_reason", reason, 500) if reason is not None else None
        result = await self.session.execute(
            update(grants)
            .where(
                grants.c.tenant_id == self.tenant_id,
                grants.c.id == normalized_id,
                grants.c.revoked_at.is_(None),
            )
            .values(revoked_at=occurred_at, version=grants.c.version + 1, updated_at=occurred_at)
        )
        if result.rowcount != 1:
            raise IdentityStateConflict("jit_grant_not_active")
        audit_id, outbox_id = await self._record(
            action=operation,
            subject_type="jit_grant",
            subject_id=grant_id,
            details={
                "revoked": True,
                "reason_hash": _stable_id(normalized_reason) if normalized_reason is not None else None,
            },
            occurred_at=occurred_at,
        )
        resource = await self.get_jit_grant(grant_id)
        if resource is None:
            raise IdentityStateConflict("jit_grant_not_found")
        return await self._complete_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            audit_id=audit_id,
            outbox_id=outbox_id,
            occurred_at=occurred_at,
        )

    async def review_break_glass(
        self,
        *,
        review_id: str,
        grant_id: str,
        reviewer_user_id: str,
        outcome: str,
        occurred_at: datetime,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        operation = "identity.break_glass.reviewed"
        request = {
            "actor_user_id": self.actor_user_id,
            "review_id": review_id,
            "grant_id": grant_id,
            "outcome": outcome,
            "expected_version": expected_version,
        }
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay is not None:
            return replay
        grants = metadata.tables["jit_grants"]
        grant = (
            await self.session.execute(
                select(grants).where(grants.c.tenant_id == self.tenant_id, grants.c.id == grant_id)
            )
        ).mappings().one_or_none()
        if grant is None or not grant["break_glass"] or grant["approved_at"] is None:
            raise IdentityStateConflict("break_glass_review_not_applicable")
        if expected_version is not None and grant["version"] != expected_version:
            raise IdentityStateConflict("jit_grant_version_conflict")
        reviewer = _required("reviewer_user_id", reviewer_user_id, 64)
        try:
            assert_separation_of_duties(
                requester_user_id=str(grant["requester_user_id"]),
                approver_user_id=str(grant["approver_user_id"]),
                reviewer_user_id=reviewer,
                action="break_glass_review",
            )
        except ValueError as exc:
            raise IdentityStateConflict(str(exc)) from exc
        if not await self._has_role(reviewer, "reviewer"):
            raise IdentityStateConflict("break_glass_reviewer_role_required")
        normalized_outcome = _required("outcome", outcome, 32)
        if normalized_outcome not in {"approved", "exception", "rejected"}:
            raise ValueError("break_glass_outcome_invalid")
        reviews = metadata.tables["break_glass_reviews"]
        await self.session.execute(
            insert(reviews).values(
                id=_required("review_id", review_id, 64),
                tenant_id=self.tenant_id,
                grant_id=_required("grant_id", grant_id, 64),
                reviewer_user_id=reviewer,
                outcome=normalized_outcome,
                reviewed_at=occurred_at,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        audit_id, outbox_id = await self._record(
            action=operation,
            subject_type="jit_grant",
            subject_id=grant_id,
            details={"outcome": normalized_outcome, "reviewer_user_id": reviewer},
            occurred_at=occurred_at,
        )
        resource = await self.get_jit_grant(grant_id)
        if resource is None:
            raise IdentityStateConflict("jit_grant_not_found")
        return await self._complete_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            audit_id=audit_id,
            outbox_id=outbox_id,
            occurred_at=occurred_at,
        )

    async def consume_replay(
        self,
        *,
        replay_type: str,
        replay_key_hash: str,
        expires_at: datetime,
        occurred_at: datetime,
    ) -> bool:
        await self._tenant_context()
        _time(occurred_at)
        _time(expires_at)
        kind = _required("replay_type", replay_type, 64)
        digest = _digest("replay_key_hash", replay_key_hash)
        # CRITICAL: serialize replay checks; a read-then-insert race must never accept the same token twice.
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"),
            {"key": _lock_key(self.tenant_id, kind, digest)},
        )
        replays = metadata.tables["identity_replay_records"]
        if await self.session.scalar(
            select(replays.c.id).where(
                replays.c.tenant_id == self.tenant_id,
                replays.c.replay_type == kind,
                replays.c.replay_key_hash == digest,
            )
        ):
            raise IdentityStateConflict("identity_replay_detected")
        await self.session.execute(
            insert(replays).values(
                id=str(uuid4()),
                tenant_id=self.tenant_id,
                replay_type=kind,
                replay_key_hash=digest,
                expires_at=expires_at,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self._record(
            action="identity.replay.consumed",
            subject_type="identity_replay",
            subject_id=_stable_id(kind, digest),
            details={"replay_type": kind},
            occurred_at=occurred_at,
        )
        return True

    async def create_service_identity(
        self,
        *,
        service_identity_id: str,
        client_id: str,
        name: str,
        secret_hash: str,
        roles: tuple[str, ...],
        expires_at: datetime,
        occurred_at: datetime,
    ) -> None:
        await self._tenant_context()
        _time(occurred_at)
        _time(expires_at)
        if expires_at <= occurred_at or expires_at > occurred_at + timedelta(days=90):
            raise ValueError("service_identity_expiry_invalid")
        services = metadata.tables["service_identities"]
        normalized_id = _required("service_identity_id", service_identity_id, 64)
        await self.session.execute(
            insert(services).values(
                id=normalized_id,
                tenant_id=self.tenant_id,
                client_id=_required("client_id", client_id, 200),
                name=_required("service_identity_name", name, 200),
                secret_hash=_digest("secret_hash", secret_hash),
                roles=list(_roles(roles)),
                expires_at=expires_at,
                revoked_at=None,
                generation=1,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self._record(
            action="identity.service.created",
            subject_type="service_identity",
            subject_id=normalized_id,
            details={"role_count": len(roles)},
            occurred_at=occurred_at,
        )

    async def resolve_service_identity(
        self,
        *,
        client_id: str,
        secret_hash: str,
        now: datetime,
    ) -> ServicePrincipal | None:
        await self._tenant_context()
        _time(now)
        services = metadata.tables["service_identities"]
        row = (
            await self.session.execute(
                select(services).where(
                    services.c.tenant_id == self.tenant_id,
                    services.c.client_id == _required("client_id", client_id, 200),
                    services.c.revoked_at.is_(None),
                    services.c.expires_at > now,
                )
            )
        ).mappings().one_or_none()
        supplied = _digest("secret_hash", secret_hash)
        if row is None or not hmac.compare_digest(str(row["secret_hash"]), supplied):
            return None
        try:
            roles = _roles(tuple(row["roles"]))
        except ValueError:
            return None
        return ServicePrincipal(
            service_identity_id=str(row["id"]),
            tenant_id=self.tenant_id,
            client_id=str(row["client_id"]),
            roles=roles,
            generation=int(row["generation"]),
        )

    async def revoke_service_identity(self, *, service_identity_id: str, occurred_at: datetime) -> None:
        await self._tenant_context()
        _time(occurred_at)
        services = metadata.tables["service_identities"]
        normalized_id = _required("service_identity_id", service_identity_id, 64)
        result = await self.session.execute(
            update(services)
            .where(
                services.c.tenant_id == self.tenant_id,
                services.c.id == normalized_id,
                services.c.revoked_at.is_(None),
            )
            .values(
                revoked_at=occurred_at,
                generation=services.c.generation + 1,
                version=services.c.version + 1,
                updated_at=occurred_at,
            )
        )
        if result.rowcount != 1:
            raise IdentityStateConflict("service_identity_not_active")
        await self._record(
            action="identity.service.revoked",
            subject_type="service_identity",
            subject_id=normalized_id,
            details={"revoked": True},
            occurred_at=occurred_at,
        )

    async def _membership_active(self, user_id: str) -> bool:
        memberships = metadata.tables["tenant_memberships"]
        return bool(
            await self.session.scalar(
                select(memberships.c.id).where(
                    memberships.c.tenant_id == self.tenant_id,
                    memberships.c.user_id == user_id,
                    memberships.c.status == "active",
                )
            )
        )

    async def _has_role(self, user_id: str, role: str) -> bool:
        if not await self._membership_active(user_id):
            return False
        return role in await self._active_roles(user_id)

    async def _active_roles(self, user_id: str) -> frozenset[str]:
        assignments = metadata.tables["role_assignments"]
        return frozenset(
            (
                await self.session.scalars(
                    select(assignments.c.role).where(
                        assignments.c.tenant_id == self.tenant_id,
                        assignments.c.user_id == user_id,
                        assignments.c.active.is_(True),
                    )
                )
            ).all()
        )

    async def _revoke_sessions(self, *, user_id: str, occurred_at: datetime) -> int:
        sessions = metadata.tables["browser_sessions"]
        result = await self.session.execute(
            update(sessions)
            .where(
                sessions.c.tenant_id == self.tenant_id,
                sessions.c.user_id == user_id,
                sessions.c.revoked_at.is_(None),
            )
            .values(
                revoked_at=occurred_at,
                generation=sessions.c.generation + 1,
                version=sessions.c.version + 1,
                updated_at=occurred_at,
            )
        )
        return int(result.rowcount or 0)

    async def _tenant_context(self) -> None:
        # CRITICAL: tenant identity is always a bound value and transaction-local for FORCE RLS.
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )

    async def _record(
        self,
        *,
        action: str,
        subject_type: str,
        subject_id: str,
        details: dict[str, object],
        occurred_at: datetime,
    ) -> tuple[str, str]:
        audits = metadata.tables["audit_events"]
        outbox = metadata.tables["outbox_events"]
        audit_id = str(uuid4())
        outbox_id = str(uuid4())
        await self.session.execute(
            insert(audits).values(
                id=audit_id,
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=action,
                subject_type=subject_type,
                subject_id=subject_id,
                correlation_id=self.correlation_id,
                details=details,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self.session.execute(
            insert(outbox).values(
                id=outbox_id,
                tenant_id=self.tenant_id,
                event_type=action,
                aggregate_id=subject_id,
                payload={"subject_type": subject_type, "subject_id": subject_id},
                published=False,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return audit_id, outbox_id

    async def _idempotency_replay(
        self,
        operation: str,
        idempotency_key: str | None,
        request: dict[str, object],
    ) -> MutationResult | None:
        if idempotency_key is None:
            return None
        key = _required("idempotency_key", idempotency_key, 200)
        request_hash = _hash(request)
        # CRITICAL: serialize identity mutations before read/write so concurrent retries cannot duplicate access changes.
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": _lock_key(self.tenant_id, operation, key)},
        )
        table = metadata.tables["idempotency_records"]
        row = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.operation == operation,
                    table.c.idempotency_key == key,
                )
            )
        ).mappings().one_or_none()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise IdempotencyConflict("idempotency_key_request_mismatch")
        response = row["response_body"]
        return MutationResult(
            resource=dict(response["resource"]),
            replayed=True,
            audit_id=str(response["audit_id"]),
            outbox_id=str(response["outbox_id"]),
        )

    async def _complete_mutation(
        self,
        *,
        operation: str,
        idempotency_key: str | None,
        request: dict[str, object],
        resource: dict[str, object],
        audit_id: str,
        outbox_id: str,
        occurred_at: datetime,
        response_status: int = 200,
    ) -> MutationResult:
        result = MutationResult(
            resource=resource,
            replayed=False,
            audit_id=audit_id,
            outbox_id=outbox_id,
        )
        if idempotency_key is None:
            return result
        table = metadata.tables["idempotency_records"]
        await self.session.execute(
            insert(table).values(
                id=str(uuid4()),
                tenant_id=self.tenant_id,
                operation=operation,
                idempotency_key=_required("idempotency_key", idempotency_key, 200),
                request_hash=_hash(request),
                response_status=response_status,
                response_body={
                    "resource": _json_safe(resource),
                    "audit_id": audit_id,
                    "outbox_id": outbox_id,
                },
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return result


def _required(name: str, value: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name}_invalid")
    return value


def _optional(name: str, value: str | None, maximum: int) -> str | None:
    return None if value is None else _required(name, value, maximum)


def _digest(name: str, value: str) -> str:
    normalized = _required(name, value, 128)
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError(f"{name}_invalid")
    return normalized


def _role(value: str) -> str:
    normalized = _required("role", value, 64)
    if normalized not in ROLE_PERMISSIONS:
        raise ValueError("role_invalid")
    return normalized


def _roles(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) > 10:
        raise ValueError("roles_invalid")
    normalized = tuple(_role(value) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError("roles_duplicate")
    return tuple(sorted(normalized))


def _time(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _pagination(limit: int, offset: int) -> None:
    # IMPORTANT: 501 is reserved for the API's bounded one-row continuation probe.
    if (
        isinstance(limit, bool)
        or isinstance(offset, bool)
        or not 1 <= limit <= 501
        or not 0 <= offset <= 100_000
    ):
        raise ValueError("pagination_invalid")


def _public_jit_grant(row) -> dict[str, object]:
    return {
        "grant_id": str(row["id"]),
        "requester_user_id": str(row["requester_user_id"]),
        "approver_user_id": str(row["approver_user_id"]) if row["approver_user_id"] else None,
        "role": str(row["role"]),
        "permission": str(row["permission"]),
        "scope_type": str(row["scope_type"]),
        "scope_id": str(row["scope_id"]),
        "reason": str(row["reason"]),
        "approved_at": row["approved_at"],
        "expires_at": row["expires_at"],
        "revoked_at": row["revoked_at"],
        "break_glass": bool(row["break_glass"]),
        "version": int(row["version"]),
    }


def _lock_key(*values: str) -> int:
    digest = hashlib.sha256("\x1f".join(values).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _json_safe(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _stable_id(*values: str) -> str:
    return hashlib.sha256("\x1f".join(values).encode("utf-8")).hexdigest()[:64]
