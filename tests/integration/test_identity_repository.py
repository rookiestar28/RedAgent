from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.identity.repository import IdentityRepository, IdentityStateConflict
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 13, 0, tzinfo=timezone.utc)


def test_membership_session_jit_break_glass_replay_and_service_identity_are_durable_and_revocable() -> None:
    asyncio.run(_identity_lifecycle())


def test_identity_force_rls_denies_default_and_isolates_non_owner_role() -> None:
    asyncio.run(_identity_rls())


async def _identity_lifecycle() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-identity-{suffix}"
    requester = f"requester-{suffix}"
    approver = f"approver-{suffix}"
    reviewer = f"reviewer-{suffix}"
    grant_id = f"grant-{suffix}"
    session_hash = "a" * 64
    try:
        async with sessions() as session, session.begin():
            core = ControlPlaneRepository(
                session, tenant_id=tenant_id, actor_user_id=requester, correlation_id=f"bootstrap-{suffix}"
            )
            await core.bootstrap_tenant(name="Identity Tenant", occurred_at=NOW)
            for user_id in (requester, approver, reviewer):
                await core.bootstrap_user(user_id=user_id, subject=f"oidc:{user_id}", occurred_at=NOW)
            await core.create_engagement(
                engagement_id=f"engagement-{suffix}",
                name="Identity lifecycle scope",
                owner_user_id=requester,
                idempotency_key=f"identity-engagement-{suffix}",
                occurred_at=NOW,
            )
            repo = IdentityRepository(
                session, tenant_id=tenant_id, actor_user_id=requester, correlation_id=f"identity-{suffix}"
            )
            await repo.provision_membership(user_id=requester, roles=("operator",), occurred_at=NOW)
            await repo.provision_membership(user_id=approver, roles=("approver",), occurred_at=NOW)
            await repo.provision_membership(user_id=reviewer, roles=("reviewer",), occurred_at=NOW)
            await repo.create_session(
                session_id=f"session-{suffix}",
                provider_id="fixture",
                user_id=requester,
                handle_hash=session_hash,
                csrf_hash="b" * 64,
                oidc_session_id=f"sid-{suffix}",
                idle_expires_at=NOW + timedelta(minutes=30),
                absolute_expires_at=NOW + timedelta(hours=8),
                occurred_at=NOW,
            )
            await repo.request_jit_grant(
                grant_id=grant_id,
                requester_user_id=requester,
                role="operator",
                permission="job:execute",
                scope_type="engagement",
                scope_id=f"engagement-{suffix}",
                reason="Synthetic controlled execution",
                expires_at=NOW + timedelta(minutes=15),
                break_glass=True,
                occurred_at=NOW,
            )

        async with sessions() as session, session.begin():
            repo = IdentityRepository(
                session, tenant_id=tenant_id, actor_user_id=requester, correlation_id=f"self-{suffix}"
            )
            with pytest.raises(IdentityStateConflict, match="separation_of_duties_required"):
                await repo.approve_jit_grant(grant_id=grant_id, approver_user_id=requester, occurred_at=NOW)

        async with sessions() as session, session.begin():
            repo = IdentityRepository(
                session, tenant_id=tenant_id, actor_user_id=approver, correlation_id=f"approve-{suffix}"
            )
            await repo.approve_jit_grant(grant_id=grant_id, approver_user_id=approver, occurred_at=NOW)

        async with sessions() as session, session.begin():
            repo = IdentityRepository(
                session, tenant_id=tenant_id, actor_user_id=requester, correlation_id=f"resolve-{suffix}"
            )
            principal = await repo.resolve_browser_session(handle_hash=session_hash, now=NOW + timedelta(minutes=1))
            assert principal is not None
            assert principal.user_id == requester
            assert principal.roles == ("operator",)
            grants = await repo.active_grants(
                user_id=requester,
                permission="job:execute",
                object_id=f"engagement-{suffix}",
                now=NOW + timedelta(minutes=1),
            )
            assert len(grants) == 1
            assert await repo.consume_replay(
                replay_type="logout_jti",
                replay_key_hash="c" * 64,
                expires_at=NOW + timedelta(minutes=10),
                occurred_at=NOW,
            )
            with pytest.raises(IdentityStateConflict, match="identity_replay_detected"):
                await repo.consume_replay(
                    replay_type="logout_jti",
                    replay_key_hash="c" * 64,
                    expires_at=NOW + timedelta(minutes=10),
                    occurred_at=NOW,
                )
            await repo.create_service_identity(
                service_identity_id=f"service-{suffix}",
                client_id=f"client-{suffix}",
                name="Synthetic automation",
                secret_hash="d" * 64,
                roles=("operator",),
                expires_at=NOW + timedelta(hours=1),
                occurred_at=NOW,
            )

        async with sessions() as session, session.begin():
            repo = IdentityRepository(
                session, tenant_id=tenant_id, actor_user_id=reviewer, correlation_id=f"review-{suffix}"
            )
            await repo.review_break_glass(
                review_id=f"review-{suffix}",
                grant_id=grant_id,
                reviewer_user_id=reviewer,
                outcome="approved",
                occurred_at=NOW + timedelta(minutes=2),
            )
            service = await repo.resolve_service_identity(
                client_id=f"client-{suffix}", secret_hash="d" * 64, now=NOW + timedelta(minutes=2)
            )
            assert service is not None and service.roles == ("operator",)
            assert await repo.resolve_service_identity(
                client_id=f"client-{suffix}", secret_hash="e" * 64, now=NOW + timedelta(minutes=2)
            ) is None
            await repo.revoke_service_identity(
                service_identity_id=f"service-{suffix}", occurred_at=NOW + timedelta(minutes=3)
            )
            await repo.revoke_jit_grant(grant_id=grant_id, occurred_at=NOW + timedelta(minutes=3))
            await repo.revoke_sessions_for_oidc_session(
                provider_id="fixture", oidc_session_id=f"sid-{suffix}", occurred_at=NOW + timedelta(minutes=3)
            )

        async with sessions() as session, session.begin():
            repo = IdentityRepository(
                session, tenant_id=tenant_id, actor_user_id=requester, correlation_id=f"verify-{suffix}"
            )
            assert await repo.resolve_browser_session(handle_hash=session_hash, now=NOW + timedelta(minutes=4)) is None
            assert await repo.active_grants(
                user_id=requester,
                permission="job:execute",
                object_id=f"engagement-{suffix}",
                now=NOW + timedelta(minutes=4),
            ) == ()
            assert await repo.resolve_service_identity(
                client_id=f"client-{suffix}", secret_hash="d" * 64, now=NOW + timedelta(minutes=4)
            ) is None
            assert await _count(session, "break_glass_reviews", tenant_id) == 1
            assert await _count(session, "audit_events", tenant_id) >= 10
            assert await _count(session, "outbox_events", tenant_id) >= 10
    finally:
        await engine.dispose()


async def _identity_rls() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    first = f"tenant-rls-id-a-{suffix}"
    second = f"tenant-rls-id-b-{suffix}"
    role_name = f"r094_test_{suffix}"
    try:
        for tenant_id, marker in ((first, "a"), (second, "b")):
            async with sessions() as session, session.begin():
                core = ControlPlaneRepository(
                    session, tenant_id=tenant_id, actor_user_id=f"user-{marker}-{suffix}", correlation_id="bootstrap"
                )
                await core.bootstrap_tenant(name=f"Tenant {marker}", occurred_at=NOW)
                await core.bootstrap_user(
                    user_id=f"user-{marker}-{suffix}", subject=f"subject-{marker}-{suffix}", occurred_at=NOW
                )
                repo = IdentityRepository(
                    session, tenant_id=tenant_id, actor_user_id=f"user-{marker}-{suffix}", correlation_id="identity"
                )
                await repo.provision_membership(
                    user_id=f"user-{marker}-{suffix}", roles=("operator",), occurred_at=NOW
                )
        async with sessions() as session:
            transaction = await session.begin()
            try:
                await session.execute(
                    text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS')
                )
                await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
                await session.execute(text(f'GRANT SELECT ON tenant_memberships TO "{role_name}"'))
                owner = await session.scalar(
                    text("SELECT tableowner FROM pg_tables WHERE schemaname='public' AND tablename='tenant_memberships'")
                )
                bypass = await session.scalar(text("SELECT rolbypassrls FROM pg_roles WHERE rolname=:role"), {"role": role_name})
                await session.execute(text(f'SET LOCAL ROLE "{role_name}"'))
                memberships = metadata.tables["tenant_memberships"]
                assert await session.scalar(select(func.count()).select_from(memberships)) == 0
                await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": first})
                visible = tuple((await session.scalars(select(memberships.c.user_id))).all())
                assert visible == (f"user-a-{suffix}",)
                assert owner != role_name
                assert bypass is False
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


def _database():
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _count(session, table_name: str, tenant_id: str) -> int:
    table = metadata.tables[table_name]
    value = await session.scalar(select(func.count()).select_from(table).where(table.c.tenant_id == tenant_id))
    return int(value or 0)
