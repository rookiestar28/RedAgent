from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.identity.repository import IdentityRepository
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]


def test_console_jit_api_is_idempotent_separated_versioned_and_tenant_scoped() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex
    tenant_id = f"tenant-r095-{suffix}"
    other_tenant = f"tenant-r095-other-{suffix}"
    operator = f"operator-{suffix}"
    approver = f"approver-{suffix}"
    reviewer = f"reviewer-{suffix}"
    other_operator = f"other-operator-{suffix}"
    other_approver = f"other-approver-{suffix}"
    other_reviewer = f"other-reviewer-{suffix}"
    grant_id = f"grant-{suffix}"
    engagement_id = f"engagement-{suffix}"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        for current_tenant in (tenant_id, other_tenant):
            current_users = (operator, approver, reviewer) if current_tenant == tenant_id else (
                other_operator,
                other_approver,
                other_reviewer,
            )
            async with sessions() as session, session.begin():
                core = ControlPlaneRepository(
                    session,
                    tenant_id=current_tenant,
                    actor_user_id="bootstrap",
                    correlation_id=f"bootstrap-{suffix}",
                )
                await core.bootstrap_tenant(name="compat_095 synthetic tenant", occurred_at=now)
                for user_id in current_users:
                    await core.bootstrap_user(
                        user_id=user_id,
                        subject=f"oidc:{current_tenant}:{user_id}",
                        occurred_at=now,
                    )
                if current_tenant == tenant_id:
                    await core.create_engagement(
                        engagement_id=engagement_id,
                        name="compat_095 bounded engagement",
                        owner_user_id=operator,
                        idempotency_key=f"bootstrap-engagement-{suffix}",
                        occurred_at=now,
                    )
                identity = IdentityRepository(
                    session,
                    tenant_id=current_tenant,
                    actor_user_id="bootstrap",
                    correlation_id=f"membership-{suffix}",
                )
                await identity.provision_membership(
                    user_id=current_users[0], roles=("operator",), occurred_at=now
                )
                await identity.provision_membership(
                    user_id=current_users[1], roles=("approver",), occurred_at=now
                )
                await identity.provision_membership(
                    user_id=current_users[2], roles=("reviewer",), occurred_at=now
                )

        app = create_app(test_issuer_enabled=True, database_settings=settings)
        operator_headers = _headers(
            tenant_id, operator, "jit:request,jit:read", f"request-{suffix}"
        )
        payload = {
            "grant_id": grant_id,
            "role": "operator",
            "permission": "engagement:update",
            "scope_type": "engagement",
            "scope_id": engagement_id,
            "reason": "Bounded synthetic console verification",
            "expires_at": (now + timedelta(minutes=15)).isoformat(),
            "break_glass": False,
        }
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                base_url="http://testserver",
            ) as client:
                created = await client.post("/api/v1/jit-grants", headers=operator_headers, json=payload)
                assert created.status_code == 201
                assert created.json()["meta"]["replayed"] is False
                assert created.json()["data"]["version"] == 1

                replayed = await client.post("/api/v1/jit-grants", headers=operator_headers, json=payload)
                assert replayed.status_code == 201
                assert replayed.json()["meta"]["replayed"] is True
                assert replayed.json()["meta"]["audit_id"] == created.json()["meta"]["audit_id"]

                mismatch = await client.post(
                    "/api/v1/jit-grants",
                    headers=operator_headers,
                    json={**payload, "reason": "A different bounded synthetic reason"},
                )
                assert mismatch.status_code == 409
                assert mismatch.json()["error"]["code"] == "idempotency_conflict"

                self_approval = await client.post(
                    f"/api/v1/jit-grants/{grant_id}/approve",
                    headers=_headers(
                        tenant_id, operator, "jit:approve", f"self-approve-{suffix}"
                    ),
                    json={"expected_version": 1},
                )
                assert self_approval.status_code == 409
                assert self_approval.json()["error"]["code"] == "identity_state_conflict"

                approval_headers = _headers(
                    tenant_id, approver, "jit:approve,jit:read", f"approve-{suffix}"
                )
                approved = await client.post(
                    f"/api/v1/jit-grants/{grant_id}/approve",
                    headers=approval_headers,
                    json={"expected_version": 1},
                )
                assert approved.status_code == 200
                assert approved.json()["data"]["version"] == 2
                assert approved.json()["meta"]["replayed"] is False

                approval_replay = await client.post(
                    f"/api/v1/jit-grants/{grant_id}/approve",
                    headers=approval_headers,
                    json={"expected_version": 1},
                )
                assert approval_replay.status_code == 200
                assert approval_replay.json()["meta"]["replayed"] is True

                stale = await client.post(
                    f"/api/v1/jit-grants/{grant_id}/approve",
                    headers=_headers(
                        tenant_id, approver, "jit:approve", f"stale-{suffix}"
                    ),
                    json={"expected_version": 1},
                )
                assert stale.status_code == 409
                assert stale.json()["error"]["code"] == "version_conflict"

                cross_tenant = await client.post(
                    f"/api/v1/jit-grants/{grant_id}/approve",
                    headers=_headers(
                        other_tenant, other_approver, "jit:approve", f"cross-{suffix}"
                    ),
                    json={"expected_version": 1},
                )
                assert cross_tenant.status_code in {404, 409}
                assert grant_id not in cross_tenant.text

        async with sessions() as session, session.begin():
            assert await _count(session, "idempotency_records", tenant_id, "identity.jit") == 2
            assert await _count(session, "audit_events", tenant_id, "identity.jit") == 2
            assert await _count(session, "outbox_events", tenant_id, "identity.jit") == 2
    finally:
        await engine.dispose()


def _headers(
    tenant_id: str, subject: str, permissions: str, idempotency_key: str
) -> dict[str, str]:
    return {
        "X-RedAgent-Test-Subject": subject,
        "X-RedAgent-Test-Tenant": tenant_id,
        "X-RedAgent-Test-Permissions": permissions,
        "X-RedAgent-Policy-Reference": "identity-policy:1",
        "Idempotency-Key": idempotency_key,
    }


async def _count(session, table_name: str, tenant_id: str, prefix: str) -> int:
    table = metadata.tables[table_name]
    action = table.c.action if table_name == "audit_events" else (
        table.c.event_type if table_name == "outbox_events" else table.c.operation
    )
    value = await session.scalar(
        select(func.count()).select_from(table).where(
            table.c.tenant_id == tenant_id,
            action.startswith(prefix),
        )
    )
    return int(value or 0)
