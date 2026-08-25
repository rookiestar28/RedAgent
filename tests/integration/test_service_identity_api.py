from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.identity.bff import IdentityRuntime
from redagent_platform.identity.config import OidcProviderConfig
from redagent_platform.identity.repository import IdentityRepository
from redagent_platform.identity.session_security import SessionCipher
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.now(timezone.utc).replace(microsecond=0)


class UnusedOidcTransport:
    async def discover(self, config):
        raise AssertionError("service identity authentication must not contact the OIDC provider")

    async def exchange_code(self, config, metadata, *, code, code_verifier):
        raise AssertionError("service identity authentication must not exchange an OIDC code")

    async def jwks(self, config, metadata):
        raise AssertionError("service identity authentication must not fetch OIDC keys")


def test_service_identity_authenticates_without_browser_csrf_and_revocation_is_immediate() -> None:
    asyncio.run(_service_scenario())


async def _service_scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    suffix = uuid4().hex
    tenant_id = f"tenant-service-{suffix}"
    client_id = f"automation-{suffix}"
    raw_secret = f"synthetic-service-secret-{suffix}"
    provider = _provider()
    runtime = IdentityRuntime(
        config=provider,
        cipher=SessionCipher(bytes(reversed(range(32)))),
        transport=UnusedOidcTransport(),
        public_origin="https://redagent.example.test",
        now=lambda: NOW,
    )
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    service_id = f"service-{suffix}"
    try:
        async with sessions() as session, session.begin():
            core = ControlPlaneRepository(
                session, tenant_id=tenant_id, actor_user_id="bootstrap", correlation_id=f"bootstrap-{suffix}"
            )
            await core.bootstrap_tenant(name="Service tenant", occurred_at=NOW)
            await core.create_engagement(
                engagement_id=f"engagement-{suffix}",
                name="Service-readable engagement",
                owner_user_id="bootstrap",
                idempotency_key=f"engagement-{suffix}",
                occurred_at=NOW,
            )
            await IdentityRepository(
                session, tenant_id=tenant_id, actor_user_id="bootstrap", correlation_id=f"service-{suffix}"
            ).create_service_identity(
                service_identity_id=service_id,
                client_id=client_id,
                name="Synthetic automation",
                secret_hash=runtime.service_secret_hash(
                    tenant_id=tenant_id, client_id=client_id, secret=raw_secret
                ),
                roles=("operator",),
                expires_at=NOW + timedelta(hours=1),
                occurred_at=NOW,
            )
        app = create_app(database_settings=settings, identity_runtime=runtime)
        headers = {
            "X-RedAgent-Service-Tenant": tenant_id,
            "X-RedAgent-Service-Client": client_id,
            "X-RedAgent-Service-Secret": raw_secret,
        }
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                base_url="https://redagent.example.test",
            ) as client:
                allowed = await client.get("/api/v1/engagements", headers=headers)
                assert allowed.status_code == 200
                assert allowed.json()["data"][0]["engagement_id"] == f"engagement-{suffix}"
                wrong = await client.get(
                    "/api/v1/engagements",
                    headers={**headers, "X-RedAgent-Service-Secret": raw_secret[::-1]},
                )
                assert wrong.status_code == 401
                async with sessions() as session, session.begin():
                    await IdentityRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id="bootstrap",
                        correlation_id=f"revoke-{suffix}",
                    ).revoke_service_identity(service_identity_id=service_id, occurred_at=NOW + timedelta(minutes=1))
                revoked = await client.get("/api/v1/engagements", headers=headers)
                assert revoked.status_code == 401
                assert raw_secret not in revoked.text
    finally:
        await engine.dispose()


def _provider() -> OidcProviderConfig:
    return OidcProviderConfig(
        provider_id="synthetic",
        issuer="https://idp.example.test",
        discovery_url="https://idp.example.test/.well-known/openid-configuration",
        client_id="redagent-bff",
        audience="redagent-bff",
        redirect_uri="https://redagent.example.test/auth/callback",
        post_logout_redirect_uri="https://redagent.example.test/auth/logged-out",
        allowed_algorithms=("RS256",),
        scopes=("openid",),
        tenant_claim="redagent_tenant",
        roles_claim_path=("realm_access", "roles"),
        token_endpoint_auth_method="none",
        clock_skew_seconds=30,
        http_timeout_seconds=5,
    )
