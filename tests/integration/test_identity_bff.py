from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import cast, select, String
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.app import create_app
from redagent_platform.identity.bff import IdentityRuntime, OidcProviderMetadata
from redagent_platform.identity.config import OidcProviderConfig
from redagent_platform.identity.session_security import SessionCipher
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.now(timezone.utc).replace(microsecond=0)


class SyntheticOidcTransport:
    def __init__(self, config: OidcProviderConfig) -> None:
        self.config = config
        self.key = RSAKey.generate_key(parameters={"kid": "fixture-key", "use": "sig"})
        self.nonce: str | None = None
        self.sid = "synthetic-idp-session"
        self.last_id_token: str | None = None

    async def discover(self, config: OidcProviderConfig) -> OidcProviderMetadata:
        return OidcProviderMetadata(
            issuer=config.issuer,
            authorization_endpoint=f"{config.issuer}/authorize",
            token_endpoint=f"{config.issuer}/token",
            jwks_uri=f"{config.issuer}/jwks",
            end_session_endpoint=f"{config.issuer}/logout",
        )

    async def exchange_code(
        self,
        config: OidcProviderConfig,
        metadata: OidcProviderMetadata,
        *,
        code: str,
        code_verifier: str,
    ) -> dict[str, object]:
        assert code == "synthetic-code"
        assert len(code_verifier) >= 43
        now_ts = int(NOW.timestamp())
        self.last_id_token = jwt.encode(
            {"alg": "RS256", "kid": "fixture-key"},
            {
                "iss": config.issuer,
                "sub": "enterprise-subject",
                "aud": config.audience,
                "exp": now_ts + 300,
                "iat": now_ts,
                "nonce": self.nonce,
                "sid": self.sid,
                "redagent_tenant": TENANT_ID,
                "realm_access": {"roles": ["redagent-operator"]},
                "synthetic_canary": "must-not-persist",
            },
            self.key,
            algorithms=["RS256"],
        )
        return {
            "id_token": self.last_id_token,
            "access_token": "access-token-must-be-discarded",
            "refresh_token": "refresh-token-must-be-discarded",
            "token_type": "Bearer",
        }

    async def jwks(self, config: OidcProviderConfig, metadata: OidcProviderMetadata) -> dict[str, object]:
        return {"keys": [self.key.as_dict(private=False)]}


SUFFIX = uuid4().hex
TENANT_ID = f"tenant-bff-{SUFFIX}"


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
        scopes=("openid", "profile"),
        tenant_claim="redagent_tenant",
        roles_claim_path=("realm_access", "roles"),
        token_endpoint_auth_method="none",
        clock_skew_seconds=30,
        http_timeout_seconds=5,
    )


def test_same_origin_bff_code_pkce_session_csrf_logout_replay_and_zero_token_persistence() -> None:
    asyncio.run(_bff_scenario())


async def _bff_scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    await _bootstrap_tenant(settings)
    await _bootstrap_other_tenant_object(settings)
    transport = SyntheticOidcTransport(_provider())
    runtime = IdentityRuntime(
        config=_provider(),
        cipher=SessionCipher(bytes(range(32))),
        transport=transport,
        public_origin="https://redagent.example.test",
        now=lambda: NOW,
    )
    app = create_app(database_settings=settings, identity_runtime=runtime)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="https://redagent.example.test",
            follow_redirects=False,
        ) as client:
            started = await client.get("/auth/login", params={"tenant_id": TENANT_ID})
            assert started.status_code == 302
            authorization = urlparse(started.headers["location"])
            query = parse_qs(authorization.query)
            assert query["response_type"] == ["code"]
            assert query["code_challenge_method"] == ["S256"]
            assert "code_verifier" not in query
            transport.nonce = query["nonce"][0]

            mixed_up = await client.get(
                "/auth/callback",
                params={"code": "synthetic-code", "state": query["state"][0], "iss": "https://other.invalid"},
            )
            assert mixed_up.status_code == 400
            assert mixed_up.json()["error"]["code"] == "oidc_callback_rejected"

            # A rejected callback consumes state, so a new login is required and the rejected state cannot be replayed.
            started = await client.get("/auth/login", params={"tenant_id": TENANT_ID})
            query = parse_qs(urlparse(started.headers["location"]).query)
            transport.nonce = query["nonce"][0]
            callback = await client.get(
                "/auth/callback",
                params={
                    "code": "synthetic-code",
                    "state": query["state"][0],
                    "iss": _provider().issuer,
                },
            )
            assert callback.status_code == 303
            cookie_headers = "\n".join(callback.headers.get_list("set-cookie"))
            assert "__Host-redagent_session=" in cookie_headers
            assert "HttpOnly" in cookie_headers and "Secure" in cookie_headers and "SameSite=lax" in cookie_headers
            assert transport.last_id_token not in callback.text
            assert "access-token-must-be-discarded" not in callback.text

            current = await client.get("/auth/session")
            assert current.status_code == 200
            assert current.json()["data"] == {
                "authenticated": True,
                "tenant_id": TENANT_ID,
                "roles": ["operator"],
            }

            mutation_headers = {
                "X-RedAgent-Policy-Reference": "identity-policy:1",
                "Idempotency-Key": f"bff-engagement-{SUFFIX}",
                "Origin": "https://redagent.example.test",
                "Sec-Fetch-Site": "same-origin",
            }
            denied_mutation = await client.post(
                "/api/v1/engagements",
                headers=mutation_headers,
                json={
                    "engagement_id": f"engagement-{SUFFIX}",
                    "name": "BFF protected engagement",
                    "owner_user_id": "opaque-owner",
                },
            )
            assert denied_mutation.status_code == 403
            assert denied_mutation.json()["error"]["code"] == "csrf_rejected"
            csrf = client.cookies.get("__Host-redagent_csrf")
            created = await client.post(
                "/api/v1/engagements",
                headers={**mutation_headers, "X-CSRF-Token": csrf},
                json={
                    "engagement_id": f"engagement-{SUFFIX}",
                    "name": "BFF protected engagement",
                    "owner_user_id": "opaque-owner",
                },
            )
            assert created.status_code == 201
            cross_tenant = await client.get(f"/api/v1/engagements/other-engagement-{SUFFIX}")
            assert cross_tenant.status_code == 404

            logout_token = jwt.encode(
                {"alg": "RS256", "kid": "fixture-key"},
                {
                    "iss": _provider().issuer,
                    "aud": _provider().audience,
                    "iat": int(NOW.timestamp()),
                    "jti": f"logout-{SUFFIX}",
                    "sid": transport.sid,
                    "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
                },
                transport.key,
                algorithms=["RS256"],
            )
            backchannel = await client.post(
                f"/auth/backchannel-logout/{TENANT_ID}",
                content=str(httpx.QueryParams({"logout_token": logout_token})),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            assert backchannel.status_code == 204
            assert (await client.get("/auth/session")).status_code == 401
            replayed_logout = await client.post(
                f"/auth/backchannel-logout/{TENANT_ID}",
                content=str(httpx.QueryParams({"logout_token": logout_token})),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            assert replayed_logout.status_code == 400
            spoofed_frontchannel = await client.get(
                f"/auth/frontchannel-logout/{TENANT_ID}",
                params={"iss": "https://attacker.invalid", "sid": transport.sid},
            )
            assert spoofed_frontchannel.status_code == 400

            # Establish a new browser session after IdP logout to exercise local + RP-initiated logout separately.
            restarted = await client.get("/auth/login", params={"tenant_id": TENANT_ID})
            restart_query = parse_qs(urlparse(restarted.headers["location"]).query)
            transport.nonce = restart_query["nonce"][0]
            restarted_callback = await client.get(
                "/auth/callback",
                params={
                    "code": "synthetic-code",
                    "state": restart_query["state"][0],
                    "iss": _provider().issuer,
                },
            )
            assert restarted_callback.status_code == 303

            no_csrf = await client.post("/auth/logout")
            assert no_csrf.status_code == 403
            csrf = client.cookies.get("__Host-redagent_csrf")
            logged_out = await client.post(
                "/auth/logout",
                headers={
                    "X-CSRF-Token": csrf,
                    "Origin": "https://redagent.example.test",
                    "Sec-Fetch-Site": "same-origin",
                },
            )
            assert logged_out.status_code == 303
            assert logged_out.headers["location"].startswith("https://idp.example.test/logout?")
            assert "id_token" not in logged_out.headers["location"]
            assert (await client.get("/auth/session")).status_code == 401

            replay = await client.get(
                "/auth/callback",
                params={"code": "synthetic-code", "state": query["state"][0], "iss": _provider().issuer},
            )
            assert replay.status_code == 400

    engine = create_async_engine(settings.url)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                select(metadata.tables["tenants"].c.id).where(metadata.tables["tenants"].c.id == TENANT_ID)
            )
            await connection.execute(
                select(cast(metadata.tables["audit_events"].c.details, String)).where(
                    cast(metadata.tables["audit_events"].c.details, String).contains("must-not-persist")
                )
            )
            for forbidden in (
                transport.last_id_token,
                "access-token-must-be-discarded",
                "refresh-token-must-be-discarded",
                "must-not-persist",
            ):
                audit_count = await connection.scalar(
                    select(metadata.tables["audit_events"].c.id)
                    .where(metadata.tables["audit_events"].c.tenant_id == TENANT_ID)
                    .where(cast(metadata.tables["audit_events"].c.details, String).contains(forbidden))
                    .limit(1)
                )
                assert audit_count is None
    finally:
        await engine.dispose()


async def _bootstrap_tenant(settings) -> None:
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=TENANT_ID,
                actor_user_id=f"bootstrap-{SUFFIX}",
                correlation_id=f"bootstrap-{SUFFIX}",
            )
            await repo.bootstrap_tenant(name="Synthetic BFF Tenant", occurred_at=NOW)
    finally:
        await engine.dispose()


async def _bootstrap_other_tenant_object(settings) -> None:
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    other_tenant = f"other-tenant-{SUFFIX}"
    other_user = f"other-user-{SUFFIX}"
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=other_tenant,
                actor_user_id=other_user,
                correlation_id=f"other-{SUFFIX}",
            )
            await repo.bootstrap_tenant(name="Other tenant", occurred_at=NOW)
            await repo.create_engagement(
                engagement_id=f"other-engagement-{SUFFIX}",
                name="Must remain isolated",
                owner_user_id=other_user,
                idempotency_key=f"other-engagement-{SUFFIX}",
                occurred_at=NOW,
            )
    finally:
        await engine.dispose()
