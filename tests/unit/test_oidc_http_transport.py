from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from redagent_platform.identity.config import OidcProviderConfig
from redagent_platform.identity.http_transport import HttpOidcTransport, OidcTransportError


def provider() -> OidcProviderConfig:
    return OidcProviderConfig(
        provider_id="fixture",
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


def test_discovery_accepts_bounded_json_and_rejects_redirect_or_oversized_body() -> None:
    asyncio.run(_transport_cases())


async def _transport_cases() -> None:
    valid_payload = {
        "issuer": provider().issuer,
        "authorization_endpoint": provider().issuer + "/authorize",
        "token_endpoint": provider().issuer + "/token",
        "jwks_uri": provider().issuer + "/jwks",
        "end_session_endpoint": provider().issuer + "/logout",
    }

    async def valid_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=valid_payload, headers={"Content-Type": "application/json"})

    metadata = await HttpOidcTransport(transport=httpx.MockTransport(valid_handler)).discover(provider())
    assert metadata.issuer == provider().issuer

    async def redirect_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://attacker.invalid"})

    with pytest.raises(OidcTransportError, match="oidc_provider_response_invalid"):
        await HttpOidcTransport(transport=httpx.MockTransport(redirect_handler)).discover(provider())

    oversized = json.dumps({"issuer": "x", "padding": "x" * (65 * 1024)}).encode()

    async def oversized_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=oversized, headers={"Content-Type": "application/json"})

    with pytest.raises(OidcTransportError, match="oidc_provider_response_invalid"):
        await HttpOidcTransport(transport=httpx.MockTransport(oversized_handler)).discover(provider())
