from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from redagent_platform.identity.config import OidcProviderConfig
from redagent_platform.identity.protocol import (
    OidcProtocolError,
    build_authorization_request,
    generate_login_material,
    validate_authorization_callback,
)


NOW = datetime(2026, 7, 10, 9, 0, tzinfo=timezone.utc)


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
        scopes=("openid", "profile", "email"),
        tenant_claim="redagent_tenant",
        roles_claim_path=("realm_access", "roles"),
        token_endpoint_auth_method="none",
        clock_skew_seconds=30,
        http_timeout_seconds=5,
    )


def test_authorization_request_is_code_pkce_s256_and_transaction_bound() -> None:
    material = generate_login_material(now=NOW, lifetime=timedelta(minutes=5))
    url = build_authorization_request(
        provider(),
        authorization_endpoint="https://idp.example.test/authorize",
        material=material,
    )
    query = parse_qs(urlparse(url).query)

    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [material.code_challenge]
    assert query["state"] == [material.state]
    assert query["nonce"] == [material.nonce]
    assert query["redirect_uri"] == [provider().redirect_uri]
    assert "token" not in query["response_type"]
    assert material.expires_at == NOW + timedelta(minutes=5)
    assert material.code_verifier not in url


@pytest.mark.parametrize(
    ("params", "error"),
    [
        ({"code": "code-1", "state": "wrong", "iss": "https://idp.example.test"}, "oidc_state_mismatch"),
        ({"code": "code-1", "state": "state-1", "iss": "https://other.example.test"}, "oidc_issuer_mismatch"),
        ({"access_token": "forbidden", "state": "state-1"}, "oidc_front_channel_token_forbidden"),
        ({"id_token": "forbidden", "state": "state-1"}, "oidc_front_channel_token_forbidden"),
        ({"code": "code-1", "state": "state-1", "error": "access_denied"}, "oidc_callback_shape_invalid"),
        ({"state": "state-1"}, "oidc_callback_shape_invalid"),
    ],
)
def test_callback_rejects_state_mixup_token_and_shape_attacks(params: dict[str, str], error: str) -> None:
    with pytest.raises(OidcProtocolError, match=error):
        validate_authorization_callback(
            provider(),
            params=params,
            expected_state="state-1",
        )


def test_callback_accepts_only_code_state_and_exact_issuer() -> None:
    result = validate_authorization_callback(
        provider(),
        params={"code": "code-1", "state": "state-1", "iss": "https://idp.example.test"},
        expected_state="state-1",
    )

    assert result.code == "code-1"
    assert result.issuer == "https://idp.example.test"
