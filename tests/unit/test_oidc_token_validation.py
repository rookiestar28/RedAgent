from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib

from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey
import pytest

from redagent_platform.identity.config import OidcProviderConfig
from redagent_platform.identity.tokens import (
    OidcTokenError,
    validate_backchannel_logout_token,
    validate_id_token,
)


NOW = datetime(2026, 7, 10, 10, 0, tzinfo=timezone.utc)
NOW_TS = int(NOW.timestamp())
PRIVATE_KEY = RSAKey.generate_key(parameters={"kid": "key-1", "use": "sig"})
JWKS = {"keys": [PRIVATE_KEY.as_dict(private=False)]}


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
        scopes=("openid", "profile"),
        tenant_claim="redagent_tenant",
        roles_claim_path=("realm_access", "roles"),
        token_endpoint_auth_method="none",
        clock_skew_seconds=30,
        http_timeout_seconds=5,
    )


def _id_claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": provider().issuer,
        "sub": "subject-1",
        "aud": provider().audience,
        "exp": NOW_TS + 300,
        "iat": NOW_TS,
        "nonce": "nonce-1",
        "sid": "idp-session-1",
        "redagent_tenant": "tenant-1",
        "realm_access": {"roles": ["redagent-operator", "redagent-reviewer"]},
    }
    claims.update(overrides)
    return claims


def _token(claims: dict[str, object], *, alg: str = "RS256", key=PRIVATE_KEY, kid: str = "key-1") -> str:
    return jwt.encode({"alg": alg, "kid": kid}, claims, key, algorithms=[alg])


def test_valid_id_token_enforces_signature_claims_nonce_tenant_and_role_shape() -> None:
    claims = validate_id_token(
        _token(_id_claims()),
        jwks=JWKS,
        config=provider(),
        expected_nonce="nonce-1",
        now=NOW,
    )

    assert claims.subject == "subject-1"
    assert claims.tenant_id == "tenant-1"
    assert claims.oidc_session_id == "idp-session-1"
    assert claims.external_roles == ("redagent-operator", "redagent-reviewer")
    assert "token" not in repr(claims).lower()


@pytest.mark.parametrize(
    ("overrides", "expected_nonce", "error"),
    [
        ({"iss": "https://other.example.test"}, "nonce-1", "oidc_token_invalid"),
        ({"aud": "other-audience"}, "nonce-1", "oidc_token_invalid"),
        ({"exp": NOW_TS - 31}, "nonce-1", "oidc_token_invalid"),
        ({"iat": NOW_TS + 31}, "nonce-1", "oidc_token_invalid"),
        ({"nonce": "nonce-2"}, "nonce-1", "oidc_token_invalid"),
        ({"sub": ""}, "nonce-1", "oidc_token_invalid"),
        ({"redagent_tenant": ""}, "nonce-1", "oidc_tenant_claim_invalid"),
        ({"realm_access": {"roles": "operator"}}, "nonce-1", "oidc_roles_claim_invalid"),
        ({"aud": ["redagent-bff", "other"], "azp": "other"}, "nonce-1", "oidc_authorized_party_invalid"),
    ],
)
def test_id_token_claim_attacks_fail_closed_without_echoing_token(
    overrides: dict[str, object],
    expected_nonce: str,
    error: str,
) -> None:
    raw = _token(_id_claims(**overrides))

    with pytest.raises(OidcTokenError, match=error) as caught:
        validate_id_token(raw, jwks=JWKS, config=provider(), expected_nonce=expected_nonce, now=NOW)

    assert raw not in str(caught.value)


def test_unknown_key_and_forbidden_algorithm_fail_closed() -> None:
    other_key = RSAKey.generate_key(parameters={"kid": "other", "use": "sig"})
    unknown = _token(_id_claims(), key=other_key, kid="other")
    symmetric_key = OctKey.generate_key(parameters={"kid": "symmetric", "use": "sig"})
    symmetric = jwt.encode(
        {"alg": "HS256", "kid": "symmetric"},
        _id_claims(),
        symmetric_key,
        algorithms=["HS256"],
    )

    for raw in (unknown, symmetric):
        with pytest.raises(OidcTokenError, match="oidc_token_invalid"):
            validate_id_token(raw, jwks=JWKS, config=provider(), expected_nonce="nonce-1", now=NOW)


def test_optional_access_token_and_code_hashes_are_validated_when_present() -> None:
    access_value = "synthetic-access-value"
    code_value = "synthetic-code-value"
    claims = _id_claims(at_hash=_oidc_hash(access_value), c_hash=_oidc_hash(code_value))

    validate_id_token(
        _token(claims),
        jwks=JWKS,
        config=provider(),
        expected_nonce="nonce-1",
        now=NOW,
        access_token=access_value,
        authorization_code=code_value,
    )
    with pytest.raises(OidcTokenError, match="oidc_token_invalid"):
        validate_id_token(
            _token(claims),
            jwks=JWKS,
            config=provider(),
            expected_nonce="nonce-1",
            now=NOW,
            access_token="wrong-access-value",
            authorization_code=code_value,
        )


def _logout_claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": provider().issuer,
        "aud": provider().audience,
        "iat": NOW_TS,
        "jti": "logout-1",
        "sid": "idp-session-1",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    }
    claims.update(overrides)
    return claims


def _oidc_hash(value: str) -> str:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def test_backchannel_logout_requires_signed_event_jti_and_sid_or_subject() -> None:
    result = validate_backchannel_logout_token(
        _token(_logout_claims()),
        jwks=JWKS,
        config=provider(),
        now=NOW,
    )

    assert result.jti == "logout-1"
    assert result.oidc_session_id == "idp-session-1"
    assert result.subject is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"events": {}},
        {"jti": ""},
        {"sid": None},
        {"nonce": "forbidden"},
        {"iat": NOW_TS - 301},
        {"aud": "other"},
    ],
)
def test_backchannel_logout_spoof_replay_shape_and_staleness_fail_closed(overrides: dict[str, object]) -> None:
    with pytest.raises(OidcTokenError, match="oidc_logout_token_invalid"):
        validate_backchannel_logout_token(
            _token(_logout_claims(**overrides)),
            jwks=JWKS,
            config=provider(),
            now=NOW,
        )
