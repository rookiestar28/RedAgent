"""Fail-closed OIDC token validation without token retention or disclosure."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import hmac
from typing import Any, Mapping

from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from redagent_platform.identity.config import OidcProviderConfig


LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
MAX_TOKEN_BYTES = 16_384
MAX_LOGOUT_AGE_SECONDS = 300


class OidcTokenError(ValueError):
    """Fixed-code validation failure that never contains supplied token data."""


@dataclass(frozen=True)
class ValidatedIdentityClaims:
    issuer: str
    subject: str
    tenant_id: str
    external_roles: tuple[str, ...]
    oidc_session_id: str | None
    authorized_party: str | None


@dataclass(frozen=True)
class ValidatedLogoutClaims:
    issuer: str
    jti: str
    oidc_session_id: str | None
    subject: str | None


def validate_id_token(
    raw_token: str,
    *,
    jwks: Mapping[str, object],
    config: OidcProviderConfig,
    expected_nonce: str,
    now: datetime,
    access_token: str | None = None,
    authorization_code: str | None = None,
) -> ValidatedIdentityClaims:
    """Validate an ID token and return only the minimum durable identity claims."""

    claims, header = _decode_signed_claims(raw_token, jwks=jwks, config=config)
    now_ts = _utc_timestamp(now)
    if not isinstance(expected_nonce, str) or not expected_nonce:
        raise OidcTokenError("oidc_token_invalid")
    registry = JWTClaimsRegistry(
        now=now_ts,
        leeway=config.clock_skew_seconds,
        iss={"essential": True, "value": config.issuer},
        sub={"essential": True},
        aud={"essential": True, "value": config.audience},
        exp={"essential": True},
        iat={"essential": True},
        nonce={"essential": True, "value": expected_nonce},
    )
    try:
        registry.validate(claims)
    except Exception as exc:
        # CRITICAL: JOSE errors may contain attacker-controlled claims; expose only a fixed code.
        raise OidcTokenError("oidc_token_invalid") from exc
    _validate_hash_claim(claims, "at_hash", access_token, str(header.get("alg", "")))
    _validate_hash_claim(claims, "c_hash", authorization_code, str(header.get("alg", "")))

    authorized_party = claims.get("azp")
    if authorized_party is not None and authorized_party != config.client_id:
        raise OidcTokenError("oidc_authorized_party_invalid")
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1 and authorized_party != config.client_id:
        raise OidcTokenError("oidc_authorized_party_invalid")

    tenant_id = claims.get(config.tenant_claim)
    if not _bounded_text(tenant_id, maximum=64):
        raise OidcTokenError("oidc_tenant_claim_invalid")
    roles = _nested_claim(claims, config.roles_claim_path)
    if (
        not isinstance(roles, list)
        or len(roles) > 100
        or any(not _bounded_text(role, maximum=100) for role in roles)
        or len(set(roles)) != len(roles)
    ):
        raise OidcTokenError("oidc_roles_claim_invalid")

    session_id = claims.get("sid")
    if session_id is not None and not _bounded_text(session_id, maximum=200):
        raise OidcTokenError("oidc_token_invalid")
    subject = claims["sub"]
    return ValidatedIdentityClaims(
        issuer=config.issuer,
        subject=subject,
        tenant_id=tenant_id,
        external_roles=tuple(roles),
        oidc_session_id=session_id,
        authorized_party=authorized_party,
    )


def validate_backchannel_logout_token(
    raw_token: str,
    *,
    jwks: Mapping[str, object],
    config: OidcProviderConfig,
    now: datetime,
) -> ValidatedLogoutClaims:
    """Validate a signed OIDC Back-Channel Logout token before revocation lookup."""

    try:
        claims, _ = _decode_signed_claims(raw_token, jwks=jwks, config=config)
        now_ts = _utc_timestamp(now)
        registry = JWTClaimsRegistry(
            now=now_ts,
            leeway=config.clock_skew_seconds,
            iss={"essential": True, "value": config.issuer},
            aud={"essential": True, "value": config.audience},
            iat={"essential": True},
            jti={"essential": True},
        )
        registry.validate(claims)
        issued_at = claims["iat"]
        if now_ts - issued_at > MAX_LOGOUT_AGE_SECONDS:
            raise ValueError("stale logout token")
        if "nonce" in claims:
            raise ValueError("logout nonce forbidden")
        events = claims.get("events")
        if not isinstance(events, dict) or events.get(LOGOUT_EVENT) != {}:
            raise ValueError("logout event missing")
        jti = claims["jti"]
        session_id = claims.get("sid")
        subject = claims.get("sub")
        if not _bounded_text(jti, maximum=200):
            raise ValueError("logout jti invalid")
        if session_id is not None and not _bounded_text(session_id, maximum=200):
            raise ValueError("logout sid invalid")
        if subject is not None and not _bounded_text(subject, maximum=200):
            raise ValueError("logout subject invalid")
        if session_id is None and subject is None:
            raise ValueError("logout subject missing")
    except Exception as exc:
        # CRITICAL: logout tokens are attacker-controlled; never propagate parser detail or raw data.
        raise OidcTokenError("oidc_logout_token_invalid") from exc
    return ValidatedLogoutClaims(
        issuer=config.issuer,
        jti=jti,
        oidc_session_id=session_id,
        subject=subject,
    )


def _decode_signed_claims(
    raw_token: str,
    *,
    jwks: Mapping[str, object],
    config: OidcProviderConfig,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(raw_token, str) or not raw_token or len(raw_token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise OidcTokenError("oidc_token_invalid")
    try:
        key_set = KeySet.import_key_set(dict(jwks))
        token = jwt.decode(raw_token, key_set, algorithms=list(config.allowed_algorithms))
        header = dict(token.header)
        claims = dict(token.claims)
        if header.get("alg") not in config.allowed_algorithms:
            raise ValueError("algorithm forbidden")
    except Exception as exc:
        # CRITICAL: never include token, key-selection, or claim parser detail in boundary errors.
        raise OidcTokenError("oidc_token_invalid") from exc
    return claims, header


def _validate_hash_claim(
    claims: Mapping[str, Any],
    claim_name: str,
    protected_value: str | None,
    algorithm: str,
) -> None:
    expected = claims.get(claim_name)
    if expected is None:
        return
    if not isinstance(expected, str) or not protected_value or algorithm not in {"RS256", "ES256"}:
        raise OidcTokenError("oidc_token_invalid")
    digest = hashlib.sha256(protected_value.encode("ascii")).digest()
    calculated = base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(expected, calculated):
        raise OidcTokenError("oidc_token_invalid")


def _nested_claim(claims: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = claims
    for segment in path:
        if not isinstance(value, Mapping) or segment not in value:
            return None
        value = value[segment]
    return value


def _bounded_text(value: object, *, maximum: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip() and len(value) <= maximum


def _utc_timestamp(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OidcTokenError("oidc_token_invalid")
    return int(value.astimezone(timezone.utc).timestamp())
