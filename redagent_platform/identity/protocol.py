"""Authorization-code/PKCE request and callback primitives."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets
from urllib.parse import urlencode, urlparse

from redagent_platform.identity.config import OidcProviderConfig


class OidcProtocolError(ValueError):
    """Raised when an OIDC message violates the configured protocol contract."""


@dataclass(frozen=True)
class LoginMaterial:
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    code_challenge: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class AuthorizationCallback:
    code: str = field(repr=False)
    state: str = field(repr=False)
    issuer: str


def generate_login_material(*, now: datetime, lifetime: timedelta) -> LoginMaterial:
    _aware(now)
    if not timedelta(seconds=30) <= lifetime <= timedelta(minutes=10):
        raise OidcProtocolError("oidc_login_lifetime_invalid")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = _base64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return LoginMaterial(state, nonce, verifier, challenge, now, now + lifetime)


def build_authorization_request(
    config: OidcProviderConfig,
    *,
    authorization_endpoint: str,
    material: LoginMaterial,
) -> str:
    _trusted_provider_endpoint(config, authorization_endpoint)
    query = urlencode(
        {
            "client_id": config.client_id,
            "response_type": "code",
            "redirect_uri": config.redirect_uri,
            "scope": " ".join(config.scopes),
            "state": material.state,
            "nonce": material.nonce,
            "code_challenge": material.code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return authorization_endpoint + ("&" if "?" in authorization_endpoint else "?") + query


def validate_authorization_callback(
    config: OidcProviderConfig,
    *,
    params: dict[str, str],
    expected_state: str,
) -> AuthorizationCallback:
    if "access_token" in params or "id_token" in params or "token" in params:
        raise OidcProtocolError("oidc_front_channel_token_forbidden")
    if set(params) - {"code", "state", "iss", "session_state"} or not params.get("code") or not params.get("state"):
        raise OidcProtocolError("oidc_callback_shape_invalid")
    if not hmac.compare_digest(params["state"], expected_state):
        raise OidcProtocolError("oidc_state_mismatch")
    issuer = params.get("iss")
    if issuer != config.issuer:
        raise OidcProtocolError("oidc_issuer_mismatch")
    if len(params["code"]) > 4096:
        raise OidcProtocolError("oidc_code_invalid")
    return AuthorizationCallback(params["code"], params["state"], issuer)


def _trusted_provider_endpoint(config: OidcProviderConfig, endpoint: str) -> None:
    parsed = urlparse(endpoint)
    issuer = urlparse(config.issuer)
    if parsed.scheme != issuer.scheme or parsed.netloc != issuer.netloc or parsed.username or parsed.password:
        raise OidcProtocolError("oidc_endpoint_origin_mismatch")
    if parsed.fragment:
        raise OidcProtocolError("oidc_endpoint_invalid")


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OidcProtocolError("oidc_timezone_required")
