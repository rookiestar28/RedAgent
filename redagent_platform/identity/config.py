"""Strict allowlisted OIDC provider configuration for R094."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse


class IdentityConfigError(ValueError):
    """Raised before network or identity state access when configuration is unsafe."""


@dataclass(frozen=True)
class OidcProviderConfig:
    provider_id: str
    issuer: str
    discovery_url: str
    client_id: str
    audience: str
    redirect_uri: str
    post_logout_redirect_uri: str
    allowed_algorithms: tuple[str, ...]
    scopes: tuple[str, ...]
    tenant_claim: str
    roles_claim_path: tuple[str, ...]
    token_endpoint_auth_method: str
    clock_skew_seconds: int
    http_timeout_seconds: int


REQUIRED_FIELDS = frozenset(
    {
        "provider_id",
        "issuer",
        "discovery_url",
        "client_id",
        "audience",
        "redirect_uri",
        "post_logout_redirect_uri",
        "allowed_algorithms",
        "scopes",
        "tenant_claim",
        "roles_claim_path",
        "token_endpoint_auth_method",
        "clock_skew_seconds",
        "http_timeout_seconds",
    }
)
ALLOWED_ALGORITHMS = frozenset({"RS256", "ES256"})


def load_oidc_provider_config(workspace: Path, path: Path, *, provider_id: str) -> OidcProviderConfig:
    root = workspace.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise IdentityConfigError("identity_config_outside_workspace")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IdentityConfigError("identity_config_load_failed") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        raise IdentityConfigError("identity_config_schema_invalid")
    providers = payload.get("providers")
    if not isinstance(providers, list):
        raise IdentityConfigError("identity_providers_invalid")
    matches = [item for item in providers if isinstance(item, dict) and item.get("provider_id") == provider_id]
    if len(matches) != 1:
        raise IdentityConfigError("identity_provider_not_unique")
    return _parse_provider(matches[0])


def _parse_provider(values: dict[str, object]) -> OidcProviderConfig:
    if set(values) != REQUIRED_FIELDS:
        raise IdentityConfigError("identity_provider_fields_invalid")
    provider_id = _text("provider_id", values["provider_id"], 64)
    issuer = _issuer(_text("issuer", values["issuer"], 500))
    discovery = _text("discovery_url", values["discovery_url"], 600)
    if discovery != issuer.rstrip("/") + "/.well-known/openid-configuration":
        raise IdentityConfigError("oidc_discovery_mismatch")
    _https_or_loopback(discovery)
    redirect = _redirect("redirect_uri", values["redirect_uri"])
    post_logout = _redirect("post_logout_redirect_uri", values["post_logout_redirect_uri"])
    if _origin(redirect) != _origin(post_logout):
        raise IdentityConfigError("oidc_redirect_origin_mismatch")
    algorithms = _string_tuple("allowed_algorithms", values["allowed_algorithms"], maximum=10)
    if not algorithms or any(algorithm not in ALLOWED_ALGORITHMS for algorithm in algorithms):
        raise IdentityConfigError("oidc_algorithm_forbidden")
    scopes = _string_tuple("scopes", values["scopes"], maximum=20)
    if not scopes or scopes[0] != "openid" or "openid" not in scopes:
        raise IdentityConfigError("oidc_openid_scope_required")
    roles_path = _string_tuple("roles_claim_path", values["roles_claim_path"], maximum=10)
    if not roles_path:
        raise IdentityConfigError("oidc_roles_claim_path_invalid")
    auth_method = _text("token_endpoint_auth_method", values["token_endpoint_auth_method"], 40)
    if auth_method not in {"none", "client_secret_basic"}:
        raise IdentityConfigError("oidc_auth_method_forbidden")
    clock_skew = _integer("clock_skew_seconds", values["clock_skew_seconds"], minimum=0, maximum=300)
    timeout = _integer("http_timeout_seconds", values["http_timeout_seconds"], minimum=1, maximum=30)
    return OidcProviderConfig(
        provider_id=provider_id,
        issuer=issuer,
        discovery_url=discovery,
        client_id=_text("client_id", values["client_id"], 200),
        audience=_text("audience", values["audience"], 200),
        redirect_uri=redirect,
        post_logout_redirect_uri=post_logout,
        allowed_algorithms=algorithms,
        scopes=scopes,
        tenant_claim=_text("tenant_claim", values["tenant_claim"], 100),
        roles_claim_path=roles_path,
        token_endpoint_auth_method=auth_method,
        clock_skew_seconds=clock_skew,
        http_timeout_seconds=timeout,
    )


def _issuer(value: str) -> str:
    if "*" in value or urlparse(value).query or urlparse(value).fragment:
        raise IdentityConfigError("oidc_issuer_invalid")
    _https_or_loopback(value)
    return value.rstrip("/")


def _https_or_loopback(value: str) -> None:
    parsed = urlparse(value)
    if parsed.username or parsed.password or not parsed.hostname or parsed.scheme not in {"http", "https"}:
        raise IdentityConfigError("oidc_url_invalid")
    if parsed.scheme == "https":
        return
    try:
        if not ipaddress.ip_address(parsed.hostname).is_loopback:
            raise IdentityConfigError("oidc_https_required")
    except ValueError as exc:
        raise IdentityConfigError("oidc_https_required") from exc


def _redirect(name: str, value: object) -> str:
    text = _text(name, value, 600)
    parsed = urlparse(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or "*" in text
    ):
        raise IdentityConfigError("oidc_redirect_uri_invalid")
    return text


def _origin(value: str) -> str:
    parsed = urlparse(value)
    return f"{parsed.scheme}://{parsed.netloc}"


def _text(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise IdentityConfigError(f"identity_{name}_invalid")
    return value.strip()


def _string_tuple(name: str, value: object, *, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise IdentityConfigError(f"identity_{name}_invalid")
    result = tuple(_text(name, item, 100) for item in value)
    if len(set(result)) != len(result):
        raise IdentityConfigError(f"identity_{name}_duplicate")
    return result


def _integer(name: str, value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise IdentityConfigError(f"identity_{name}_invalid")
    return value
