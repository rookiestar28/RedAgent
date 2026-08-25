"""Fail-closed compat_098 secret-provider runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit


class SecretConfigError(ValueError):
    """Secret-provider configuration is incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class SecretSettings:
    profile: str
    provider: str
    endpoint: str | None = None
    auth_method: str | None = None
    token_file: Path | None = None
    ca_file: Path | None = None
    role_mapping_file: Path | None = None
    capability_record: Path | None = None
    kubernetes_jwt_file: Path | None = None
    approle_role_id_file: Path | None = None
    approle_wrapped_secret_id_file: Path | None = None


_INLINE_MATERIAL = frozenset({
    "REDAGENT_SECRET_TOKEN",
    "REDAGENT_SECRET_ID",
    "REDAGENT_SECRET_ROOT_TOKEN",
    "BAO_TOKEN",
    "VAULT_TOKEN",
})


def load_secret_settings(workspace: Path, env: Mapping[str, str]) -> SecretSettings:
    root = workspace.resolve()
    if any(env.get(name, "").strip() for name in _INLINE_MATERIAL):
        raise SecretConfigError("secret_inline_material_forbidden")
    profile = _required(env, "REDAGENT_SECRET_PROFILE")
    provider = _required(env, "REDAGENT_SECRET_PROVIDER")
    if provider == "fake":
        if profile == "production":
            raise SecretConfigError("secret_production_fake_provider_forbidden")
        if profile != "synthetic-local":
            raise SecretConfigError("secret_fake_provider_synthetic_only")
        return SecretSettings(profile=profile, provider=provider)
    if provider != "openbao":
        raise SecretConfigError("secret_provider_unsupported")
    endpoint = _required(env, "REDAGENT_SECRET_ENDPOINT")
    parsed = urlsplit(endpoint)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password or not parsed.hostname:
        raise SecretConfigError("secret_endpoint_invalid")
    auth_method = _required(env, "REDAGENT_SECRET_AUTH_METHOD")
    if profile == "local-conformance":
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise SecretConfigError("secret_local_conformance_loopback_required")
        if auth_method != "token-file":
            raise SecretConfigError("secret_local_conformance_token_file_required")
        token = _workspace_file(root, env, "REDAGENT_SECRET_TOKEN_FILE")
        mapping = _mapping_file(root, env)
        return SecretSettings(
            profile=profile,
            provider=provider,
            endpoint=endpoint,
            auth_method=auth_method,
            token_file=token,
            role_mapping_file=mapping,
        )
    if profile != "production":
        raise SecretConfigError("secret_profile_unsupported")
    if parsed.scheme != "https":
        raise SecretConfigError("secret_production_tls_required")
    ca_file = _workspace_file(root, env, "REDAGENT_SECRET_CA_FILE")
    mapping = _mapping_file(root, env)
    capability = _workspace_file(root, env, "REDAGENT_SECRET_CAPABILITY_RECORD")
    if auth_method == "kubernetes":
        kubernetes_jwt = _workspace_file(root, env, "REDAGENT_SECRET_KUBERNETES_JWT_FILE")
        return SecretSettings(
            profile, provider, endpoint, auth_method,
            ca_file=ca_file, role_mapping_file=mapping, capability_record=capability,
            kubernetes_jwt_file=kubernetes_jwt,
        )
    if auth_method == "approle":
        role_id = _workspace_file(root, env, "REDAGENT_SECRET_APPROLE_ROLE_ID_FILE")
        wrapped = _workspace_file(root, env, "REDAGENT_SECRET_APPROLE_WRAPPED_SECRET_ID_FILE")
        return SecretSettings(
            profile, provider, endpoint, auth_method,
            ca_file=ca_file, role_mapping_file=mapping, capability_record=capability,
            approle_role_id_file=role_id, approle_wrapped_secret_id_file=wrapped,
        )
    raise SecretConfigError("secret_production_auth_method_unsupported")


def _mapping_file(root: Path, env: Mapping[str, str]) -> Path:
    path = _workspace_file(root, env, "REDAGENT_SECRET_ROLE_MAPPING_FILE")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecretConfigError("secret_role_mapping_invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0" or not isinstance(payload.get("roles"), dict):
        raise SecretConfigError("secret_role_mapping_invalid")
    forbidden_keys = {"token", "secret_id", "credential_value", "credential", "value"}
    if _contains_forbidden_key(payload, forbidden_keys):
        raise SecretConfigError("secret_role_mapping_material_forbidden")
    return path


def _workspace_file(root: Path, env: Mapping[str, str], name: str) -> Path:
    raw = Path(_required(env, name))
    path = (raw if raw.is_absolute() else root / raw).resolve()
    if not path.is_relative_to(root):
        raise SecretConfigError(f"{name.lower()}_outside_workspace")
    if not path.is_file():
        raise SecretConfigError(f"{name.lower()}_missing")
    return path


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value or len(value) > 500:
        raise SecretConfigError(f"{name.lower()}_required")
    return value


def _contains_forbidden_key(value: object, forbidden: set[str]) -> bool:
    if isinstance(value, dict):
        return any(str(key).lower() in forbidden or _contains_forbidden_key(item, forbidden) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_forbidden_key(item, forbidden) for item in value)
    return False
