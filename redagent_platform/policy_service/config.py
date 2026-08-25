"""Fail-closed runtime configuration for compat_099 policy decision providers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit


class PolicyConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PolicySettings:
    profile: str
    provider: str
    required_revision: str | None = None
    endpoint: str | None = None
    token_file: Path | None = None
    bundle_public_key_file: Path | None = None
    ca_file: Path | None = None
    client_cert_file: Path | None = None
    client_key_file: Path | None = None


def load_policy_settings(workspace: Path, env: Mapping[str, str]) -> PolicySettings:
    root = workspace.resolve()
    if env.get("REDAGENT_POLICY_TOKEN", "").strip():
        raise PolicyConfigError("policy_inline_token_forbidden")
    if env.get("REDAGENT_POLICY_DECISION_PATH", "").strip():
        raise PolicyConfigError("policy_decision_path_forbidden")
    profile = _required(env, "REDAGENT_POLICY_PROFILE")
    provider = _required(env, "REDAGENT_POLICY_PROVIDER")
    if provider == "fake":
        if profile == "production":
            raise PolicyConfigError("policy_production_fake_provider_forbidden")
        if profile != "synthetic-local":
            raise PolicyConfigError("policy_fake_provider_synthetic_only")
        return PolicySettings(profile, provider, "synthetic-r099-v1")
    if provider != "opa":
        raise PolicyConfigError("policy_provider_unsupported")
    endpoint = _required(env, "REDAGENT_POLICY_ENDPOINT")
    revision = _required(env, "REDAGENT_POLICY_REQUIRED_REVISION")
    _identifier(revision, "policy_required_revision_invalid")
    parsed = urlsplit(endpoint)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password or not parsed.hostname:
        raise PolicyConfigError("policy_endpoint_invalid")
    if profile == "local-conformance":
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise PolicyConfigError("policy_local_loopback_required")
        return PolicySettings(
            profile, provider, revision, endpoint,
            token_file=_workspace_file(root, env, "REDAGENT_POLICY_TOKEN_FILE"),
            bundle_public_key_file=_workspace_file(root, env, "REDAGENT_POLICY_BUNDLE_PUBLIC_KEY_FILE"),
        )
    if profile != "production":
        raise PolicyConfigError("policy_profile_unsupported")
    if parsed.scheme != "https":
        raise PolicyConfigError("policy_production_tls_required")
    return PolicySettings(
        profile, provider, revision, endpoint,
        token_file=_workspace_file(root, env, "REDAGENT_POLICY_TOKEN_FILE"),
        bundle_public_key_file=_workspace_file(root, env, "REDAGENT_POLICY_BUNDLE_PUBLIC_KEY_FILE"),
        ca_file=_workspace_file(root, env, "REDAGENT_POLICY_CA_FILE"),
        client_cert_file=_workspace_file(root, env, "REDAGENT_POLICY_CLIENT_CERT_FILE"),
        client_key_file=_workspace_file(root, env, "REDAGENT_POLICY_CLIENT_KEY_FILE"),
    )


def _workspace_file(root: Path, env: Mapping[str, str], name: str) -> Path:
    raw = Path(_required(env, name))
    path = (raw if raw.is_absolute() else root / raw).resolve()
    if not path.is_relative_to(root):
        raise PolicyConfigError(f"{name.lower()}_outside_workspace")
    if not path.is_file():
        raise PolicyConfigError(f"{name.lower()}_missing")
    return path


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value or len(value) > 500:
        raise PolicyConfigError(f"{name.lower()}_required")
    return value


def _identifier(value: str, error: str) -> None:
    import re
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}", value):
        raise PolicyConfigError(error)
