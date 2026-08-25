"""Fail-closed compat_100 runner mTLS configuration."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Mapping
import os
import re


class RunnerIdentityConfigError(ValueError):
    """Runner identity configuration is incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class RunnerIdentitySettings:
    profile: str
    trust_domain: str
    bind_host: str
    server_name: str
    ca_file: Path
    server_cert_file: Path
    server_key_file: Path


_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_INLINE_MATERIAL = {
    "REDAGENT_RUNNER_CA_PEM",
    "REDAGENT_RUNNER_SERVER_CERT_PEM",
    "REDAGENT_RUNNER_SERVER_KEY_PEM",
    "REDAGENT_RUNNER_CLIENT_CERT_PEM",
    "REDAGENT_RUNNER_CLIENT_KEY_PEM",
}
_REQUIRED = {
    "REDAGENT_RUNNER_TRUST_DOMAIN",
    "REDAGENT_RUNNER_BIND_HOST",
    "REDAGENT_RUNNER_SERVER_NAME",
    "REDAGENT_RUNNER_CA_FILE",
    "REDAGENT_RUNNER_SERVER_CERT_FILE",
    "REDAGENT_RUNNER_SERVER_KEY_FILE",
}


def load_runner_identity_settings(
    workspace: Path,
    *,
    env: Mapping[str, str] | None = None,
) -> RunnerIdentitySettings:
    values = dict(os.environ if env is None else env)
    if any(values.get(name, "").strip() for name in _INLINE_MATERIAL):
        raise RunnerIdentityConfigError("runner_identity_inline_material_forbidden")
    profile = values.get("REDAGENT_RUNNER_IDENTITY_PROFILE", "").strip()
    if profile not in {"local-conformance", "production"}:
        raise RunnerIdentityConfigError("runner_identity_profile_invalid")
    if any(not values.get(name, "").strip() for name in _REQUIRED):
        raise RunnerIdentityConfigError("runner_identity_configuration_incomplete")

    trust_domain = values["REDAGENT_RUNNER_TRUST_DOMAIN"].strip().lower()
    bind_host = values["REDAGENT_RUNNER_BIND_HOST"].strip()
    server_name = values["REDAGENT_RUNNER_SERVER_NAME"].strip().lower()
    if not _DOMAIN.fullmatch(trust_domain) or not _DOMAIN.fullmatch(server_name):
        raise RunnerIdentityConfigError("runner_identity_domain_invalid")
    try:
        address = ip_address(bind_host)
    except ValueError as exc:
        raise RunnerIdentityConfigError("runner_identity_bind_host_invalid") from exc

    root = workspace.resolve()
    paths = tuple(
        _required_file(values[name], root, local=profile == "local-conformance")
        for name in (
            "REDAGENT_RUNNER_CA_FILE",
            "REDAGENT_RUNNER_SERVER_CERT_FILE",
            "REDAGENT_RUNNER_SERVER_KEY_FILE",
        )
    )
    if profile == "local-conformance":
        if not address.is_loopback or trust_domain != "redagent.test" or server_name != "localhost":
            raise RunnerIdentityConfigError("runner_identity_local_loopback_required")
    else:
        if trust_domain.endswith(".test"):
            raise RunnerIdentityConfigError("runner_identity_production_test_domain_forbidden")
        if address.is_loopback or server_name == "localhost":
            raise RunnerIdentityConfigError("runner_identity_production_private_endpoint_required")
    return RunnerIdentitySettings(profile, trust_domain, bind_host, server_name, paths[0], paths[1], paths[2])


def _required_file(raw: str, workspace: Path, *, local: bool) -> Path:
    path = Path(raw).expanduser().resolve()
    if local and not path.is_relative_to(workspace):
        raise RunnerIdentityConfigError("runner_identity_local_file_scope_invalid")
    if not path.is_file():
        raise RunnerIdentityConfigError("runner_identity_file_required")
    return path
