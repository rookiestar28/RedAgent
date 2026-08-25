"""Closed-set lifecycle helpers for the compat_092 local dependency stack."""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable
from urllib.parse import quote

from redagent_platform.identity.config import IdentityConfigError, load_oidc_provider_config
from redagent_platform.local_stack_config import (
    ConfigError,
    DEFAULT_COMPOSE_PROJECT_NAME,
    LocalStackConfig,
    ensure_approved_runtime_state_dir,
    is_reparse_path,
    load_local_stack_config,
)


class LocalStackError(RuntimeError):
    """Raised before or during a bounded local-stack lifecycle action."""


@dataclass(frozen=True)
class PrerequisiteVersions:
    docker_client: str
    docker_server: str
    compose: str
    engine_os: str
    engine_arch: str


_RUNTIME_PORT_FIELDS = (
    ("postgres", "postgres_port"),
    ("keycloak", "keycloak_port"),
    ("temporal", "temporal_port"),
    ("rustfs", "rustfs_port"),
)
_MAX_FRESH_PORT_OFFSET = 32


def effective_runtime_config(
    config: LocalStackConfig,
    env_file: Path,
    *,
    require_persisted_project: bool = False,
    allow_missing_project: bool = False,
) -> LocalStackConfig:
    """Overlay persisted coordinates only when existing stack ownership is explicit."""

    if not env_file.is_file():
        return config
    allowed = {
        "REDAGENT_COMPOSE_PROJECT_NAME",
        "REDAGENT_BIND_HOST",
        "REDAGENT_POSTGRES_PORT",
        "REDAGENT_KEYCLOAK_PORT",
        "REDAGENT_TEMPORAL_PORT",
        "REDAGENT_RUSTFS_PORT",
    }
    values = {
        "REDAGENT_PROFILE": config.profile,
        "REDAGENT_COMPOSE_PROJECT_NAME": config.compose_project_name,
        "REDAGENT_STATE_DIR": str(config.state_dir),
        "REDAGENT_BIND_HOST": config.bind_host,
        "REDAGENT_POSTGRES_PORT": str(config.postgres_port),
        "REDAGENT_KEYCLOAK_PORT": str(config.keycloak_port),
        "REDAGENT_TEMPORAL_PORT": str(config.temporal_port),
        "REDAGENT_RUSTFS_PORT": str(config.rustfs_port),
    }
    seen: set[str] = set()
    for line in env_file.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if not separator or name not in allowed:
            continue
        if name in seen:
            raise LocalStackError(f"runtime_public_config_duplicate:{name}")
        seen.add(name)
        values[name] = value
    if "REDAGENT_COMPOSE_PROJECT_NAME" not in seen:
        # CRITICAL: never infer legacy Compose ownership from a shared compatibility default.
        if require_persisted_project or (
            not allow_missing_project
            and config.compose_project_name == DEFAULT_COMPOSE_PROJECT_NAME
        ):
            raise LocalStackError("runtime_compose_project_missing")
    return load_local_stack_config(config.workspace, env=values)


def _ensure_workspace_path(root: Path, candidate: Path, error: str) -> Path:
    """Reject links and reparse points before a runtime artifact is accessed."""

    lexical_root = Path(os.path.abspath(root))
    lexical_candidate = Path(os.path.abspath(candidate))
    try:
        relative = lexical_candidate.relative_to(lexical_root)
    except ValueError as exc:
        raise LocalStackError(error) from exc
    current = lexical_root
    for component in relative.parts:
        current /= component
        try:
            exists = current.exists() or current.is_symlink()
        except OSError as exc:
            raise LocalStackError(error) from exc
        if exists and is_reparse_path(current):
            raise LocalStackError(error)
    try:
        resolved = lexical_candidate.resolve()
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise LocalStackError(error) from exc
    return resolved


def _runtime_directory(config: LocalStackConfig, error: str) -> Path:
    try:
        root = config.workspace.resolve()
        state_dir = ensure_approved_runtime_state_dir(root, config.state_dir)
    except (ConfigError, OSError, RuntimeError) as exc:
        raise LocalStackError(error) from exc
    runtime_dir = state_dir / "runtime"
    _ensure_workspace_path(root, runtime_dir, error)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    resolved = _ensure_workspace_path(root, runtime_dir, error)
    if not resolved.is_dir():
        raise LocalStackError(error)
    return resolved


def _runtime_artifact(config: LocalStackConfig, filename: str, error: str) -> Path:
    runtime_dir = _runtime_directory(config, error)
    target = runtime_dir / filename
    _ensure_workspace_path(config.workspace.resolve(), target, error)
    return target


def _runtime_oidc_artifact(config: LocalStackConfig, filename: str) -> Path:
    """Return an OIDC artifact path only under the ignored .local runtime tree."""

    root = config.workspace.resolve()
    try:
        state_dir = ensure_approved_runtime_state_dir(root, config.state_dir)
    except ConfigError as exc:
        if str(exc) == "state_dir_outside_workspace":
            raise LocalStackError("runtime_oidc_config_outside_workspace") from exc
        raise LocalStackError("runtime_oidc_config_outside_local_runtime") from exc
    local_root = root / ".local"
    try:
        local_root = _ensure_workspace_path(
            root,
            local_root,
            "runtime_oidc_config_outside_local_runtime",
        )
        if state_dir == local_root or not state_dir.is_relative_to(local_root):
            raise LocalStackError("runtime_oidc_config_outside_local_runtime")
    except (OSError, RuntimeError, ValueError) as exc:
        raise LocalStackError("runtime_oidc_config_outside_local_runtime") from exc

    runtime_dir = state_dir / "runtime"
    _ensure_workspace_path(root, runtime_dir, "runtime_oidc_config_outside_local_runtime")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir = _ensure_workspace_path(root, runtime_dir, "runtime_oidc_config_outside_local_runtime")
    if not runtime_dir.is_dir():
        raise LocalStackError("runtime_oidc_config_outside_local_runtime")
    target = runtime_dir / filename
    _ensure_workspace_path(root, target, "runtime_oidc_config_outside_local_runtime")
    return target


def _assert_runtime_artifact(
    config: LocalStackConfig,
    target: Path,
    filename: str,
    error: str,
) -> Path:
    expected = _runtime_artifact(config, filename, error)
    if Path(os.path.abspath(target)) != Path(os.path.abspath(expected)):
        raise LocalStackError(error)
    _ensure_workspace_path(config.workspace.resolve(), target, error)
    return expected


def _atomic_write_runtime_text(
    config: LocalStackConfig,
    target: Path,
    filename: str,
    text: str,
    *,
    encoding: str,
    validator: Callable[[Path], None] | None = None,
    resolver: Callable[[LocalStackConfig, str], Path] | None = None,
    error: str = "runtime_artifact_invalid",
) -> None:
    """Write an approved runtime artifact atomically after a final reparse check."""

    resolve_target = resolver or (lambda current, name: _runtime_artifact(current, name, error))
    expected = resolve_target(config, filename)
    if Path(os.path.abspath(target)) != Path(os.path.abspath(expected)):
        raise LocalStackError(error)
    _ensure_workspace_path(config.workspace.resolve(), target, error)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            dir=expected.parent,
            prefix=f".{filename}-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(text)
        if validator is not None:
            validator(temporary)
        # CRITICAL: check again immediately before replace; Windows junctions can redirect writes.
        expected = resolve_target(config, filename)
        if Path(os.path.abspath(target)) != Path(os.path.abspath(expected)):
            raise LocalStackError(error)
        _ensure_workspace_path(config.workspace.resolve(), expected, error)
        os.replace(temporary, expected)
        temporary = None
        try:
            os.chmod(expected, 0o600)
        except OSError:
            # Windows ACLs are diagnosed separately; never weaken an existing ACL here.
            pass
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _runtime_oidc_payload(config: LocalStackConfig, template: Path) -> dict[str, object]:
    try:
        template_payload = json.loads(template.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalStackError("runtime_oidc_template_invalid") from exc
    if (
        not isinstance(template_payload, dict)
        or set(template_payload) != {"schema_version", "providers"}
        or template_payload.get("schema_version") != "1.0"
    ):
        raise LocalStackError("runtime_oidc_template_invalid")
    providers = template_payload.get("providers")
    if (
        not isinstance(providers, list)
        or len(providers) != 1
        or not isinstance(providers[0], dict)
        or providers[0].get("provider_id") != "local-keycloak"
    ):
        raise LocalStackError("runtime_oidc_template_invalid")
    try:
        reviewed = load_oidc_provider_config(
            config.workspace.resolve(),
            template,
            provider_id="local-keycloak",
        )
    except IdentityConfigError as exc:
        raise LocalStackError("runtime_oidc_template_invalid") from exc
    if not 1024 <= config.keycloak_port <= 65535:
        raise LocalStackError("runtime_oidc_template_invalid")
    issuer = f"http://{config.bind_host}:{config.keycloak_port}/realms/redagent-local"
    return {
        "schema_version": "1.0",
        "providers": [
            {
                "provider_id": reviewed.provider_id,
                "issuer": issuer,
                "discovery_url": issuer + "/.well-known/openid-configuration",
                "client_id": reviewed.client_id,
                "audience": reviewed.audience,
                "redirect_uri": reviewed.redirect_uri,
                "post_logout_redirect_uri": reviewed.post_logout_redirect_uri,
                "allowed_algorithms": list(reviewed.allowed_algorithms),
                "scopes": list(reviewed.scopes),
                "tenant_claim": reviewed.tenant_claim,
                "roles_claim_path": list(reviewed.roles_claim_path),
                "token_endpoint_auth_method": reviewed.token_endpoint_auth_method,
                "clock_skew_seconds": reviewed.clock_skew_seconds,
                "http_timeout_seconds": reviewed.http_timeout_seconds,
            }
        ],
    }


def create_runtime_oidc_provider_config(config: LocalStackConfig) -> Path:
    """Render the local OIDC template with the effective Keycloak endpoint."""

    root = config.workspace.resolve()
    template = root / "config" / "identity-providers.json"
    try:
        _ensure_workspace_path(root, template, "runtime_oidc_template_invalid")
    except LocalStackError:
        raise
    if not template.is_file():
        raise LocalStackError("runtime_oidc_template_invalid")
    rendered = _runtime_oidc_payload(config, template)
    target = _runtime_oidc_artifact(config, "identity-providers.json")
    text = json.dumps(rendered, indent=2, sort_keys=True) + "\n"
    try:
        _atomic_write_runtime_text(
            config,
            target,
            "identity-providers.json",
            text,
            encoding="utf-8",
            validator=lambda temporary: load_oidc_provider_config(
                root,
                temporary,
                provider_id="local-keycloak",
            ),
            resolver=_runtime_oidc_artifact,
            error="runtime_oidc_config_outside_local_runtime",
        )
    except (IdentityConfigError, OSError) as exc:
        raise LocalStackError("runtime_oidc_template_invalid") from exc
    # CRITICAL: local fixture ports are dynamic; never rewrite the tracked provider template.
    return target


def build_compose_command(action: str, config: LocalStackConfig, env_file: Path) -> tuple[str, ...]:
    prefix = (
        "docker",
        "compose",
        "--project-name",
        config.compose_project_name,
        "--env-file",
        str(env_file),
        "--file",
        str(config.workspace / "compose.yaml"),
    )
    actions = {
        "pull": ("pull",),
        "start": (
            "up",
            "--detach",
            "--wait",
            "--wait-timeout",
            str(config.startup_timeout_seconds),
            "--pull",
            "never",
        ),
        "status": ("ps", "--format", "json"),
        "stop": ("stop", "--timeout", str(config.stop_timeout_seconds)),
        "reset": ("down", "--volumes", "--remove-orphans"),
        "config": ("config", "--quiet"),
    }
    if action not in actions:
        raise LocalStackError(f"unsupported_lifecycle_action:{action}")
    return prefix + actions[action]


def create_runtime_env(
    config: LocalStackConfig,
    target: Path,
    *,
    secret_factory: Callable[[], str],
    key_factory: Callable[[], bytes] | None = None,
) -> bool:
    target = _assert_runtime_artifact(
        config,
        target,
        "local-stack.env",
        "runtime_artifact_invalid",
    )
    generate_key = key_factory or (lambda: os.urandom(32))
    if target.exists():
        _ensure_compose_project_env(config, target)
        _ensure_database_url(config, target)
        _ensure_temporal_env(config, target, generate_key)
        _ensure_evidence_env(config, target, secret_factory)
        return False
    postgres_password = secret_factory()
    keycloak_password = secret_factory()
    rustfs_secret = secret_factory()
    codec_key_path = _runtime_artifact(config, "temporal-codec-key", "runtime_artifact_invalid")
    _ensure_codec_key(config, generate_key)
    images = config.image_map
    keycloak_admin_username_key = "KC_" + "BOOTSTRAP_ADMIN_USERNAME"
    lines = (
        f"REDAGENT_COMPOSE_PROJECT_NAME={config.compose_project_name}",
        f"REDAGENT_BIND_HOST={config.bind_host}",
        f"REDAGENT_POSTGRES_PORT={config.postgres_port}",
        f"REDAGENT_KEYCLOAK_PORT={config.keycloak_port}",
        f"REDAGENT_TEMPORAL_PORT={config.temporal_port}",
        f"REDAGENT_RUSTFS_PORT={config.rustfs_port}",
        f"REDAGENT_POSTGRES_IMAGE={images['postgres'].reference}",
        f"REDAGENT_KEYCLOAK_IMAGE={images['keycloak'].reference}",
        f"REDAGENT_TEMPORAL_IMAGE={images['temporal'].reference}",
        f"REDAGENT_RUSTFS_IMAGE={images['rustfs'].reference}",
        f"REDAGENT_TEMPORAL_TARGET={config.bind_host}:{config.temporal_port}",
        "REDAGENT_TEMPORAL_NAMESPACE=redagent-local",
        "REDAGENT_TEMPORAL_TASK_QUEUE=redagent-r096-v1",  # pragma: allowlist secret
        f"REDAGENT_TEMPORAL_CODEC_KEY_FILE={codec_key_path.resolve()}",
        "REDAGENT_TEMPORAL_CODEC_KEY_ID=local-r096-v1",  # pragma: allowlist secret
        "REDAGENT_TEMPORAL_TLS=false",
        "REDAGENT_EVIDENCE_PROFILE=local-conformance",
        "REDAGENT_EVIDENCE_BACKEND=s3",
        f"REDAGENT_EVIDENCE_ENDPOINT=http://{config.bind_host}:{config.rustfs_port}",
        "REDAGENT_EVIDENCE_BUCKET=redagent-evidence",
        "REDAGENT_EVIDENCE_REGION=us-east-1",
        "REDAGENT_EVIDENCE_KMS_REFERENCE=sse-s3:local-fixture",
        "AWS_ACCESS_KEY_ID=redagent-local",
        f"AWS_SECRET_ACCESS_KEY={rustfs_secret}",
        "REDAGENT_POSTGRES_USER=redagent",
        "REDAGENT_POSTGRES_DB=redagent",
        f"REDAGENT_POSTGRES_PASSWORD={postgres_password}",
        f"{keycloak_admin_username_key}=local-admin",
        f"KC_BOOTSTRAP_ADMIN_PASSWORD={keycloak_password}",
    )
    _atomic_write_runtime_text(
        config,
        target,
        "local-stack.env",
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    _write_database_url(config, _runtime_artifact(config, "database-url", "runtime_artifact_invalid"), postgres_password)
    return True


def _ensure_compose_project_env(config: LocalStackConfig, env_file: Path) -> None:
    env_file = _assert_runtime_artifact(
        config,
        env_file,
        "local-stack.env",
        "runtime_artifact_invalid",
    )
    text = env_file.read_text(encoding="utf-8")
    values = [
        line.partition("=")[2]
        for line in text.splitlines()
        if line.partition("=")[0] == "REDAGENT_COMPOSE_PROJECT_NAME"
    ]
    if len(values) > 1:
        raise LocalStackError("runtime_compose_project_duplicate")
    if values:
        if values[0] != config.compose_project_name:
            raise LocalStackError("runtime_compose_project_mismatch")
        return
    # IMPORTANT: persist the identity before lifecycle commands so a later stop/reset
    # cannot fall back to another checkout's Docker Compose project.
    _atomic_write_runtime_text(
        config,
        env_file,
        "local-stack.env",
        text.rstrip("\n")
        + "\nREDAGENT_COMPOSE_PROJECT_NAME="
        + config.compose_project_name
        + "\n",
        encoding="utf-8",
    )


def _ensure_temporal_env(
    config: LocalStackConfig,
    env_file: Path,
    key_factory: Callable[[], bytes],
) -> None:
    env_file = _assert_runtime_artifact(
        config,
        env_file,
        "local-stack.env",
        "runtime_artifact_invalid",
    )
    text = env_file.read_text(encoding="utf-8")
    existing = {line.partition("=")[0] for line in text.splitlines() if "=" in line}
    images = config.image_map
    codec_key_path = _runtime_artifact(config, "temporal-codec-key", "runtime_artifact_invalid")
    _ensure_codec_key(config, key_factory)
    additions = []
    if "REDAGENT_TEMPORAL_PORT" not in existing:
        additions.append(f"REDAGENT_TEMPORAL_PORT={config.temporal_port}")
    if "REDAGENT_TEMPORAL_IMAGE" not in existing:
        additions.append(f"REDAGENT_TEMPORAL_IMAGE={images['temporal'].reference}")
    temporal_values = {
        "REDAGENT_TEMPORAL_TARGET": f"{config.bind_host}:{config.temporal_port}",
        "REDAGENT_TEMPORAL_NAMESPACE": "redagent-local",
        "REDAGENT_TEMPORAL_TASK_QUEUE": "redagent-r096-v1",
        "REDAGENT_TEMPORAL_CODEC_KEY_FILE": str(codec_key_path.resolve()),
        "REDAGENT_TEMPORAL_CODEC_KEY_ID": "local-r096-v1",
        "REDAGENT_TEMPORAL_TLS": "false",
    }
    additions.extend(f"{name}={value}" for name, value in temporal_values.items() if name not in existing)
    if additions:
        # IMPORTANT: preserve generated credentials byte-for-byte while migrating non-secret stack metadata.
        _atomic_write_runtime_text(
            config,
            env_file,
            "local-stack.env",
            text.rstrip("\n") + "\n" + "\n".join(additions) + "\n",
            encoding="utf-8",
        )


def _ensure_evidence_env(
    config: LocalStackConfig,
    env_file: Path,
    secret_factory: Callable[[], str],
) -> None:
    env_file = _assert_runtime_artifact(
        config,
        env_file,
        "local-stack.env",
        "runtime_artifact_invalid",
    )
    text = env_file.read_text(encoding="utf-8")
    legacy_reference = "REDAGENT_EVIDENCE_KMS_REFERENCE=kms:local:fixture"
    if legacy_reference in text:
        text = text.replace(legacy_reference, "REDAGENT_EVIDENCE_KMS_REFERENCE=sse-s3:local-fixture")
        _atomic_write_runtime_text(
            config,
            env_file,
            "local-stack.env",
            text,
            encoding="utf-8",
        )
    existing = {line.partition("=")[0] for line in text.splitlines() if "=" in line}
    images = config.image_map
    values = {
        "REDAGENT_RUSTFS_PORT": str(config.rustfs_port),
        "REDAGENT_RUSTFS_IMAGE": images["rustfs"].reference,
        "REDAGENT_EVIDENCE_PROFILE": "local-conformance",
        "REDAGENT_EVIDENCE_BACKEND": "s3",
        "REDAGENT_EVIDENCE_ENDPOINT": f"http://{config.bind_host}:{config.rustfs_port}",
        "REDAGENT_EVIDENCE_BUCKET": "redagent-evidence",
        "REDAGENT_EVIDENCE_REGION": "us-east-1",
        "REDAGENT_EVIDENCE_KMS_REFERENCE": "sse-s3:local-fixture",
        "AWS_ACCESS_KEY_ID": "redagent-local",
    }
    additions = [f"{name}={value}" for name, value in values.items() if name not in existing]
    if "AWS_SECRET_ACCESS_KEY" not in existing:
        additions.append(f"AWS_SECRET_ACCESS_KEY={secret_factory()}")
    if additions:
        # IMPORTANT: migrate only missing evidence settings and preserve every existing generated secret byte-for-byte.
        _atomic_write_runtime_text(
            config,
            env_file,
            "local-stack.env",
            text.rstrip("\n") + "\n" + "\n".join(additions) + "\n",
            encoding="utf-8",
        )


def _ensure_codec_key(config: LocalStackConfig, key_factory: Callable[[], bytes]) -> None:
    path = _runtime_artifact(config, "temporal-codec-key", "runtime_artifact_invalid")
    if path.exists():
        return
    value = key_factory()
    if not isinstance(value, bytes) or len(value) != 32:
        raise LocalStackError("temporal_codec_key_generation_invalid")
    _atomic_write_runtime_text(
        config,
        path,
        "temporal-codec-key",
        base64.urlsafe_b64encode(value).decode("ascii") + "\n",
        encoding="ascii",
    )


def _ensure_database_url(config: LocalStackConfig, env_file: Path) -> None:
    env_file = _assert_runtime_artifact(
        config,
        env_file,
        "local-stack.env",
        "runtime_artifact_invalid",
    )
    target = _runtime_artifact(config, "database-url", "runtime_artifact_invalid")
    if target.exists():
        return
    values = dict(line.partition("=")[::2] for line in env_file.read_text(encoding="utf-8").splitlines() if "=" in line)
    password = values.get("REDAGENT_POSTGRES_PASSWORD", "")
    if not password:
        raise LocalStackError("postgres_password_missing_from_runtime_env")
    _write_database_url(config, target, password)


def _write_database_url(config: LocalStackConfig, target: Path, password: str) -> None:
    target = _assert_runtime_artifact(
        config,
        target,
        "database-url",
        "runtime_artifact_invalid",
    )
    encoded_password = quote(password, safe="")
    _atomic_write_runtime_text(
        config,
        target,
        "database-url",
        f"postgresql+asyncpg://redagent:{encoded_password}@{config.bind_host}:{config.postgres_port}/redagent\n",
        encoding="utf-8",
    )


def require_reset_confirmation(config: LocalStackConfig, *, confirmed: bool) -> None:
    try:
        ensure_approved_runtime_state_dir(config.workspace, config.state_dir)
    except ConfigError as exc:
        raise LocalStackError("local_reset_scope_invalid") from exc
    if config.profile != "local":
        raise LocalStackError("local_reset_scope_invalid")
    if not confirmed:
        raise LocalStackError("local_reset_confirmation_required")


def requires_port_preflight(env_file: Path) -> bool:
    """Only fresh boot preflights ports; an existing fixed project owns its published ports."""

    return not env_file.is_file()


def allocate_available_runtime_ports(
    config: LocalStackConfig,
    *,
    port_available: Callable[[str, int], bool] | None = None,
    allow_fallback: bool = True,
) -> LocalStackConfig:
    """Return a bounded, non-conflicting port map for a fresh local runtime.

    Existing runtimes use their persisted coordinates.  A caller must explicitly
    disable fallback when an operator supplied any service-port override.
    """

    probe = port_available or _loopback_port_available
    configured_ports = {getattr(config, field) for _, field in _RUNTIME_PORT_FIELDS}
    selected_ports: set[int] = set()
    replacements: dict[str, int] = {}
    for service, field in _RUNTIME_PORT_FIELDS:
        configured_port = getattr(config, field)
        selected_port: int | None = None
        for offset in range(_MAX_FRESH_PORT_OFFSET + 1):
            if offset and not allow_fallback:
                break
            candidate = configured_port + offset
            if candidate > 65535:
                break
            if candidate in selected_ports or (
                candidate in configured_ports and candidate != configured_port
            ):
                continue
            if probe(config.bind_host, candidate):
                selected_port = candidate
                break
        if selected_port is None:
            raise LocalStackError(f"local_runtime_port_unavailable:{service}:{configured_port}")
        selected_ports.add(selected_port)
        replacements[field] = selected_port
    return replace(config, **replacements)


def _loopback_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, port))
        except OSError:
            return False
    return True


def parse_prerequisite_versions(docker_output: str, compose_output: str) -> PrerequisiteVersions:
    parts = docker_output.strip().split("|")
    if len(parts) != 4:
        raise LocalStackError("docker_version_output_invalid")
    client, server, engine_os, engine_arch = parts
    if not server:
        raise LocalStackError("docker_engine_unavailable")
    if engine_os != "linux" or engine_arch != "amd64":
        raise LocalStackError(f"docker_engine_platform_unsupported:{engine_os}/{engine_arch}")
    if _version_tuple(client) < (24, 0, 0) or _version_tuple(server) < (24, 0, 0):
        raise LocalStackError("docker_engine_version_unsupported")
    compose = compose_output.strip().removeprefix("v")
    if _version_tuple(compose) < (2, 20, 0):
        raise LocalStackError("docker_compose_version_unsupported")
    return PrerequisiteVersions(client, server, compose, engine_os, engine_arch)


def redact_diagnostics(text: str, secret_values: tuple[str, ...]) -> str:
    result = text
    for value in secret_values:
        if value:
            result = result.replace(value, "[REDACTED]")
    return result


def verify_host_endpoints(
    config: LocalStackConfig,
    *,
    connector: Callable[[tuple[str, int], float], object] = socket.create_connection,
) -> tuple[tuple[str, str, int], ...]:
    """Prove the Desktop host-forwarding boundary, not only container health."""

    endpoints = (
        ("postgres", config.bind_host, config.postgres_port),
        ("keycloak", config.bind_host, config.keycloak_port),
        ("temporal", config.bind_host, config.temporal_port),
        ("rustfs", config.bind_host, config.rustfs_port),
    )
    for service, host, port in endpoints:
        try:
            connection = connector((host, port), 2.0)
        except OSError as exc:
            raise LocalStackError(f"host_endpoint_unreachable:{service}:{port}") from exc
        close = getattr(connection, "close", None)
        if callable(close):
            close()
    return endpoints


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        raise LocalStackError(f"version_invalid:{value}")
    return tuple(int(part or 0) for part in match.groups())
