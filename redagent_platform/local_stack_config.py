"""Typed, fail-closed configuration for the compat_092 local dependency stack."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class ConfigError(ValueError):
    """Raised before Docker access when local-stack configuration is unsafe."""


@dataclass(frozen=True)
class LockedImage:
    service: str
    registry: str
    tag: str
    index_digest: str
    platform_digest: str
    platform: str
    reference: str
    license_security_status: str


@dataclass(frozen=True)
class LocalStackConfig:
    workspace: Path
    profile: str
    compose_project_name: str
    bind_host: str
    postgres_port: int
    keycloak_port: int
    temporal_port: int
    rustfs_port: int
    state_dir: Path
    startup_timeout_seconds: int
    stop_timeout_seconds: int
    active_target_access: bool
    real_scanners: bool
    privileged_runners: bool
    external_delivery: bool
    images: tuple[LockedImage, ...]

    @property
    def image_map(self) -> dict[str, LockedImage]:
        return {image.service: image for image in self.images}


REQUIRED_IMAGES = frozenset({"postgres", "keycloak", "temporal", "rustfs"})
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET_NAME = re.compile(r"(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY)", re.IGNORECASE)
APPROVED_RUNTIME_ROOTS = frozenset({".local"})
DEFAULT_COMPOSE_PROJECT_NAME = "redagent-local"
COMPOSE_PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def is_reparse_path(path: Path) -> bool:
    """Return whether an existing path can redirect runtime writes elsewhere."""

    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def ensure_approved_runtime_state_dir(workspace: Path, state_dir: Path) -> Path:
    """Validate the only workspace roots allowed to receive local runtime state."""

    root = workspace.resolve()
    lexical_root = Path(os.path.abspath(root))
    lexical_state = Path(os.path.abspath(state_dir))
    try:
        relative = lexical_state.relative_to(lexical_root)
    except ValueError as exc:
        raise ConfigError("state_dir_outside_workspace") from exc
    if len(relative.parts) < 2 or relative.parts[0] not in APPROVED_RUNTIME_ROOTS:
        raise ConfigError("state_dir_runtime_root_invalid")

    current = lexical_root
    for component in relative.parts:
        current /= component
        try:
            exists = current.exists() or current.is_symlink()
        except OSError as exc:
            raise ConfigError("state_dir_reparse_point") from exc
        if exists and is_reparse_path(current):
            raise ConfigError("state_dir_reparse_point")
    try:
        resolved = lexical_state.resolve()
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ConfigError("state_dir_outside_workspace") from exc
    return resolved


def load_local_stack_config(
    workspace: Path,
    *,
    env: Mapping[str, str] | None = None,
    image_lock_path: Path | None = None,
) -> LocalStackConfig:
    root = workspace.resolve()
    values = dict(os.environ if env is None else env)
    _reject_embedded_secrets(values)

    profile = values.get("REDAGENT_PROFILE", "local").strip().lower()
    if profile != "local":
        raise ConfigError(f"unsupported_profile:{profile}")
    compose_project_name = values.get(
        "REDAGENT_COMPOSE_PROJECT_NAME",
        DEFAULT_COMPOSE_PROJECT_NAME,
    ).strip()
    if not COMPOSE_PROJECT_NAME.fullmatch(compose_project_name):
        raise ConfigError("compose_project_name_invalid")
    bind_host = values.get("REDAGENT_BIND_HOST", "127.0.0.1").strip()
    try:
        address = ipaddress.ip_address(bind_host)
        if address.version != 4 or not address.is_loopback:
            raise ConfigError("local_bind_must_be_loopback")
    except ValueError as exc:
        raise ConfigError("local_bind_must_be_loopback") from exc

    postgres_port = _port(values.get("REDAGENT_POSTGRES_PORT", "55432"), "postgres")
    keycloak_port = _port(values.get("REDAGENT_KEYCLOAK_PORT", "58080"), "keycloak")
    temporal_port = _port(values.get("REDAGENT_TEMPORAL_PORT", "57233"), "temporal")
    rustfs_port = _port(values.get("REDAGENT_RUSTFS_PORT", "59000"), "rustfs")
    if len({postgres_port, keycloak_port, temporal_port, rustfs_port}) != 4:
        raise ConfigError("service_ports_must_be_unique")

    raw_state = Path(values.get("REDAGENT_STATE_DIR", ".local/redagent"))
    state_dir = ensure_approved_runtime_state_dir(
        root,
        raw_state if raw_state.is_absolute() else root / raw_state,
    )

    timeout = _positive_int(values.get("REDAGENT_STARTUP_TIMEOUT_SECONDS", "180"), "startup_timeout")
    stop_timeout = _positive_int(values.get("REDAGENT_STOP_TIMEOUT_SECONDS", "30"), "stop_timeout")
    flags = {
        "active_target_access": _boolean(values.get("REDAGENT_ACTIVE_TARGET_ACCESS", "false")),
        "real_scanners": _boolean(values.get("REDAGENT_REAL_SCANNERS", "false")),
        "privileged_runners": _boolean(values.get("REDAGENT_PRIVILEGED_RUNNERS", "false")),
        "external_delivery": _boolean(values.get("REDAGENT_EXTERNAL_DELIVERY", "false")),
    }
    enabled = sorted(name for name, value in flags.items() if value)
    if enabled:
        raise ConfigError(f"dangerous_capability_must_remain_disabled:{','.join(enabled)}")

    lock_path = image_lock_path or root / "config" / "local-stack-images.json"
    images = _load_images(lock_path)
    return LocalStackConfig(
        workspace=root,
        profile=profile,
        compose_project_name=compose_project_name,
        bind_host=bind_host,
        postgres_port=postgres_port,
        keycloak_port=keycloak_port,
        temporal_port=temporal_port,
        rustfs_port=rustfs_port,
        state_dir=state_dir,
        startup_timeout_seconds=timeout,
        stop_timeout_seconds=stop_timeout,
        images=images,
        **flags,
    )


def _reject_embedded_secrets(values: Mapping[str, str]) -> None:
    for name, value in sorted(values.items()):
        if name.startswith("REDAGENT_") and value and SECRET_NAME.search(name):
            raise ConfigError(f"embedded_secret_forbidden:{name}")


def _load_images(path: Path) -> tuple[LockedImage, ...]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"image_lock_load_failed:{type(exc).__name__}") from exc
    errors: list[str] = []
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        errors.append("image_lock_schema_invalid")
    expected_platform = payload.get("platform") if isinstance(payload, dict) else None
    if expected_platform != "linux/amd64":
        errors.append("image_lock_platform_unsupported")
    records = payload.get("images", []) if isinstance(payload, dict) else []
    if not isinstance(records, list):
        records = []
        errors.append("image_lock_images_must_be_array")
    parsed: list[LockedImage] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            errors.append("image_lock_entry_must_be_object")
            continue
        service = str(record.get("service", ""))
        if service in seen:
            errors.append(f"duplicate_image:{service}")
        seen.add(service)
        registry = str(record.get("registry", ""))
        tag = str(record.get("tag", ""))
        index_digest = str(record.get("index_digest", ""))
        platform_digest = str(record.get("platform_digest", ""))
        platform = str(record.get("platform", ""))
        reference = str(record.get("reference", ""))
        status = str(record.get("license_security_status", ""))
        if platform != expected_platform:
            errors.append(f"image_platform_mismatch:{service}")
        if not DIGEST.fullmatch(index_digest) or not DIGEST.fullmatch(platform_digest):
            errors.append(f"image_digest_invalid:{service}")
        if reference != f"{registry}:{tag}@{index_digest}":
            errors.append(f"image_reference_not_digest_pinned:{service}")
        if not all((service, registry, tag, status)):
            errors.append(f"image_field_required:{service or 'unknown'}")
        parsed.append(
            LockedImage(service, registry, tag, index_digest, platform_digest, platform, reference, status)
        )
    for service in sorted(REQUIRED_IMAGES - seen):
        errors.append(f"required_image_missing:{service}")
    for service in sorted(seen - REQUIRED_IMAGES):
        errors.append(f"unexpected_image:{service}")
    if errors:
        raise ConfigError(";".join(errors))
    return tuple(sorted(parsed, key=lambda image: image.service))


def _port(value: str, service: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ConfigError(f"port_invalid:{service}") from exc
    if not 1024 <= port <= 65535:
        raise ConfigError(f"port_out_of_range:{service}")
    return port


def _positive_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"positive_integer_required:{name}") from exc
    if parsed <= 0:
        raise ConfigError(f"positive_integer_required:{name}")
    return parsed


def _boolean(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"false", "0", "no"}:
        return False
    if normalized in {"true", "1", "yes"}:
        return True
    raise ConfigError(f"boolean_value_invalid:{value}")
