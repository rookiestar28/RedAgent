"""Fail-closed Temporal client/worker configuration."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import ipaddress
import os
from pathlib import Path
import re
from typing import Mapping


class TemporalConfigError(ValueError):
    """Raised before a Temporal network connection when configuration is unsafe."""


@dataclass(frozen=True, slots=True)
class TemporalSettings:
    target: str
    namespace: str
    task_queue: str
    codec_key_id: str
    codec_key_path: Path
    codec_key: bytes = field(repr=False)
    tls: bool = False
    profile: str = "local"


_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def load_temporal_settings(
    workspace: Path,
    *,
    env: Mapping[str, str] | None = None,
) -> TemporalSettings:
    values = dict(os.environ if env is None else env)
    if values.get("REDAGENT_TEMPORAL_CODEC_KEY"):
        raise TemporalConfigError("inline_temporal_codec_key_forbidden")
    profile = values.get("REDAGENT_PROFILE", "local").strip().lower()
    if profile not in {"local", "production"}:
        raise TemporalConfigError("temporal_profile_invalid")
    target = values.get("REDAGENT_TEMPORAL_TARGET", "127.0.0.1:57233").strip()
    host, port = _target(target)
    if profile == "local":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise TemporalConfigError("local_temporal_target_must_be_loopback")
        except ValueError as exc:
            raise TemporalConfigError("local_temporal_target_must_be_loopback") from exc
    namespace = values.get("REDAGENT_TEMPORAL_NAMESPACE", "redagent-local").strip()
    task_queue = values.get("REDAGENT_TEMPORAL_TASK_QUEUE", "redagent-r096-v1").strip()
    if not _NAME.fullmatch(namespace):
        raise TemporalConfigError("temporal_namespace_invalid")
    if not _NAME.fullmatch(task_queue):
        raise TemporalConfigError("temporal_task_queue_invalid")
    tls = _boolean(values.get("REDAGENT_TEMPORAL_TLS", "false"))
    if profile == "production" and not tls:
        raise TemporalConfigError("production_temporal_tls_required")

    root = workspace.resolve()
    raw_key_path = values.get("REDAGENT_TEMPORAL_CODEC_KEY_FILE", "").strip()
    if not raw_key_path:
        raise TemporalConfigError("temporal_codec_key_file_required")
    candidate = Path(raw_key_path)
    key_path = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if not key_path.is_relative_to(root):
        raise TemporalConfigError("temporal_codec_key_file_outside_workspace")
    if not key_path.is_file():
        raise TemporalConfigError("temporal_codec_key_file_missing")
    try:
        codec_key = base64.b64decode(key_path.read_text(encoding="ascii").strip(), altchars=b"-_", validate=True)
    except (OSError, UnicodeError, binascii.Error) as exc:
        raise TemporalConfigError("temporal_codec_key_invalid") from exc
    if len(codec_key) != 32:
        raise TemporalConfigError("temporal_codec_key_invalid")
    key_id = values.get("REDAGENT_TEMPORAL_CODEC_KEY_ID", "").strip()
    if not _KEY_ID.fullmatch(key_id):
        raise TemporalConfigError("temporal_codec_key_id_invalid")
    return TemporalSettings(
        target=f"{host}:{port}",
        namespace=namespace,
        task_queue=task_queue,
        codec_key_id=key_id,
        codec_key_path=key_path,
        codec_key=codec_key,
        tls=tls,
        profile=profile,
    )


def _target(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if not separator or not host or not raw_port.isdecimal():
        raise TemporalConfigError("temporal_target_invalid")
    port = int(raw_port)
    if not 1024 <= port <= 65535:
        raise TemporalConfigError("temporal_target_invalid")
    return host.strip("[]"), port


def _boolean(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise TemporalConfigError("temporal_tls_invalid")
