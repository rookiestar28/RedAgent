#!/usr/bin/env python3
"""Build and operate the closed synthetic-only compat_099 OPA fixture."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Iterator

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# IMPORTANT: direct execution places scripts/ on sys.path; keep package imports deterministic for G2.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.gate_lease import ValidationLease, ValidationLeaseError  # noqa: E402

POLICY = ROOT / "config" / "opa" / "policy"
DETECTION_POLICY = ROOT / "config" / "validation" / "detection-feedback"
RUNTIME = ROOT / ".local" / "redagent" / "opa"
IMAGE_LOCK = ROOT / "config" / "opa-conformance-image.json"
BUNDLE_SERVER_IMAGE_LOCK = ROOT / "config" / "opa-bundle-server-image.json"
COMPOSE = ROOT / "compose.opa-conformance.yaml"
APP_TOKEN = "redagent-r099-app"  # pragma: allowlist secret
OPA_HOST_PORT_START = 58181
OPA_HOST_PORT_END = 58281
OPA_HOST_PORT_FALLBACK_START = 64080
OPA_HOST_PORT_FALLBACK_END = 64180
OPA_ENDPOINT_STATE = "opa-endpoint.json"
OPA_PLATFORM = "linux/amd64"
_OPA_FIXTURE_LEASE_FILENAME = "opa-conformance-fixture.lock"
_RUNTIME_RELATIVE = Path(".local") / "redagent" / "opa"
_COMPOSE_PROJECT_PREFIX = "redagent-opa"
_CLEANUP_IMAGE_PLACEHOLDER = "local.invalid/redagent-opa-cleanup:noop"
_MAX_BUNDLE_BYTES = 64 * 1024 * 1024
_MAX_PUBLIC_KEY_BYTES = 64 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}\Z")
_IMAGE_LOCK_FIELDS = {
    "index_digest",
    "license_security_status",
    "platform",
    "platform_digest",
    "production_qualified",
    "purpose",
    "reference",
    "registry",
    "source",
    "tag",
}
_REVIEWED_IMAGE_LOCKS = {
    "opa-conformance-image.json": {
        "registry": "docker.io/openpolicyagent/opa",
        "tag": "1.18.2-static",
        "index_digest": "sha256:57f7d06808fff6de3ea1d698e6430990973ca1370be0e54975f0083d615521da",
        "platform_digest": "sha256:3ece20d3a58eb4051db71c0b84fc962bca2a6f9aa74ee8ea3d027d693fdc2d1a",
    },
    "opa-bundle-server-image.json": {
        "registry": "docker.io/library/python",
        "tag": "3.13-alpine",
        "index_digest": "sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0",
        "platform_digest": "sha256:c25cd44f45df1279a2cba589e67dfcd9db04647ea483b117a7de8b1a99bdfb23",
    },
}


class ConformanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class _PathSnapshot:
    path: Path
    kind: str
    device: int
    inode: int
    mode: int
    content_digest: str | None = None


def _opa_endpoint_state_path() -> Path:
    return _runtime_file(OPA_ENDPOINT_STATE)


def _load_opa_host_port() -> int | None:
    try:
        path = _existing_runtime_file(OPA_ENDPOINT_STATE)
        if path is None:
            return None
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    port = state.get("port") if isinstance(state, dict) else None
    if isinstance(port, bool) or not isinstance(port, int):
        return None
    if not any(start <= port <= end for start, end in _opa_host_port_ranges()):
        return None
    return port


def _opa_host_port_ranges() -> tuple[tuple[int, int], ...]:
    # IMPORTANT: preserve primary-first order; the fallback is only for Windows hosts
    # that deny every bind in the established conformance range.
    return (
        (OPA_HOST_PORT_START, OPA_HOST_PORT_END),
        (OPA_HOST_PORT_FALLBACK_START, OPA_HOST_PORT_FALLBACK_END),
    )


def _write_opa_host_port(port: int) -> None:
    _opa_endpoint_state_path().write_text(
        f'{json.dumps({"port": port}, sort_keys=True)}\n',
        encoding="utf-8",
    )


def opa_endpoint() -> str:
    port = _load_opa_host_port() or OPA_HOST_PORT_START
    return f"http://127.0.0.1:{port}"


def _image() -> str:
    return _locked_image(IMAGE_LOCK)


def _bundle_server_image() -> str:
    return _locked_image(BUNDLE_SERVER_IMAGE_LOCK)


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate image-lock key")
        result[key] = value
    return result


def _locked_image(lock_path: Path) -> str:
    reviewed = _REVIEWED_IMAGE_LOCKS.get(lock_path.name)
    try:
        payload = json.loads(
            lock_path.read_text(encoding="utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid JSON constant")),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ConformanceError("opa_image_lock_invalid") from exc
    if reviewed is None or not isinstance(payload, dict) or set(payload) != _IMAGE_LOCK_FIELDS:
        raise ConformanceError("opa_image_lock_invalid")
    if any(payload.get(field) != value for field, value in reviewed.items()):
        raise ConformanceError("opa_image_lock_invalid")
    index_digest = payload["index_digest"]
    platform_digest = payload["platform_digest"]
    reference = payload["reference"]
    if (
        not isinstance(index_digest, str)
        or not isinstance(platform_digest, str)
        or not _DIGEST.fullmatch(index_digest)
        or not _DIGEST.fullmatch(platform_digest)
        or payload.get("platform") != OPA_PLATFORM
        or payload.get("purpose") != "local-conformance-only"
        or payload.get("production_qualified") is not False
        or not isinstance(payload.get("source"), str)
        or not payload["source"].startswith("https://")
        or not isinstance(payload.get("license_security_status"), str)
        or not payload["license_security_status"].strip()
        or reference != f"{reviewed['registry']}:{reviewed['tag']}@{reviewed['index_digest']}"
    ):
        raise ConformanceError("opa_image_lock_invalid")
    return reference


def _metadata_is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x00000400
    )


def _path_is_link_or_reparse(path: Path) -> bool:
    return _metadata_is_link_or_reparse(path.lstat())


def _workspace_root() -> Path:
    try:
        root = ROOT.resolve(strict=True)
    except OSError as exc:
        raise ConformanceError("opa_workspace_path_invalid") from exc
    if not root.is_dir():
        raise ConformanceError("opa_workspace_path_invalid")
    return root


def _compose_project_name() -> str:
    root = _workspace_root()
    identity = os.path.normcase(str(root)).replace("\\", "/")
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"{_COMPOSE_PROJECT_PREFIX}-{digest}"


def _legacy_implicit_project_name() -> str:
    """Return the old Compose-v2 default project name for this workspace only."""

    name = re.sub(r"[^a-z0-9_-]", "", _workspace_root().name.casefold())
    if not name:
        raise ConformanceError("opa_legacy_fixture_inventory_invalid")
    return name


def _compose_file(root: Path) -> Path:
    try:
        compose = COMPOSE.absolute()
        expected = root / "compose.opa-conformance.yaml"
        metadata = compose.lstat()
    except OSError as exc:
        raise ConformanceError("opa_compose_path_invalid") from exc
    if compose != expected or _metadata_is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ConformanceError("opa_compose_path_invalid")
    return compose


def _is_local_docker_host(value: str) -> bool:
    lowered = value.lower()
    if lowered.startswith("npipe:////./pipe/"):
        return True
    if lowered.startswith("unix:///"):
        return True
    if not lowered.startswith("tcp://"):
        return False
    host_port = value[6:].rsplit("@", 1)[-1]
    host = host_port
    if host.startswith("["):
        closing = host.find("]")
        if closing < 0:
            return False
        host = host[1:closing]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _safe_docker_environment() -> dict[str, str]:
    """Remove ambient compose scope and reject any non-local Docker target."""

    env = dict(os.environ)
    for key in tuple(env):
        if key.upper().startswith("COMPOSE_"):
            env.pop(key, None)

    def remove_case_insensitive(name: str) -> tuple[str, ...]:
        values: list[str] = []
        for key in tuple(env):
            if key.upper() == name:
                values.append(env.pop(key))
        return tuple(values)

    contexts = remove_case_insensitive("DOCKER_CONTEXT")
    hosts = remove_case_insensitive("DOCKER_HOST")
    remove_case_insensitive("DOCKER_CONFIG")
    tls_values = remove_case_insensitive("DOCKER_TLS")
    tls_values += remove_case_insensitive("DOCKER_TLS_VERIFY")
    certificate_paths = remove_case_insensitive("DOCKER_CERT_PATH")
    if any(context not in {"", "default"} for context in contexts):
        raise ConformanceError("opa_docker_target_override_forbidden")
    if any(host and not _is_local_docker_host(host) for host in hosts):
        raise ConformanceError("opa_docker_target_override_forbidden")
    if any(tls_values) or any(certificate_paths):
        raise ConformanceError("opa_docker_target_override_forbidden")
    return env


def _docker_command(*arguments: str) -> list[str]:
    # CRITICAL: the OPA fixture must not inherit an ambient remote Docker context.
    return ["docker", "--context", "default", *arguments]


def _container_user() -> str:
    """Use the current non-root POSIX owner for bind-mounted private artifacts."""

    if os.name != "posix":
        return "65532:65532"
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if not callable(getuid) or not callable(getgid):
        raise ConformanceError("opa_container_identity_invalid")
    uid = getuid()
    gid = getgid()
    # CRITICAL: root or an unbounded identity would expand the fixture's host access.
    if (
        isinstance(uid, bool)
        or isinstance(gid, bool)
        or not isinstance(uid, int)
        or not isinstance(gid, int)
        or uid <= 0
        or gid <= 0
        or uid >= 2**31
        or gid >= 2**31
    ):
        raise ConformanceError("opa_container_identity_invalid")
    return f"{uid}:{gid}"


def _runtime_directory() -> Path:
    """Create and validate the sole workspace-local mutable OPA runtime root."""

    try:
        root = _workspace_root()
        expected = root.joinpath(*_RUNTIME_RELATIVE.parts)
        runtime = RUNTIME.absolute()
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    if runtime != expected:
        raise ConformanceError("opa_runtime_path_invalid")

    current = root
    try:
        for component in _RUNTIME_RELATIVE.parts:
            current /= component
            exists = current.exists() or current.is_symlink()
            if exists:
                metadata = current.lstat()
                if _path_is_link_or_reparse(current) or not stat.S_ISDIR(metadata.st_mode):
                    raise ConformanceError("opa_runtime_path_invalid")
            else:
                current.mkdir()
                metadata = current.lstat()
                if _path_is_link_or_reparse(current) or not stat.S_ISDIR(metadata.st_mode):
                    raise ConformanceError("opa_runtime_path_invalid")
    except ConformanceError:
        raise
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    return current


def _runtime_child_directory(name: str) -> Path:
    if Path(name).name != name:
        raise ConformanceError("opa_runtime_path_invalid")
    parent = _runtime_directory()
    target = parent / name
    try:
        exists = target.exists() or target.is_symlink()
        if exists:
            metadata = target.lstat()
            if _path_is_link_or_reparse(target) or not stat.S_ISDIR(metadata.st_mode):
                raise ConformanceError("opa_runtime_path_invalid")
        else:
            target.mkdir()
            metadata = target.lstat()
            if _path_is_link_or_reparse(target) or not stat.S_ISDIR(metadata.st_mode):
                raise ConformanceError("opa_runtime_path_invalid")
    except ConformanceError:
        raise
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    return target


def _runtime_file(name: str, *, required: bool = False) -> Path:
    if Path(name).name != name:
        raise ConformanceError("opa_runtime_path_invalid")
    target = _runtime_directory() / name
    try:
        exists = target.exists() or target.is_symlink()
        if not exists:
            if required:
                raise ConformanceError("opa_runtime_artifact_missing")
            return target
        metadata = target.lstat()
        if _path_is_link_or_reparse(target) or not stat.S_ISREG(metadata.st_mode):
            raise ConformanceError("opa_runtime_path_invalid")
    except ConformanceError:
        raise
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    return target


def _runtime_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _read_pinned_runtime_file(path: Path, *, max_bytes: int) -> bytes:
    """Read a bounded local artifact only while its path and descriptor agree."""

    try:
        initial = path.lstat()
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_race_detected") from exc
    if (
        _metadata_is_link_or_reparse(initial)
        or not stat.S_ISREG(initial.st_mode)
        or initial.st_size < 0
        or initial.st_size > max_bytes
    ):
        raise ConformanceError("opa_runtime_path_invalid")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise ConformanceError("opa_runtime_path_invalid")
        # CRITICAL: O_NOFOLLOW may be a no-op on Windows. A descriptor that
        # differs from the lstat-pinned local file must not reach Docker mounts.
        if _runtime_file_identity(initial) != _runtime_file_identity(before):
            raise ConformanceError("opa_runtime_path_race_detected")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(65536, before.st_size - len(payload)))
            if not chunk:
                raise ConformanceError("opa_runtime_path_race_detected")
            payload.extend(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            _metadata_is_link_or_reparse(current)
            or not stat.S_ISREG(current.st_mode)
            or _runtime_file_identity(before) != _runtime_file_identity(after)
            or _runtime_file_identity(initial) != _runtime_file_identity(current)
        ):
            raise ConformanceError("opa_runtime_path_race_detected")
        return bytes(payload)
    except ConformanceError:
        raise
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_race_detected") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _existing_runtime_file(name: str) -> Path | None:
    """Read an existing runtime file without creating any fixture directory."""

    if Path(name).name != name:
        raise ConformanceError("opa_runtime_path_invalid")
    root = _workspace_root()
    runtime = RUNTIME.absolute()
    try:
        relative = runtime.relative_to(root)
    except ValueError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    current = root
    for component in relative.parts:
        current = current / component
        if not current.exists() and not current.is_symlink():
            return None
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ConformanceError("opa_runtime_path_invalid") from exc
        if _path_is_link_or_reparse(current) or not stat.S_ISDIR(metadata.st_mode):
            raise ConformanceError("opa_runtime_path_invalid")
    target = runtime / name
    if not target.exists() and not target.is_symlink():
        return None
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    if _path_is_link_or_reparse(target) or not stat.S_ISREG(metadata.st_mode):
        raise ConformanceError("opa_runtime_path_invalid")
    return target


def _snapshot_runtime_path(path: Path, *, required_kind: str | None = None) -> _PathSnapshot:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    if _metadata_is_link_or_reparse(metadata):
        raise ConformanceError("opa_runtime_path_invalid")
    if stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
    elif stat.S_ISREG(metadata.st_mode):
        kind = "file"
    else:
        raise ConformanceError("opa_runtime_path_invalid")
    if required_kind is not None and kind != required_kind:
        raise ConformanceError("opa_runtime_path_invalid")
    digest: str | None = None
    if kind == "file":
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            after = path.lstat()
        except OSError as exc:
            raise ConformanceError("opa_runtime_path_race_detected") from exc
        if (
            _metadata_is_link_or_reparse(after)
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_mode != metadata.st_mode
        ):
            raise ConformanceError("opa_runtime_path_race_detected")
    return _PathSnapshot(
        path=path,
        kind=kind,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        content_digest=digest,
    )


def _assert_runtime_snapshot(snapshot: _PathSnapshot) -> None:
    current = _snapshot_runtime_path(snapshot.path, required_kind=snapshot.kind)
    if current != snapshot:
        raise ConformanceError("opa_runtime_path_race_detected")


def _compose_mount_snapshots() -> tuple[_PathSnapshot, ...]:
    server = _runtime_child_directory("server")
    bundle = server / "redagent.tar.gz"
    config = _runtime_file("config.yaml", required=True)
    persist = _runtime_child_directory("persist")
    return (
        _snapshot_runtime_path(bundle, required_kind="file"),
        _snapshot_runtime_path(config, required_kind="file"),
        _snapshot_runtime_path(persist, required_kind="directory"),
    )


def _assert_compose_mount_snapshots(snapshots: tuple[_PathSnapshot, ...]) -> None:
    for snapshot in snapshots:
        _assert_runtime_snapshot(snapshot)


def _remove_endpoint_state() -> None:
    # IMPORTANT: cleanup must stay inert when no fixture has ever created runtime state.
    target = _existing_runtime_file(OPA_ENDPOINT_STATE)
    if target is None:
        return
    snapshot = _snapshot_runtime_path(target, required_kind="file")
    _assert_runtime_snapshot(snapshot)
    try:
        target.unlink()
    except OSError as exc:
        raise ConformanceError("opa_endpoint_state_cleanup_failed") from exc
    if target.exists() or target.is_symlink():
        raise ConformanceError("opa_endpoint_state_cleanup_failed")


def opa_fixture_lease_path() -> Path:
    """Return a contained lock that serializes all mutable OPA fixture users."""

    root = ROOT.absolute()
    parent = root / ".tmp" / "validation"
    current = root
    for part in (".tmp", "validation"):
        current = current / part
        if current.exists() or current.is_symlink():
            if _path_is_link_or_reparse(current) or not stat.S_ISDIR(current.lstat().st_mode):
                raise ConformanceError("opa_fixture_lease_path_invalid")
        else:
            current.mkdir()
            if _path_is_link_or_reparse(current) or not stat.S_ISDIR(current.lstat().st_mode):
                raise ConformanceError("opa_fixture_lease_path_invalid")
    target = parent / _OPA_FIXTURE_LEASE_FILENAME
    if target.exists() or target.is_symlink():
        if _path_is_link_or_reparse(target) or not stat.S_ISREG(target.lstat().st_mode):
            raise ConformanceError("opa_fixture_lease_path_invalid")
    return target


@contextmanager
def opa_fixture_lease() -> Iterator[None]:
    """Fail fast when another process owns the shared local OPA fixture."""

    try:
        with ValidationLease(opa_fixture_lease_path()):
            yield
    except ValidationLeaseError as exc:
        raise ConformanceError("opa_fixture_already_active") from exc


def _run_docker(
    *arguments: str,
    timeout: int,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _docker_command(*arguments),
        cwd=_workspace_root(),
        env=_safe_docker_environment(),
        check=False,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
    )


def _legacy_fixture_container_ids() -> tuple[str, ...]:
    """List, but never mutate, stale containers from the old implicit project."""

    result = _run_docker(
        "ps",
        "--all",
        "--filter",
        f"label=com.docker.compose.project={_legacy_implicit_project_name()}",
        "--format",
        "{{.ID}}",
        timeout=30,
    )
    if result.returncode:
        raise ConformanceError("opa_legacy_fixture_inventory_failed")
    identifiers = tuple(item.strip() for item in result.stdout.splitlines() if item.strip())
    if len(identifiers) > 8 or any(not _CONTAINER_ID.fullmatch(item) for item in identifiers):
        raise ConformanceError("opa_legacy_fixture_inventory_invalid")
    return identifiers


def legacy_fixture_status() -> dict[str, Any]:
    """Expose stale legacy-project presence without granting a destructive cleanup path."""

    containers = _legacy_fixture_container_ids()
    return {
        "ok": not containers,
        "action": "legacy-status",
        "legacy_project": _legacy_implicit_project_name(),
        "container_ids": list(containers),
        "remediation_required": bool(containers),
    }


def _opa_source(
    source: Path,
    *arguments: str,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise ConformanceError("opa_policy_source_invalid") from exc
    if resolved not in {POLICY.resolve(strict=True), DETECTION_POLICY.resolve(strict=True)}:
        raise ConformanceError("opa_policy_source_invalid")
    command = [
        "run", f"--platform={OPA_PLATFORM}", "--rm", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        f"--user={_container_user()}",
    ]
    if input_text is not None:
        command.append("--interactive")
    command.extend(("-v", f"{resolved}:/policy:ro", _image(), *arguments))
    result = _run_docker(*command, timeout=180, input_text=input_text)
    if result.returncode:
        raise ConformanceError(f"opa_command_failed:{arguments[0]}:{result.returncode}")
    return result


def _opa(*arguments: str) -> subprocess.CompletedProcess[str]:
    return _opa_source(POLICY, *arguments)


def validate() -> dict[str, Any]:
    _opa("fmt", "--fail", "/policy")
    _opa("check", "--strict", "/policy")
    tests = _opa("test", "--fail-on-empty", "--coverage", "/policy")
    # IMPORTANT: detection correlation is a separate non-authorizing validation policy; never
    # add it to the immutable compat_099 authorization bundle without a separately reviewed revision.
    _opa_source(DETECTION_POLICY, "fmt", "--fail", "/policy")
    _opa_source(DETECTION_POLICY, "check", "--strict", "/policy")
    detection_tests = _opa_source(
        DETECTION_POLICY, "test", "--fail-on-empty", "--coverage", "/policy"
    )
    differential_cases = _validate_detection_correlation_differential()
    return {
        "ok": True,
        "validated": ["fmt", "check", "test", "detection-correlation", "differential"],
        "coverage_output": bool(tests.stdout.strip()),
        "detection_coverage_output": bool(detection_tests.stdout.strip()),
        "detection_differential_cases": differential_cases,
    }


def _validate_detection_correlation_differential() -> int:
    """Compare Python and Rego results for every frozen synthetic detection case."""
    from datetime import datetime, timedelta, timezone

    from redagent_platform.campaign_service.contracts import (
        Confidence,
        DetectionSeverity,
        TelemetrySource,
        TypedReferenceV1,
    )
    from redagent_platform.campaign_service.detection_feedback import (
        build_detection_correlation_opa_input,
        correlate_detection_observations,
        ingest_detection_observation,
        promote_detection_observation_by_human,
    )

    corpus_path = ROOT / "tests" / "fixtures" / "detection_feedback" / "frozen-corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    now = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)
    cases = corpus.get("cases") if isinstance(corpus, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ConformanceError("detection_differential_corpus_invalid")
    for case in cases:
        if not isinstance(case, dict):
            raise ConformanceError("detection_differential_corpus_invalid")
        age = timedelta(seconds=float(case["age_seconds"]))
        observation = ingest_detection_observation(
            observation_id=str(case["case_id"]),
            tenant_id="tenant-a",
            engagement_id="engagement-a",
            correlation_key=str(case["correlation_key"]),
            capability_id="zap-controlled-runtime",
            source=TelemetrySource.SIEM,
            source_system="owned-purple-fixture",
            attack_technique_id=str(case["attack_technique_id"]),
            attack_version="18.0",
            confidence=Confidence(str(case["confidence"])),
            severity=DetectionSeverity.MEDIUM,
            evidence_ref=TypedReferenceV1(
                kind="evidence", reference_id=f"evidence-{case['case_id']}", sha256="a" * 64
            ),
            observed_at=now - age,
            ingested_at=now - age + timedelta(seconds=1),
            expires_at=now + timedelta(minutes=1),
        )
        if case["disposition"] == "confirmed":
            observation = promote_detection_observation_by_human(
                observation=observation,
                review_ref=TypedReferenceV1(
                    kind="human-review",
                    reference_id=f"review-{case['case_id']}",
                    sha256="b" * 64,
                ),
                reviewed_at=now - age + timedelta(seconds=2),
            )
        keyword = {
            "observations": (observation,),
            "tenant_id": "tenant-a",
            "engagement_id": "engagement-a",
            "correlation_key": str(case["correlation_key"]),
            "attack_technique_id": str(case["attack_technique_id"]),
            "now": now,
            "max_age_seconds": 300,
        }
        python_result = correlate_detection_observations(**keyword).correlated
        opa_input = build_detection_correlation_opa_input(**keyword)
        evaluated = _opa_source(
            DETECTION_POLICY,
            "eval",
            "--format=json",
            "--data",
            "/policy",
            "--stdin-input",
            "data.redagent.detection_correlation.correlated",
            input_text=json.dumps(opa_input, sort_keys=True, separators=(",", ":")),
        )
        try:
            payload = json.loads(evaluated.stdout)
            opa_result = payload["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ConformanceError("detection_differential_result_invalid") from exc
        if not isinstance(opa_result, bool) or opa_result is not python_result:
            raise ConformanceError(f"detection_differential_mismatch:{case['case_id']}")
    return len(cases)


def _build() -> dict[str, Any]:
    runtime = _runtime_directory()
    private_key, public_key = _signing_keys()
    output = runtime / "redagent.tar.gz"
    verified = runtime / "redagent-verified.tar.gz"
    command = [
        "run", f"--platform={OPA_PLATFORM}", "--rm", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", f"--user={_container_user()}",
        "-v", f"{POLICY}:/policy:ro", "-v", f"{runtime}:/output", _image(),
        "build", "--bundle", "--ignore", "*_test.rego", "--signing-alg", "RS256",
        "--signing-key", f"/output/{private_key.name}",
        "--output", "/output/redagent.tar.gz", "/policy",
    ]
    result = _run_docker(*command, timeout=180)
    if result.returncode or not output.is_file():
        raise ConformanceError(f"opa_command_failed:build:{result.returncode}")
    verify_command = [
        "run", f"--platform={OPA_PLATFORM}", "--rm", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", f"--user={_container_user()}",
        "-v", f"{runtime}:/output", _image(), "build", "--bundle",
        "--verification-key", f"/output/{public_key.name}",
        "--output", "/output/redagent-verified.tar.gz", "/output/redagent.tar.gz",
    ]
    verified_result = _run_docker(*verify_command, timeout=180)
    if verified_result.returncode or not verified.is_file():
        raise ConformanceError(f"opa_command_failed:verify:{verified_result.returncode}")
    with tarfile.open(output, "r:gz") as archive:
        names = tuple(sorted(member.name.removeprefix("/") for member in archive.getmembers() if member.isfile()))
    if ".signatures.json" not in names or any(name.endswith("_test.rego") for name in names):
        raise ConformanceError("opa_bundle_inventory_invalid")
    return {
        "ok": True, "artifact": str(output.relative_to(ROOT)), "size": output.stat().st_size,
        "signature_verified": True, "inventory": names,
    }


def build() -> dict[str, Any]:
    with opa_fixture_lease():
        return _build()


def _build_rollback_fixture() -> dict[str, Any]:
    """Build the single fixed prior revision used only by rollback conformance."""
    runtime = _runtime_directory()
    private_key, public_key = _signing_keys()
    # CRITICAL: avoid recursive pathname deletion in a mutable workspace tree.
    # A unique ignored staging directory can be left for normal workspace cleanup
    # rather than risking an ancestor/junction swap during automated reset.
    try:
        stage = Path(tempfile.mkdtemp(prefix=".rollback-source-", dir=runtime))
        metadata = stage.lstat()
    except OSError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    if _path_is_link_or_reparse(stage) or not stat.S_ISDIR(metadata.st_mode):
        raise ConformanceError("opa_runtime_path_invalid")
    shutil.copytree(POLICY, stage, dirs_exist_ok=True)
    for relative in (Path(".manifest"), Path("data.json"), Path("redagent/decision.rego")):
        path = stage / relative
        source = path.read_text(encoding="utf-8")
        if "r099-v1" not in source:
            raise ConformanceError("opa_rollback_source_revision_missing")
        path.write_text(source.replace("r099-v1", "r099-v0"), encoding="utf-8")
    output = runtime / "redagent-r099-v0.tar.gz"
    verified = runtime / "redagent-r099-v0-verified.tar.gz"
    command = [
        "run", f"--platform={OPA_PLATFORM}", "--rm", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", f"--user={_container_user()}",
        "-v", f"{stage}:/policy:ro", "-v", f"{runtime}:/output", _image(),
        "build", "--bundle", "--ignore", "*_test.rego", "--signing-alg", "RS256",
        "--signing-key", f"/output/{private_key.name}",
        "--output", f"/output/{output.name}", "/policy",
    ]
    result = _run_docker(*command, timeout=180)
    if result.returncode or not output.is_file():
        raise ConformanceError(f"opa_command_failed:build-rollback:{result.returncode}")
    verify_command = [
        "run", f"--platform={OPA_PLATFORM}", "--rm", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", f"--user={_container_user()}",
        "-v", f"{runtime}:/output", _image(), "build", "--bundle",
        "--verification-key", f"/output/{public_key.name}",
        "--output", f"/output/{verified.name}", f"/output/{output.name}",
    ]
    verify = _run_docker(*verify_command, timeout=180)
    if verify.returncode or not verified.is_file():
        raise ConformanceError(f"opa_command_failed:verify-rollback:{verify.returncode}")
    return {
        "ok": True, "revision": "r099-v0", "artifact": str(output.relative_to(ROOT)),
        "signature_verified": True, "size": output.stat().st_size,
    }


def build_rollback_fixture() -> dict[str, Any]:
    with opa_fixture_lease():
        return _build_rollback_fixture()


def _signing_keys() -> tuple[Path, Path]:
    private_path = _runtime_file("signing-private.pem")
    public_path = _runtime_file("signing-public.pem")
    if private_path.is_file() and public_path.is_file():
        return private_path, public_path
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    try:
        os.chmod(private_path, 0o600)
        os.chmod(public_path, 0o644)
    except OSError:
        pass
    return private_path, public_path


def _compose_requires_mount_validation(arguments: tuple[str, ...]) -> bool:
    return any(action in {"up", "start", "restart"} for action in arguments)


def _compose(
    *arguments: str,
    opa_host_port: int | None = None,
    cleanup: bool = False,
) -> subprocess.CompletedProcess[str]:
    root = _workspace_root()
    compose = _compose_file(root)
    mount_snapshots = _compose_mount_snapshots() if _compose_requires_mount_validation(arguments) else ()
    env = _safe_docker_environment()
    if cleanup:
        # Cleanup only needs project labels; do not let damaged image metadata strand containers.
        env["REDAGENT_OPA_IMAGE"] = _CLEANUP_IMAGE_PLACEHOLDER
        env["REDAGENT_OPA_BUNDLE_SERVER_IMAGE"] = _CLEANUP_IMAGE_PLACEHOLDER
    else:
        env["REDAGENT_OPA_IMAGE"] = _image()
        env["REDAGENT_OPA_BUNDLE_SERVER_IMAGE"] = _bundle_server_image()
    # CRITICAL: overwrite ambient identity; POSIX bind mounts must use only
    # the already validated non-root owner that created the runtime artifacts.
    env["REDAGENT_OPA_CONTAINER_USER"] = _container_user()
    if opa_host_port is not None:
        env["REDAGENT_OPA_HOST_PORT"] = str(opa_host_port)
    elif "up" in arguments and (recorded_port := _load_opa_host_port()):
        env["REDAGENT_OPA_HOST_PORT"] = str(recorded_port)
    command = _docker_command(
        "compose",
        "--project-directory",
        str(root),
        "-p",
        _compose_project_name(),
        "-f",
        str(compose),
        *arguments,
    )
    if mount_snapshots:
        _assert_compose_mount_snapshots(mount_snapshots)
    result = subprocess.run(
        command, cwd=root, env=env,
        check=False, capture_output=True, text=True, timeout=240,
    )
    if result.returncode:
        diagnostic = (result.stderr or result.stdout or "").strip().replace("\r", " ").replace("\n", " ")
        raise ConformanceError(f"opa_compose_failed:{result.returncode}:{diagnostic[:512]}")
    return result


def _assert_compose_project_absent() -> None:
    result = _compose("ps", "--all", "--format", "json", cleanup=True)
    if result.stdout.strip() not in {"", "[]"}:
        raise ConformanceError("opa_scoped_cleanup_incomplete")


def _scoped_cleanup() -> None:
    cleanup_error: ConformanceError | None = None
    try:
        _compose("down", "--volumes", "--remove-orphans", cleanup=True)
    except ConformanceError as exc:
        cleanup_error = exc
    try:
        _remove_endpoint_state()
    except ConformanceError as exc:
        cleanup_error = cleanup_error or exc
    if cleanup_error is not None:
        raise ConformanceError(f"opa_scoped_cleanup_failed:{cleanup_error}") from cleanup_error
    _assert_compose_project_absent()


def _cleanup_after_provision_failure(error: ConformanceError) -> None:
    try:
        _scoped_cleanup()
    except ConformanceError as cleanup_error:
        raise ConformanceError(f"{error};opa_scoped_cleanup_failed:{cleanup_error}") from cleanup_error


def status() -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {APP_TOKEN}", "Accept": "application/json"}
    endpoint = opa_endpoint()
    health = httpx.get(f"{endpoint}/health?bundles&plugins", headers=headers, timeout=5)
    plugin = httpx.get(f"{endpoint}/v1/status", headers=headers, timeout=5)
    decision_route = "/v1/data/redagent/decision"
    if health.status_code != 200 or plugin.status_code != 200:
        raise ConformanceError("opa_status_unavailable")
    payload = plugin.json()
    state = payload.get("result", {}) if isinstance(payload, dict) else {}
    bundles = state.get("bundles", {}) if isinstance(state, dict) else {}
    plugins = state.get("plugins", {}) if isinstance(state, dict) else {}
    labels = state.get("labels", {}) if isinstance(state, dict) else {}
    bundle = bundles.get("redagent", {}) if isinstance(bundles, dict) else {}
    bundle_plugin = plugins.get("bundle", {}) if isinstance(plugins, dict) else {}
    if bundle.get("active_revision") != "r099-v1" or bundle_plugin.get("state") != "OK":
        raise ConformanceError("opa_required_revision_not_active")
    return {
        "ok": True, "health": health.json(), "decision_route": decision_route,
        "version": labels.get("version"), "active_revision": bundle.get("active_revision"),
        "bundle_state": bundle_plugin.get("state"),
    }


def _provision() -> dict[str, Any]:
    built = _build()
    _prepare_bundle_server()
    _write_runtime_config()
    attempted_ports: set[int] = set()
    available_port_count = sum(end - start + 1 for start, end in _opa_host_port_ranges())
    for _attempt in range(available_port_count):
        host_port = _allocate_opa_host_port(excluded=attempted_ports)
        attempted_ports.add(host_port)
        try:
            _compose("up", "-d", "--force-recreate", opa_host_port=host_port)
        except ConformanceError as exc:
            _cleanup_after_provision_failure(exc)
            if "port is already allocated" not in str(exc).lower():
                raise
            continue
        try:
            _write_opa_host_port(host_port)
        except (ConformanceError, OSError) as exc:
            write_error = ConformanceError("opa_endpoint_state_write_failed")
            _cleanup_after_provision_failure(write_error)
            raise write_error from exc
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                current = status()
                return {
                    "ok": True,
                    "build": built,
                    "bundle_server": "internal",
                    "opa_host_port": host_port,
                    "runtime": current,
                }
            except (ConformanceError, httpx.HTTPError, ValueError):
                time.sleep(1)
        timeout_error = ConformanceError("opa_startup_timeout")
        _cleanup_after_provision_failure(timeout_error)
        raise timeout_error
    raise ConformanceError("opa_no_available_loopback_port")


def provision() -> dict[str, Any]:
    with opa_fixture_lease():
        if _legacy_fixture_container_ids():
            # CRITICAL: a new project name must not mask old RedAgent containers
            # with retained ports/restart policy; require explicit operator reconciliation.
            raise ConformanceError("opa_legacy_fixture_reconciliation_required")
        return _provision()


def _write_runtime_config() -> None:
    try:
        public_key = _read_pinned_runtime_file(
            _runtime_file("signing-public.pem", required=True),
            max_bytes=_MAX_PUBLIC_KEY_BYTES,
        ).decode("utf-8").rstrip()
    except UnicodeDecodeError as exc:
        raise ConformanceError("opa_runtime_path_invalid") from exc
    indented_key = "\n".join(f"      {line}" for line in public_key.splitlines())
    config = (
        "services:\n"
        "  redagent_bundle:\n"
        "    url: http://bundle-server:8080\n"
        "bundles:\n"
        "  redagent:\n"
        "    service: redagent_bundle\n"
        "    resource: redagent.tar.gz\n"
        "    persist: true\n"
        "    signing:\n"
        "      keyid: default\n"
        "    polling:\n"
        "      min_delay_seconds: 1\n"
        "      max_delay_seconds: 2\n"
        "keys:\n"
        "  default:\n"
        "    algorithm: RS256\n"
        "    key: |\n"
        f"{indented_key}\n"
        "persistence_directory: /bundles\n"
        "status:\n"
        "  console: true\n"
        "decision_logs:\n"
        "  console: true\n"
    )
    _runtime_child_directory("persist")
    _runtime_file("config.yaml").write_text(config, encoding="utf-8")


def _loopback_port_available(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", port))
    except OSError:
        return False
    return True


def _allocate_opa_host_port(*, excluded: set[int] | None = None) -> int:
    excluded = excluded or set()
    for start, end in _opa_host_port_ranges():
        for port in range(start, end + 1):
            if port not in excluded and _loopback_port_available(port):
                return port
    raise ConformanceError("opa_no_available_loopback_port")


def _prepare_bundle_server() -> Path:
    source = _runtime_file("redagent.tar.gz", required=True)
    source_bytes = _read_pinned_runtime_file(source, max_bytes=_MAX_BUNDLE_BYTES)
    server_root = _runtime_child_directory("server")
    bundle_path = server_root / "redagent.tar.gz"
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=server_root,
            prefix=".redagent.tar.gz-",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as destination:
            written = destination.write(source_bytes)
            if written != len(source_bytes):
                raise ConformanceError("opa_bundle_prepare_failed")
            destination.flush()
            os.fsync(destination.fileno())
        # CRITICAL: revalidate immediately before replacement; a junction must not redirect the mount source.
        if _runtime_child_directory("server") != server_root:
            raise ConformanceError("opa_runtime_path_invalid")
        if bundle_path.exists() or bundle_path.is_symlink():
            metadata = bundle_path.lstat()
            if _path_is_link_or_reparse(bundle_path) or not stat.S_ISREG(metadata.st_mode):
                raise ConformanceError("opa_runtime_path_invalid")
        os.replace(temporary, bundle_path)
        temporary = None
    except ConformanceError:
        raise
    except OSError as exc:
        raise ConformanceError("opa_bundle_prepare_failed") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return bundle_path


def stop() -> dict[str, Any]:
    with opa_fixture_lease():
        _scoped_cleanup()
        return {"ok": True, "action": "stop"}


def _reset() -> dict[str, Any]:
    _scoped_cleanup()
    # CRITICAL: no automated recursive deletion under a mutable workspace path.
    # Runtime artifacts are ignored and can be reconciled only by an authorized
    # operator after inspecting the workspace boundary.
    return {"ok": True, "action": "reset", "runtime_preserved": True}


def reset() -> dict[str, Any]:
    # CRITICAL: an invalid lock cannot prove the absence of an active fixture owner.
    # Never tear down shared containers or the mounted runtime without the lease.
    with opa_fixture_lease():
        return _reset()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "build", "build-rollback", "provision", "status", "stop", "reset", "legacy-status"))
    action = parser.parse_args().action
    try:
        if action == "validate":
            result = validate()
        elif action == "build":
            result = build()
        elif action == "build-rollback":
            result = build_rollback_fixture()
        elif action == "provision":
            result = provision()
        elif action == "status":
            result = status()
        elif action == "stop":
            result = stop()
        elif action == "legacy-status":
            result = legacy_fixture_status()
        else:
            result = reset()
    except (ConformanceError, OSError, subprocess.SubprocessError, httpx.HTTPError) as exc:
        result = {"ok": False, "error": str(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
