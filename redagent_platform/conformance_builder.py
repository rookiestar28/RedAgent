"""Digest-pinned, credential-isolated BuildKit lifecycle for local conformance images."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tarfile
import tempfile
from typing import Callable, Iterator, Mapping


_LOCK_NAME = "conformance-buildkit.json"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PURPOSE = re.compile(r"[a-z0-9-]{1,16}")
_TOKEN = re.compile(r"[0-9a-f]{16}")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_CONFIG_MEMBER = re.compile(r"(?:blobs/sha256/)?([0-9a-f]{64})(?:\.json)?")
_MAX_IMAGE_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_IMAGE_MANIFEST_BYTES = 64 * 1024
_MAX_IMAGE_CONFIG_BYTES = 1024 * 1024
_REMOVED_DOCKER_ENV = {
    "BUILDKIT_HOST",
    "BUILDX_BUILDER",
    "DOCKER_AUTH_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
}


class ConformanceBuilderError(RuntimeError):
    """A pinned conformance builder could not be safely created or removed."""


@dataclass(frozen=True, slots=True)
class PinnedConformanceBuilder:
    name: str
    environment: Mapping[str, str]

    @property
    def build_prefix(self) -> tuple[str, ...]:
        return ("buildx", "build", "--builder", self.name)


@contextmanager
def isolated_docker_environment(
    repo_root: str | Path,
    *,
    inherited_environment: Mapping[str, str] | None = None,
) -> Iterator[dict[str, str]]:
    """Provide a contained empty Docker config without remote/credential overrides."""

    root = Path(os.path.abspath(repo_root))
    inherited = os.environ if inherited_environment is None else inherited_environment
    environment = {key: value for key, value in inherited.items() if key.upper() not in _REMOVED_DOCKER_ENV}
    with _contained_runtime_root(root) as runtime_root:
        with tempfile.TemporaryDirectory(prefix="docker-cli-", dir=runtime_root) as directory:
            config_root = Path(directory)
            config_path = config_root / "config.json"
            config_path.write_text("{}\n", encoding="utf-8")
            try:
                config_path.chmod(0o600)
                config_root.chmod(0o700)
            except OSError:  # pragma: no cover - Windows ACLs remain authoritative
                pass
            environment["DOCKER_CONFIG"] = str(config_root)
            yield environment


@contextmanager
def pinned_conformance_builder(
    repo_root: str | Path,
    *,
    purpose: str,
    inherited_environment: Mapping[str, str] | None = None,
    token_factory: Callable[[], str] = lambda: secrets.token_hex(8),
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Iterator[PinnedConformanceBuilder]:
    """Create, bootstrap, select, and remove one exact digest-pinned builder."""

    root = Path(os.path.abspath(repo_root))
    if not _PURPOSE.fullmatch(purpose):
        raise ConformanceBuilderError("conformance_builder_purpose_invalid")
    token = token_factory()
    if not _TOKEN.fullmatch(token):
        raise ConformanceBuilderError("conformance_builder_token_invalid")
    name = f"redagent-{purpose}-{token}"
    lock = _load_lock(root)
    reference = str(lock["reference"])
    created = False
    body_error: BaseException | None = None

    with isolated_docker_environment(root, inherited_environment=inherited_environment) as environment:
        inspect = _invoke(run, root, environment, ("buildx", "inspect", name), timeout=30)
        if inspect.returncode == 0:
            raise ConformanceBuilderError("conformance_builder_name_collision")
        create = _invoke(
            run,
            root,
            environment,
            (
                "buildx",
                "create",
                "--name",
                name,
                "--driver",
                "docker-container",
                "--driver-opt",
                f"image={reference}",
            ),
            timeout=120,
        )
        if create.returncode != 0:
            raise ConformanceBuilderError(f"conformance_builder_create_failed:{_bounded(create.stderr)}")
        created = True
        try:
            bootstrap = _invoke(
                run, root, environment, ("buildx", "inspect", "--bootstrap", name), timeout=180
            )
            if bootstrap.returncode != 0:
                raise ConformanceBuilderError(
                    f"conformance_builder_bootstrap_failed:{_bounded(bootstrap.stderr)}"
                )
            yield PinnedConformanceBuilder(name=name, environment=dict(environment))
        except BaseException as exc:
            body_error = exc
            raise
        finally:
            if created:
                cleanup = _invoke(run, root, environment, ("buildx", "rm", name), timeout=120)
                if cleanup.returncode != 0 and body_error is None:
                    raise ConformanceBuilderError(f"conformance_builder_cleanup_failed:{_bounded(cleanup.stderr)}")


def attest_docker_image_config(
    repo_root: str | Path,
    image: str,
    expected_digest: str,
    *,
    inherited_environment: Mapping[str, str] | None = None,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    """Verify the portable image config digest without trusting store-specific `.Id`."""

    root = Path(os.path.abspath(repo_root))
    if not _IMAGE.fullmatch(image) or not _DIGEST.fullmatch(expected_digest):
        raise ConformanceBuilderError("conformance_image_attestation_input_invalid")
    with isolated_docker_environment(root, inherited_environment=inherited_environment) as environment:
        with _contained_runtime_root(root) as runtime_root, tempfile.TemporaryDirectory(
            prefix="image-attest-", dir=runtime_root
        ) as directory:
            archive_path = Path(directory) / "image.tar"
            saved = _invoke(
                run,
                root,
                environment,
                ("image", "save", "--output", str(archive_path), image),
                timeout=180,
            )
            if saved.returncode != 0:
                raise ConformanceBuilderError(f"conformance_image_save_failed:{_bounded(saved.stderr)}")
            if (
                archive_path.is_symlink()
                or not archive_path.is_file()
                or not 0 < archive_path.stat().st_size <= _MAX_IMAGE_ARCHIVE_BYTES
            ):
                raise ConformanceBuilderError("conformance_image_archive_invalid")
            with tarfile.open(archive_path, mode="r:*") as archive:
                manifest_bytes = _read_regular_member(
                    archive, "manifest.json", maximum=_MAX_IMAGE_MANIFEST_BYTES
                )
                manifest = json.loads(manifest_bytes)
                if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
                    raise ConformanceBuilderError("conformance_image_manifest_invalid")
                entry = manifest[0]
                tags = entry.get("RepoTags")
                config_member = entry.get("Config")
                if not isinstance(tags, list) or tags != [image] or not isinstance(config_member, str):
                    raise ConformanceBuilderError("conformance_image_manifest_binding_invalid")
                match = _CONFIG_MEMBER.fullmatch(config_member)
                if match is None:
                    raise ConformanceBuilderError("conformance_image_config_member_invalid")
                config_bytes = _read_regular_member(
                    archive, config_member, maximum=_MAX_IMAGE_CONFIG_BYTES
                )
                observed = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
                if observed != "sha256:" + match.group(1) or observed != expected_digest:
                    raise ConformanceBuilderError("conformance_image_config_digest_mismatch")
                return observed


@contextmanager
def _contained_runtime_root(root: Path) -> Iterator[Path]:
    lexical_root = Path(os.path.abspath(root))
    _assert_real_directory(lexical_root)
    runtime_parent = _ensure_real_child(lexical_root, ".tmp")
    runtime = _ensure_real_child(runtime_parent, "conformance-builders")
    # CRITICAL: keep the final parent pinned while tempfile creates and removes children.
    with _pinned_directory(runtime):
        yield runtime


def _is_linklike(path: Path, metadata: os.stat_result) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    return bool(getattr(metadata, "st_file_attributes", 0) & 0x00000400)


def _assert_real_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConformanceBuilderError("conformance_builder_runtime_unavailable") from exc
    if _is_linklike(path, metadata):
        raise ConformanceBuilderError("conformance_builder_runtime_reparse_forbidden")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConformanceBuilderError("conformance_builder_runtime_not_directory")


def _directory_identity(path: Path) -> tuple[int, int, int]:
    _assert_real_directory(path)
    metadata = path.lstat()
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _ensure_real_child(parent: Path, name: str) -> Path:
    child = parent / name
    with _pinned_directory(parent) as descriptor:
        parent_identity = _directory_identity(parent)
        if child.exists() or child.is_symlink():
            _assert_real_directory(child)
        else:
            try:
                if descriptor is not None and os.name == "posix":
                    os.mkdir(name, dir_fd=descriptor)
                else:
                    child.mkdir()
            except FileExistsError:
                pass
            _assert_real_directory(child)
        if _directory_identity(parent) != parent_identity:
            raise ConformanceBuilderError("conformance_builder_runtime_parent_changed")
    return child


@contextmanager
def _pinned_directory(path: Path) -> Iterator[int | None]:
    identity = _directory_identity(path)
    descriptor: int | None = None
    windows_handle: int | None = None
    try:
        if os.name == "nt":
            windows_handle = _lock_windows_directory_against_delete(path)
        else:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
        if _directory_identity(path) != identity:
            raise ConformanceBuilderError("conformance_builder_runtime_parent_changed")
        yield descriptor
        if _directory_identity(path) != identity:
            raise ConformanceBuilderError("conformance_builder_runtime_parent_changed")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if windows_handle is not None:
            _close_windows_handle(windows_handle)


def _lock_windows_directory_against_delete(path: Path) -> int:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000,
        0x00000001 | 0x00000002,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise ConformanceBuilderError("conformance_builder_runtime_lock_failed")
    return int(handle)


def _close_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(handle)):
        raise ConformanceBuilderError("conformance_builder_runtime_unlock_failed")


def _load_lock(root: Path) -> dict[str, object]:
    path = root / "config" / _LOCK_NAME
    if path.is_symlink() or not path.is_file():
        raise ConformanceBuilderError("conformance_builder_lock_missing")
    value = json.loads(path.read_text(encoding="utf-8"))
    expected_keys = {
        "schema_version",
        "name",
        "version",
        "index_digest",
        "linux_amd64_digest",
        "reference",
        "platform",
        "purpose",
        "production_qualified",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ConformanceBuilderError("conformance_builder_lock_schema_invalid")
    if (
        value["schema_version"] != "1.0"
        or value["name"] != "moby/buildkit"
        or value["version"] != "v0.32.2"
        or value["platform"] != "linux/amd64"
        or value["purpose"] != "local-conformance-builder-only"
        or value["production_qualified"] is not False
        or not isinstance(value["index_digest"], str)
        or not _DIGEST.fullmatch(value["index_digest"])
        or not isinstance(value["linux_amd64_digest"], str)
        or not _DIGEST.fullmatch(value["linux_amd64_digest"])
        or value["reference"]
        != f"docker.io/moby/buildkit:v0.32.2@{value['index_digest']}"
    ):
        raise ConformanceBuilderError("conformance_builder_lock_value_invalid")
    return value


def _invoke(
    run: Callable[..., subprocess.CompletedProcess[str]],
    root: Path,
    environment: Mapping[str, str],
    arguments: tuple[str, ...],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return run(
        ["docker", *arguments],
        cwd=root,
        env=dict(environment),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _bounded(value: str | None) -> str:
    return (value or "unknown").strip().replace("\r", " ").replace("\n", " ")[:200]


def _read_regular_member(archive: tarfile.TarFile, name: str, *, maximum: int) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError as exc:
        raise ConformanceBuilderError("conformance_image_archive_member_missing") from exc
    if not member.isfile() or not 0 < member.size <= maximum:
        raise ConformanceBuilderError("conformance_image_archive_member_invalid")
    stream = archive.extractfile(member)
    if stream is None:
        raise ConformanceBuilderError("conformance_image_archive_member_unreadable")
    data = stream.read(maximum + 1)
    if len(data) != member.size:
        raise ConformanceBuilderError("conformance_image_archive_member_size_mismatch")
    return data
