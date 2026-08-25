"""Cross-platform, fail-fast serialization for authoritative validation writers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess


_LEASE_DIRECTORY = (".tmp", "validation")
_LEASE_FILENAME = "authoritative-validation.lock"
_PLATFORM_CONTEXT_FILENAME = "authoritative-validation-platform.json"
_PLATFORM_CONTEXT_SCHEMA = "r118-validation-platform-v1"
_MAX_PLATFORM_CONTEXT_BYTES = 512
_LEASE_GIT_TIMEOUT_SECONDS = 30
_LEASE_GIT_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}


class ValidationLeaseError(RuntimeError):
    """Raised when another authoritative validation writer already owns the lease."""


class ValidationLeaseCapability:
    """Unforgeable-by-convention proof that an authoritative lease remains live."""

    __slots__ = ("_lease", "_path")

    def __init__(self, lease: "ValidationLease") -> None:
        self._lease = lease
        self._path = lease._path

    def _assert_active(self) -> None:
        if self._lease._descriptor is None:
            raise ValidationLeaseError("authoritative validation lease is not held")


def require_active_validation_lease(capability: object) -> None:
    """Reject mutable helper use unless it received a live writer capability."""

    if not isinstance(capability, ValidationLeaseCapability):
        raise ValidationLeaseError("authoritative validation lease capability is required")
    capability._assert_active()


def require_authoritative_validation_lease(capability: object, root: Path) -> None:
    """Require the live capability for exactly this workspace's writer coordinate."""

    require_active_validation_lease(capability)
    assert isinstance(capability, ValidationLeaseCapability)
    expected = authoritative_validation_lease_path(root).absolute()
    if capability._path != expected:
        raise ValidationLeaseError("authoritative validation capability is not bound to the canonical lease")


def authoritative_validation_lease_path(root: Path) -> Path:
    """Return the one workspace-local coordinate shared by all authoritative writers."""

    return root.joinpath(*_LEASE_DIRECTORY, _LEASE_FILENAME)


def validated_authoritative_validation_lease_path(root: Path) -> Path:
    """Require the canonical writer coordinate to remain a regular ignored file path."""

    workspace = Path(root).absolute()
    target = authoritative_validation_lease_path(workspace).absolute()
    if target.parent != workspace.joinpath(*_LEASE_DIRECTORY).absolute():
        raise ValidationLeaseError("authoritative validation lease escaped the workspace")
    if target.exists() or target.is_symlink():
        try:
            metadata = target.lstat()
        except OSError as exc:
            raise ValidationLeaseError("authoritative validation lease target cannot be inspected") from exc
        if _is_linklike(target, metadata) or not stat.S_ISREG(metadata.st_mode):
            raise ValidationLeaseError("authoritative validation lease target is not a regular file")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(_LEASE_GIT_ENVIRONMENT)
    try:
        completed = subprocess.run(
            (
                "git",
                "--no-replace-objects",
                "check-ignore",
                "--quiet",
                "--",
                str(target.relative_to(workspace)),
            ),
            cwd=workspace,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=_LEASE_GIT_TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationLeaseError("authoritative validation lease ignore check failed") from exc
    if completed.returncode != 0:
        raise ValidationLeaseError("authoritative validation lease path must be ignored by Git")
    return target


def authoritative_validation_platform_context_path(root: Path) -> Path:
    """Return the persistent fail-closed OS-context marker for one checkout."""

    return root.joinpath(*_LEASE_DIRECTORY, _PLATFORM_CONTEXT_FILENAME)


def _validation_platform() -> str:
    return "windows" if os.name == "nt" else "posix"


def _is_linklike(path: Path, metadata: os.stat_result) -> bool:
    return path.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & 0x00000400)


def _platform_context_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return the attributes that must remain stable for one marker descriptor."""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _assert_regular_platform_context(path: Path, metadata: os.stat_result) -> None:
    if _is_linklike(path, metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationLeaseError("validation platform context is not a regular file")


def _ensure_regular_parent(parent: Path) -> None:
    """Create only the lease parent, rejecting link-like directories on the way."""

    missing: list[Path] = []
    current = parent
    while True:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            missing.append(current)
            if current.parent == current:
                raise ValidationLeaseError("validation lease parent cannot be created")
            current = current.parent
            continue
        if _is_linklike(current, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise ValidationLeaseError("validation lease parent is not a regular directory")
        break

    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            pass
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise ValidationLeaseError("validation lease parent cannot be initialized") from exc
        if _is_linklike(directory, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise ValidationLeaseError("validation lease parent is not a regular directory")


def _read_platform_context(path: Path) -> str:
    try:
        initial = path.lstat()
    except OSError as exc:
        raise ValidationLeaseError("validation platform context cannot be inspected") from exc
    _assert_regular_platform_context(path, initial)
    if initial.st_size <= 0 or initial.st_size > _MAX_PLATFORM_CONTEXT_BYTES:
        raise ValidationLeaseError("validation platform context is invalid")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_PLATFORM_CONTEXT_BYTES
        ):
            raise ValidationLeaseError("validation platform context is invalid")
        # CRITICAL: O_NOFOLLOW is unavailable on some Windows Python builds.
        # A descriptor that no longer identifies the lstat-pinned leaf must fail closed.
        if _platform_context_identity(metadata) != _platform_context_identity(initial):
            raise ValidationLeaseError("validation platform context changed while reading")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise ValidationLeaseError("validation platform context is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if _platform_context_identity(metadata) != _platform_context_identity(after):
            raise ValidationLeaseError("validation platform context changed while reading")
        current = path.lstat()
        _assert_regular_platform_context(path, current)
        if _platform_context_identity(initial) != _platform_context_identity(current):
            raise ValidationLeaseError("validation platform context changed while reading")
    except ValidationLeaseError:
        raise
    except OSError as exc:
        raise ValidationLeaseError("validation platform context cannot be opened") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationLeaseError("validation platform context is invalid") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"platform", "schema_version"}
        or payload.get("schema_version") != _PLATFORM_CONTEXT_SCHEMA
        or payload.get("platform") not in {"windows", "posix"}
    ):
        raise ValidationLeaseError("validation platform context is invalid")
    return str(payload["platform"])


def _create_platform_context(path: Path, platform_name: str) -> None:
    payload = json.dumps(
        {"platform": platform_name, "schema_version": _PLATFORM_CONTEXT_SCHEMA},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise ValidationLeaseError("validation platform context cannot be inspected") from exc
    if existing is not None:
        _assert_regular_platform_context(path, existing)
        return
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        try:
            existing = path.lstat()
        except OSError as exc:
            raise ValidationLeaseError("validation platform context cannot be inspected") from exc
        _assert_regular_platform_context(path, existing)
        return
    except OSError as exc:
        raise ValidationLeaseError("validation platform context cannot be created") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValidationLeaseError("validation platform context is not a regular file")
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise ValidationLeaseError("validation platform context could not be written")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        current = path.lstat()
        _assert_regular_platform_context(path, current)
        if _platform_context_identity(after) != _platform_context_identity(current):
            raise ValidationLeaseError("validation platform context changed while creating")
    except ValidationLeaseError:
        raise
    except OSError as exc:
        raise ValidationLeaseError("validation platform context could not be written") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def bind_authoritative_validation_platform(root: Path, capability: object) -> str:
    """Bind this checkout to its first writer OS; cross Windows/WSL use fails closed.

    Windows byte-range locks and POSIX flock locks are not an interoperability guarantee
    on a mounted checkout.  An exclusive immutable marker gives the first writer a
    durable platform claim before it can mutate a venv, cache, fixture, or receipt.
    """

    require_authoritative_validation_lease(capability, root)
    parent = authoritative_validation_lease_path(root).absolute().parent
    _ensure_regular_parent(parent)
    context = authoritative_validation_platform_context_path(root).absolute()
    if context.parent != parent:
        raise ValidationLeaseError("validation platform context is outside the canonical lease directory")
    platform_name = _validation_platform()
    _create_platform_context(context, platform_name)
    bound_platform = _read_platform_context(context)
    if bound_platform != platform_name:
        raise ValidationLeaseError(
            "concurrent Windows/WSL access to this checkout is unqualified; "
            f"validation is bound to {bound_platform}"
        )
    return bound_platform


class ValidationLease:
    """Hold a non-blocking OS descriptor lock until the surrounding run exits."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path).absolute()
        self._descriptor: int | None = None
        self._capability = ValidationLeaseCapability(self)

    def capability(self) -> ValidationLeaseCapability:
        """Return the capability only while this lease owns the descriptor."""

        if self._descriptor is None:
            raise ValidationLeaseError("authoritative validation lease is not held")
        return self._capability

    def __enter__(self) -> "ValidationLease":
        if self._descriptor is not None:
            raise ValidationLeaseError("validation lease is already held by this runner")
        try:
            # IMPORTANT: this narrow pre-lock mkdir only creates the lock parent;
            # venvs, caches, receipts, and reports are created after acquisition.
            _ensure_regular_parent(self._path.parent)
        except OSError as exc:
            raise ValidationLeaseError("validation lease parent cannot be initialized") from exc
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._path, flags, 0o600)
        except OSError as exc:
            raise ValidationLeaseError("validation lease target cannot be opened") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValidationLeaseError("validation lease target is not a regular file")
            os.set_inheritable(descriptor, False)
            self._prepare_region(descriptor, metadata.st_size)
        except ValidationLeaseError:
            os.close(descriptor)
            raise
        except OSError as exc:
            os.close(descriptor)
            raise ValidationLeaseError("validation lease target cannot be initialized") from exc
        try:
            self._acquire(descriptor)
        except OSError as exc:
            os.close(descriptor)
            raise ValidationLeaseError("authoritative validation already active") from exc
        self._descriptor = descriptor
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is None:
            return
        try:
            self._release(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _prepare_region(descriptor: int, size: int) -> None:
        if os.name == "nt":
            if size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)

    @staticmethod
    def _acquire(descriptor: int) -> None:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _release(descriptor: int) -> None:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            return
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)
