"""Contained project-venv and scratch-path guards for authoritative validation."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import sysconfig
import threading
import time
from typing import Callable, Mapping, Sequence

from redagent_platform.gate_lease import require_authoritative_validation_lease


_MAX_VENV_CONFIG_BYTES = 16 * 1024
_VENV_NAMES = {".venv", ".venv-wsl"}


class GateRuntimeError(RuntimeError):
    """Raised when the authoritative runner lacks a safe project runtime."""


@dataclass(frozen=True, slots=True)
class BoundedCommandResult:
    """Small, captured result for a trusted command with a strict stdout cap."""

    returncode: int
    stdout: bytes


@dataclass(slots=True)
class ContainedProcess:
    """A child bound to an OS-level containment boundary for its whole lifetime."""

    process: subprocess.Popen[bytes]
    windows_job_handle: int | None = None


_CREATE_SUSPENDED = 0x00000004
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000


def _uses_windows_process_containment() -> bool:
    return os.name == "nt"


def _uses_windows_runtime_paths() -> bool:
    return os.name == "nt"


def _create_windows_kill_job() -> int | None:
    """Create a kill-on-close Job Object before starting an untrusted child."""

    if not _uses_windows_process_containment():
        return None
    import ctypes
    from ctypes import wintypes

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    information.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(
        job,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        kernel32.CloseHandle(job)
        return None
    return int(job)


def _close_windows_job(job_handle: int | None) -> None:
    if not _uses_windows_process_containment() or not job_handle:
        return
    import ctypes

    try:
        ctypes.windll.kernel32.CloseHandle(job_handle)
    except (AttributeError, OSError):  # pragma: no cover - Windows API defensive path
        pass


def _terminate_windows_job(job_handle: int | None) -> bool:
    if not _uses_windows_process_containment() or not job_handle:
        return False
    import ctypes

    try:
        return bool(ctypes.windll.kernel32.TerminateJobObject(job_handle, 1))
    except (AttributeError, OSError):  # pragma: no cover - Windows API defensive path
        return False


def _assign_windows_kill_job(process: subprocess.Popen[bytes], job_handle: int | None) -> bool:
    if not _uses_windows_process_containment() or not job_handle:
        return False
    import ctypes
    from ctypes import wintypes

    raw_handle = getattr(process, "_handle", None)
    if raw_handle is None:
        return False
    kernel32 = ctypes.windll.kernel32
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    return bool(
        kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(job_handle),
            wintypes.HANDLE(raw_handle),
        )
    )


def _resume_windows_process(process: subprocess.Popen[bytes]) -> bool:
    if not _uses_windows_process_containment():
        return False
    import ctypes
    from ctypes import wintypes

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = (wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = (wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = (wintypes.HANDLE,)
    kernel32.ResumeThread.restype = wintypes.DWORD
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    invalid_handle = ctypes.c_void_p(-1).value
    if not snapshot or int(snapshot) == invalid_handle:
        return False
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        found = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
        while found:
            if entry.th32OwnerProcessID == process.pid:
                thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)  # THREAD_SUSPEND_RESUME
                if not thread:
                    return False
                try:
                    return kernel32.ResumeThread(thread) != 0xFFFFFFFF
                finally:
                    kernel32.CloseHandle(thread)
            entry.dwSize = ctypes.sizeof(entry)
            found = bool(kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
        return False
    finally:
        kernel32.CloseHandle(snapshot)


def _terminate_suspended_windows_process(
    process: subprocess.Popen[bytes],
    job_handle: int | None,
) -> None:
    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    finally:
        _close_windows_job(job_handle)


def start_contained_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    stdin: int | None,
    stdout: int | None,
    stderr: int | None,
    text: bool = False,
    popen_factory: Callable[..., subprocess.Popen[bytes]] | None = None,
) -> ContainedProcess:
    """Start a child with the available platform containment boundary.

    Windows uses a pre-assigned kill-on-close Job Object. POSIX starts a new
    process group only; it cannot prove containment of a child that escapes
    with ``setsid`` or ``setpgid``.
    """

    launcher = subprocess.Popen if popen_factory is None else popen_factory
    kwargs: dict[str, object] = {
        "cwd": cwd,
        "env": dict(environment),
        "stdin": stdin,
        "stdout": stdout,
        "stderr": stderr,
        "text": text,
        "shell": False,
    }
    if not _uses_windows_process_containment():
        kwargs["start_new_session"] = True
        return ContainedProcess(process=launcher(tuple(argv), **kwargs))

    job_handle = _create_windows_kill_job()
    if job_handle is None:
        raise OSError("validation process Job Object could not be created")
    # CRITICAL: child execution remains suspended until it is assigned to the
    # kill-on-close Job Object; post-start assignment permits an escape race.
    # IMPORTANT: keep the canonical Win32 bits platform-independent so POSIX can test this branch
    # without mutating process-global os.name or depending on Windows-only subprocess attributes.
    kwargs["creationflags"] = _CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED
    try:
        process = launcher(tuple(argv), **kwargs)
    except Exception:
        _close_windows_job(job_handle)
        raise
    if not _assign_windows_kill_job(process, job_handle):
        _terminate_suspended_windows_process(process, job_handle)
        raise OSError("validation process could not be assigned to its Job Object")
    if not _resume_windows_process(process):
        _terminate_suspended_windows_process(process, job_handle)
        raise OSError("validation process could not be resumed after Job assignment")
    return ContainedProcess(process=process, windows_job_handle=job_handle)


def terminate_contained_process(
    contained: ContainedProcess,
    *,
    wait_timeout_seconds: float = 1.0,
) -> bool:
    """Terminate the platform containment boundary for a bounded command.

    On Windows this is the Job Object. On POSIX it is only the initial process
    group, not a guarantee over descendants that deliberately escape it.
    """

    process = contained.process
    try:
        timeout = max(0.0, float(wait_timeout_seconds))
    except (TypeError, ValueError):
        timeout = 0.0
    if _uses_windows_process_containment():
        terminated = _terminate_windows_job(contained.windows_job_handle)
        _close_windows_job(contained.windows_job_handle)
        contained.windows_job_handle = None
        if not terminated and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        if timeout > 0:
            try:
                process.wait(timeout=timeout)
            except (OSError, subprocess.TimeoutExpired):
                pass
        return process.poll() is not None

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, OSError, ProcessLookupError):
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    if timeout > 0:
        try:
            process.wait(timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        os.killpg(process.pid, 0)
    except (AttributeError, OSError, ProcessLookupError):
        return process.poll() is not None
    return False


def run_bounded_stdout(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    max_output_bytes: int,
) -> BoundedCommandResult | None:
    """Run a trusted command without allowing timeout or stdout to grow unbounded.

    The reader signals as soon as it observes ``max_output_bytes + 1`` and the
    parent kills the command.  Stderr is deliberately discarded because callers
    need only deterministic Git control output, never diagnostics in evidence.
    """

    if (
        not argv
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
        or isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes <= 0
    ):
        raise GateRuntimeError("bounded command parameters are invalid")
    try:
        contained = start_contained_process(
            argv,
            cwd=cwd,
            environment=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    process = contained.process
    if process.stdout is None:
        terminate_contained_process(contained, wait_timeout_seconds=1)
        return None

    captured = bytearray()
    exceeded = threading.Event()
    reader_failed = threading.Event()
    reader_done = threading.Event()

    def read_stdout() -> None:
        try:
            while True:
                chunk = process.stdout.read(min(65536, max_output_bytes + 1 - len(captured)))
                if not chunk:
                    return
                captured.extend(chunk)
                if len(captured) > max_output_bytes:
                    exceeded.set()
                    return
        except OSError:
            reader_failed.set()
        finally:
            reader_done.set()

    reader = threading.Thread(target=read_stdout, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    terminated = False

    def stop_tree() -> None:
        nonlocal terminated
        if terminated:
            return
        remaining = max(0.0, deadline - time.monotonic())
        terminate_contained_process(contained, wait_timeout_seconds=min(1.0, remaining))
        terminated = True

    try:
        while process.poll() is None:
            if exceeded.is_set() or reader_failed.is_set():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            reader_done.wait(timeout=min(0.05, remaining))
        if process.poll() is None:
            stop_tree()
        while not reader_done.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                stop_tree()
                break
            reader_done.wait(timeout=min(0.05, remaining))
    finally:
        # A successful parent may still have a helper descendant holding stdout.
        # Always close the containment boundary before returning any result.
        stop_tree()
        try:
            process.stdout.close()
        except OSError:
            pass
        reader_done.wait(timeout=min(0.1, max(0.0, deadline - time.monotonic())))
    if timed_out or exceeded.is_set() or reader_failed.is_set() or not reader_done.is_set():
        return None
    if len(captured) > max_output_bytes:
        return None
    if not isinstance(process.returncode, int):
        return None
    return BoundedCommandResult(returncode=process.returncode, stdout=bytes(captured))


def expected_project_venv_name() -> str:
    return ".venv" if os.name == "nt" else ".venv-wsl"


def _is_linklike(path: Path, metadata: os.stat_result) -> bool:
    return path.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & 0x00000400)


def _assert_real_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GateRuntimeError(f"validation runtime directory is unavailable: {path}") from exc
    if _is_linklike(path, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise GateRuntimeError(f"validation runtime directory is not a real directory: {path}")


def _assert_real_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GateRuntimeError(f"validation runtime file is unavailable: {path}") from exc
    if _is_linklike(path, metadata) or not stat.S_ISREG(metadata.st_mode):
        raise GateRuntimeError(f"validation runtime file is not a real file: {path}")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _read_pinned_venv_configuration(config: Path) -> bytes:
    """Return a bounded config only when its path and descriptor remain identical."""

    try:
        initial = config.lstat()
    except OSError as exc:
        raise GateRuntimeError("validation venv configuration cannot be read") from exc
    if _is_linklike(config, initial) or not stat.S_ISREG(initial.st_mode):
        raise GateRuntimeError("validation venv configuration is not a real file")
    if initial.st_size < 0 or initial.st_size > _MAX_VENV_CONFIG_BYTES:
        raise GateRuntimeError("validation venv configuration exceeds the bounded size")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(config, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > _MAX_VENV_CONFIG_BYTES:
            raise GateRuntimeError("validation venv configuration exceeds the bounded size")
        # CRITICAL: O_NOFOLLOW is absent on some Windows Python builds; pin the
        # leaf identity so a reparse or replacement cannot redirect the read.
        if _file_identity(initial) != _file_identity(before):
            raise GateRuntimeError("validation venv configuration changed while reading")
        content = bytearray()
        while len(content) < before.st_size:
            chunk = os.read(descriptor, min(65536, before.st_size - len(content)))
            if not chunk:
                raise GateRuntimeError("validation venv configuration is truncated")
            content.extend(chunk)
        after = os.fstat(descriptor)
        current = config.lstat()
        if (
            _is_linklike(config, current)
            or not stat.S_ISREG(current.st_mode)
            or _file_identity(before) != _file_identity(after)
            or _file_identity(initial) != _file_identity(current)
        ):
            raise GateRuntimeError("validation venv configuration changed while reading")
        return bytes(content)
    except GateRuntimeError:
        raise
    except OSError as exc:
        raise GateRuntimeError("validation venv configuration cannot be read") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _ensure_contained_real_directory(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise GateRuntimeError("validation runtime path is unsafe")
    _assert_real_directory(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            _assert_real_directory(current)
            continue
        try:
            current.mkdir()
        except FileExistsError:
            pass
        _assert_real_directory(current)
    return current


def _directory_identity(path: Path) -> tuple[int, int, int]:
    _assert_real_directory(path)
    metadata = path.lstat()
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _lock_windows_directory_against_delete(parent: Path) -> int:
    """Hold a directory handle without FILE_SHARE_DELETE during publication."""

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
        str(parent),
        0x80000000,  # GENERIC_READ
        0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE; no DELETE
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in (None, invalid_handle):
        raise GateRuntimeError("validation evidence parent could not be locked")
    return int(handle)


def _close_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(handle)):
        raise GateRuntimeError("validation evidence parent could not be unlocked")


@dataclass(slots=True)
class EvidenceParentGuard:
    """Pin `.tmp/validation` so a parent swap cannot redirect receipt/report writes."""

    parent: Path
    identity: tuple[int, int, int]
    parent_descriptor: int | None = None
    windows_handle: int | None = None

    @classmethod
    def create(cls, root: Path, *, lease_capability: object) -> "EvidenceParentGuard":
        root = root.absolute()
        require_authoritative_validation_lease(lease_capability, root)
        parent = _ensure_contained_real_directory(root, Path(".tmp") / "validation")
        return cls._pin(parent)

    @classmethod
    def open_readonly(cls, root: Path) -> "EvidenceParentGuard":
        root = root.absolute()
        _assert_real_directory(root)
        parent = root / ".tmp" / "validation"
        _assert_real_directory(root / ".tmp")
        _assert_real_directory(parent)
        return cls._pin(parent)

    @classmethod
    def _pin(cls, parent: Path) -> "EvidenceParentGuard":
        identity = _directory_identity(parent)
        descriptor: int | None = None
        handle: int | None = None
        try:
            if os.name == "nt":
                handle = _lock_windows_directory_against_delete(parent)
            else:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(parent, flags)
                metadata = os.fstat(descriptor)
                observed = (
                    int(metadata.st_dev),
                    int(metadata.st_ino),
                    int(getattr(metadata, "st_file_attributes", 0)),
                )
                if observed != identity:
                    raise GateRuntimeError("validation evidence parent changed while being pinned")
            guard = cls(parent=parent, identity=identity, parent_descriptor=descriptor, windows_handle=handle)
            guard.assert_intact()
            return guard
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            if handle is not None:
                _close_windows_handle(handle)
            raise

    def __enter__(self) -> "EvidenceParentGuard":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        descriptor, handle = self.parent_descriptor, self.windows_handle
        self.parent_descriptor = None
        self.windows_handle = None
        if descriptor is not None:
            os.close(descriptor)
        if handle is not None:
            _close_windows_handle(handle)

    def assert_intact(self) -> None:
        if _directory_identity(self.parent) != self.identity:
            raise GateRuntimeError("validation evidence parent changed during publication")

    def _filename(self, value: str) -> str:
        candidate = Path(value)
        if candidate.name != value or value in {"", ".", ".."}:
            raise GateRuntimeError("validation evidence filename is unsafe")
        return value

    def _target(self, filename: str) -> Path:
        target = self.parent / self._filename(filename)
        if target.exists() or target.is_symlink():
            _assert_real_file(target)
        return target

    def _open_temporary(self, name: str, flags: int) -> int:
        if self.parent_descriptor is not None:
            return os.open(name, flags, 0o600, dir_fd=self.parent_descriptor)
        return os.open(self.parent / name, flags, 0o600)

    def _replace(self, temporary: str, filename: str) -> None:
        if self.parent_descriptor is not None:
            os.replace(
                temporary,
                filename,
                src_dir_fd=self.parent_descriptor,
                dst_dir_fd=self.parent_descriptor,
            )
            os.fsync(self.parent_descriptor)
            return
        os.replace(self.parent / temporary, self.parent / filename)

    def atomic_replace(self, filename: str, payload: bytes) -> Path:
        """Atomically replace one direct evidence file after rechecking the pinned parent."""

        filename = self._filename(filename)
        target = self._target(filename)
        temporary = f".{filename}.{os.getpid()}.{time.monotonic_ns()}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        try:
            self.assert_intact()
            descriptor = self._open_temporary(temporary, flags)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            descriptor = None
            self.assert_intact()
            self._target(filename)
            self._replace(temporary, filename)
            self.assert_intact()
            return target
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                if self.parent_descriptor is not None:
                    os.unlink(temporary, dir_fd=self.parent_descriptor)
                else:
                    (self.parent / temporary).unlink()
            except FileNotFoundError:
                pass

    def read_bounded(self, filename: str, max_bytes: int) -> bytes:
        """Read one direct evidence file through the pinned parent without following links."""

        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise GateRuntimeError("validation evidence read limit is invalid")
        filename = self._filename(filename)
        self.assert_intact()
        self._target(filename)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            if self.parent_descriptor is not None:
                descriptor = os.open(filename, flags, dir_fd=self.parent_descriptor)
            else:
                descriptor = os.open(self.parent / filename, flags)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > max_bytes:
                raise GateRuntimeError("validation evidence file is invalid")
            content = bytearray()
            while len(content) < before.st_size:
                chunk = os.read(descriptor, min(65536, before.st_size - len(content)))
                if not chunk:
                    raise GateRuntimeError("validation evidence file is truncated")
                content.extend(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                len(content),
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise GateRuntimeError("validation evidence file changed while reading")
            self.assert_intact()
            return bytes(content)
        except OSError as exc:
            raise GateRuntimeError("validation evidence file cannot be read") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)


def attest_project_venv_layout(root: Path, name: str) -> Path:
    """Validate the on-disk project venv layout without executing its interpreter."""

    if name not in _VENV_NAMES:
        raise GateRuntimeError("validation venv name is not permitted")
    root = root.absolute()
    _assert_real_directory(root)
    venv = root / name
    _assert_real_directory(venv)
    scripts = venv / ("Scripts" if os.name == "nt" else "bin")
    config = venv / "pyvenv.cfg"
    _assert_real_directory(scripts)
    try:
        content = _read_pinned_venv_configuration(config).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise GateRuntimeError("validation venv configuration cannot be read") from exc
    settings = [
        line
        for line in content.splitlines()
        if re.match(r"^\s*include-system-site-packages\s*=", line, re.IGNORECASE)
    ]
    if len(settings) != 1 or not re.match(
        r"^\s*include-system-site-packages\s*=\s*false\s*$",
        settings[0],
        re.IGNORECASE,
    ):
        raise GateRuntimeError(
            "validation venv must set include-system-site-packages = false exactly once"
        )
    return venv


def attest_active_project_venv(root: Path) -> Path:
    """Require mutable validation work to run under the canonical project interpreter."""

    venv = attest_project_venv_layout(root, expected_project_venv_name())
    expected = venv.absolute()
    active = Path(sys.prefix).absolute()
    base = Path(sys.base_prefix).absolute()
    if active != expected or base == active:
        raise GateRuntimeError("authoritative validation requires the active project virtual environment")
    scripts = expected / ("Scripts" if os.name == "nt" else "bin")
    executable_parent = Path(sys.executable).absolute().parent
    if executable_parent != scripts:
        raise GateRuntimeError("active validation interpreter is outside the project virtual environment")
    for key in ("purelib", "platlib"):
        raw_destination = Path(sysconfig.get_paths()[key]).absolute()
        try:
            relative = raw_destination.relative_to(expected)
            destination = raw_destination.resolve(strict=True)
        except (KeyError, OSError, ValueError) as exc:
            raise GateRuntimeError(f"validation venv {key} destination is unsafe") from exc
        current = expected
        for part in relative.parts:
            current = current / part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise GateRuntimeError(f"validation venv {key} destination is unavailable") from exc
            if _is_linklike(current, metadata):
                raise GateRuntimeError(f"validation venv {key} path contains a link or reparse point")
        if expected != destination and expected not in destination.parents:
            raise GateRuntimeError(f"validation venv {key} destination escaped the project environment")
        if not destination.is_dir():
            raise GateRuntimeError(f"validation venv {key} destination is not a directory")
    return expected


def prepare_authoritative_runtime(root: Path, *, lease_capability: object) -> dict[str, str]:
    """Create only canonical ignored scratch directories while the writer lease is held."""

    root = root.absolute()
    require_authoritative_validation_lease(lease_capability, root)
    venv = attest_active_project_venv(root)
    windows_paths = _uses_windows_runtime_paths()
    cache_name = "pre-commit-r118-windows-v1" if windows_paths else "pre-commit-r118-linux-v1"
    pre_commit_home = _ensure_contained_real_directory(root, Path(".tmp") / cache_name)
    scripts = venv / ("Scripts" if windows_paths else "bin")
    current_path = os.environ.get("PATH", "")
    updates = {
        # CRITICAL: pre-commit stores this path in its SQLite index. Forward
        # slashes avoid its Windows stale-path rewrite across sibling checkouts.
        "PRE_COMMIT_HOME": pre_commit_home.as_posix(),
        "PATH": str(scripts) if not current_path else f"{scripts}{os.pathsep}{current_path}",
    }
    if not windows_paths:
        playwright = _ensure_contained_real_directory(root, Path(".tmp") / "playwright")
        updates.update({"TMPDIR": str(playwright), "TMP": str(playwright), "TEMP": str(playwright)})
    return updates
