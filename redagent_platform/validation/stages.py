from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Mapping


STAGE_REGISTRY_REVISION = "r118-stages-v1"
DEFAULT_STAGE_CONFIG = Path(__file__).resolve().parents[2] / "config/validation/r118-stage-registry.json"
PIP_BOOTSTRAP_FIXED_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    # IMPORTANT: bootstrap must not inherit a workstation/global pip config.
    "PIP_CONFIG_FILE": os.devnull,
}


class ValidationConfigError(ValueError):
    """Raised when a validation stage registry is unsafe or inconsistent."""


@dataclass(frozen=True, slots=True)
class Stage:
    id: str
    argv: tuple[str, ...]
    gates: tuple[str, ...]
    timeout_seconds: int
    planes: tuple[str, ...] = ()


_BACKEND_G1_PLANES = ("backend", "evidence_reporting", "connector_integration", "governance")
_FRONTEND_G1_PLANES = ("frontend",)

# CRITICAL: this code-owned exact contract is the validation authority. The JSON
# file is a reviewable serialization and must match it byte-for-field; it cannot
# weaken commands, composition, or timeouts from a candidate checkout.
DEFAULT_STAGE_CONTRACT: tuple[Stage, ...] = (
    Stage("local-stack", ("python", "scripts/redagent_local_stack.py", "start"), ("G2",), 300),
    Stage("database-upgrade", ("python", "-m", "alembic", "upgrade", "head"), ("G2",), 300),
    Stage("openbao-conformance", ("python", "scripts/openbao_conformance.py", "provision"), ("G2",), 300),
    Stage("opa-validate", ("python", "scripts/opa_conformance.py", "validate"), ("G2",), 300),
    Stage("opa-build", ("python", "scripts/opa_conformance.py", "build"), ("G2",), 300),
    Stage("opa-build-rollback", ("python", "scripts/opa_conformance.py", "build-rollback"), ("G2",), 300),
    Stage("opa-provision", ("python", "scripts/opa_conformance.py", "provision"), ("G2",), 300),
    Stage("secure-sdlc", ("python", "scripts/validate_secure_sdlc.py"), ("G1", "G2"), 300),
    Stage("agent-skills", ("python", "scripts/validate_agent_skills.py", "--json"), ("G1", "G2"), 300),
    Stage("changed-file-hooks", ("python", "-m", "pre_commit", "run", "--files"), ("G0", "G1"), 600),
    Stage("pre-commit-all-files", ("python", "-m", "pre_commit", "run", "--all-files", "--show-diff-on-failure"), ("G2",), 1200),
    Stage("backend-tests", ("python", "-m", "pytest", "tests"), ("G1", "G2"), 2400, _BACKEND_G1_PLANES),
    Stage("frontend-install", ("npm", "ci", "--audit=false"), ("G1", "G2"), 900, _FRONTEND_G1_PLANES),
    Stage("frontend-audit", ("npm", "audit", "--audit-level=moderate"), ("G2",), 300),
    Stage("frontend-api-check", ("npm", "run", "check:api"), ("G2",), 300),
    Stage("frontend-typecheck", ("npm", "run", "typecheck"), ("G1", "G2"), 300, _FRONTEND_G1_PLANES),
    Stage("frontend-lint", ("npm", "run", "lint"), ("G1", "G2"), 300, _FRONTEND_G1_PLANES),
    Stage("frontend-unit", ("npm", "run", "test:unit"), ("G1", "G2"), 600, _FRONTEND_G1_PLANES),
    Stage("frontend-build", ("npm", "run", "build"), ("G1", "G2"), 600, _FRONTEND_G1_PLANES),
    Stage("playwright-install", ("npx", "playwright", "install", "chromium"), ("G2",), 900),
    Stage("frontend-e2e", ("npm", "test"), ("G2",), 1200),
)


def stage_ids_for_gate(gate: str, planes: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if gate not in {"G0", "G1", "G2"}:
        raise ValidationConfigError(f"unknown gate: {gate}")
    plane_set = set(planes)
    required = tuple(
        stage.id
        for stage in DEFAULT_STAGE_CONTRACT
        if gate in stage.gates and (gate != "G1" or not stage.planes or plane_set.intersection(stage.planes))
    )
    all_ids = tuple(stage.id for stage in DEFAULT_STAGE_CONTRACT)
    return required, tuple(stage_id for stage_id in all_ids if stage_id not in required)


@dataclass(frozen=True)
class StageResult:
    stage_id: str
    status: str
    exit_code: int | None
    duration_ms: int
    argv: tuple[str, ...]
    started_at: str | None = None
    ended_at: str | None = None


class StageRegistry:
    def __init__(self, stages: tuple[Stage, ...], revision: str = STAGE_REGISTRY_REVISION) -> None:
        identifiers: set[str] = set()
        for stage in stages:
            if stage.id in identifiers:
                raise ValidationConfigError(f"duplicate stage id: {stage.id}")
            identifiers.add(stage.id)
            if not stage.id or not stage.argv or any(not isinstance(item, str) or not item for item in stage.argv):
                raise ValidationConfigError("stage id and argv must be non-empty")
            if stage.timeout_seconds <= 0:
                raise ValidationConfigError("stage timeout must be positive")
            if not stage.gates or any(gate not in {"G0", "G1", "G2"} for gate in stage.gates):
                raise ValidationConfigError("stage gate is invalid")
            executable = Path(stage.argv[0]).name.casefold()
            if executable in {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "sh", "bash"}:
                raise ValidationConfigError("shell executables are prohibited")
        self._stages = stages
        self.revision = revision

    def plan(self, gate: str, planes: tuple[str, ...] = ()) -> tuple[Stage, ...]:
        if gate not in {"G0", "G1", "G2"}:
            raise ValidationConfigError(f"unknown gate: {gate}")
        # Stable IDs are the deduplication boundary even if future configuration expands aliases.
        selected: dict[str, Stage] = {}
        plane_set = set(planes)
        for stage in self._stages:
            if gate in stage.gates and (gate != "G1" or not stage.planes or plane_set.intersection(stage.planes)):
                selected.setdefault(stage.id, stage)
        return tuple(selected.values())

    def plan_ids(self, stage_ids: tuple[str, ...]) -> tuple[Stage, ...]:
        if len(stage_ids) != len(set(stage_ids)):
            raise ValidationConfigError("duplicate requested stage id")
        by_id = {stage.id: stage for stage in self._stages}
        unknown = tuple(stage_id for stage_id in stage_ids if stage_id not in by_id)
        if unknown:
            raise ValidationConfigError(f"unknown stage IDs: {unknown}")
        return tuple(by_id[stage_id] for stage_id in stage_ids)


class StageRunner:
    _ALLOWED_ENVIRONMENT = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
        "CI",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "PRE_COMMIT_HOME",
        "REDAGENT_DATABASE_URL_FILE",
    }
    _FIXED_ENVIRONMENT_VALUES = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    _FIXED_PIP_BOOTSTRAP_ENVIRONMENT_VALUES = PIP_BOOTSTRAP_FIXED_ENVIRONMENT

    def __init__(
        self,
        repository_root: Path,
        inherited_environment: Mapping[str, str],
        *,
        fixed_environment: Mapping[str, str] | None = None,
    ) -> None:
        self._repository_root = repository_root.resolve()
        self._environment = {
            key: value
            for key, value in inherited_environment.items()
            if key.upper() in self._ALLOWED_ENVIRONMENT
        }
        if fixed_environment is not None:
            fixed_values = dict(fixed_environment)
            if fixed_values not in (
                self._FIXED_ENVIRONMENT_VALUES,
                self._FIXED_PIP_BOOTSTRAP_ENVIRONMENT_VALUES,
            ):
                raise ValidationConfigError("fixed environment is not permitted")
            # CRITICAL: fixed controls are code-owned values only; do not widen
            # the inherited-environment allowlist to arbitrary GIT_* settings.
            self._environment.update(fixed_values)
            protected_git_config = {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": str(self._repository_root),
            }
            if os.name == "nt":
                # IMPORTANT: nested Windows Git processes must interpret the
                # checkout with the same fixed CRLF normalization as the gate.
                protected_git_config.update(
                    {
                        "GIT_CONFIG_COUNT": "2",
                        "GIT_CONFIG_KEY_1": "core.autocrlf",
                        "GIT_CONFIG_VALUE_1": "true",
                    }
                )
            self._environment.update(protected_git_config)

    def execution_contract(self, stage: Stage, *, source_oid: str) -> dict[str, object]:
        """Digest the exact argv/environment used by one same-source stage run."""

        if not isinstance(stage, Stage) or re.fullmatch(r"[0-9a-f]{40}", source_oid) is None:
            raise ValidationConfigError("stage execution identity is invalid")
        execution_argv = self._resolved_execution_argv(stage)
        argv_raw = json.dumps(
            list(execution_argv),
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        environment_raw = json.dumps(
            dict(sorted(self._environment.items())),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return {
            "source_oid": source_oid,
            "stage_registry_revision": STAGE_REGISTRY_REVISION,
            "stage_id": stage.id,
            "argv_sha256": hashlib.sha256(argv_raw).hexdigest(),
            "environment_sha256": hashlib.sha256(environment_raw).hexdigest(),
        }

    def _resolved_execution_argv(self, stage: Stage) -> tuple[str, ...]:
        if stage.argv[0] == "python":
            return (sys.executable, *stage.argv[1:])
        resolved = shutil.which(stage.argv[0], path=self._environment.get("PATH"))
        if resolved:
            return (resolved, *stage.argv[1:])
        return stage.argv

    def run(self, stage: Stage, *, deadline_monotonic: float | None = None) -> StageResult:
        started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        started = time.monotonic()
        effective_timeout = self._effective_timeout(stage.timeout_seconds, deadline_monotonic)
        if effective_timeout <= 0:
            return self._timed_out_result(stage, started, started_at)
        execution_argv = self._resolved_execution_argv(stage)
        creationflags = 0
        if os.name == "nt":
            # CRITICAL: the child must not execute before Job assignment; a
            # post-Popen assignment leaves a descendant-escape race.
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        process: subprocess.Popen[bytes] | None = None
        job_handle: int | None = None
        stdout_thread: threading.Thread | None = None
        stderr_thread: threading.Thread | None = None
        try:
            if os.name == "nt":
                job_handle = self._create_windows_kill_job()
                if job_handle is None:
                    raise OSError("Windows Job Object containment is unavailable")
            effective_timeout = self._effective_timeout(stage.timeout_seconds, deadline_monotonic)
            if effective_timeout <= 0:
                self._close_windows_job(job_handle)
                job_handle = None
                return self._timed_out_result(stage, started, started_at)
            process = subprocess.Popen(
                execution_argv,
                cwd=self._repository_root,
                env=self._environment,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=os.name != "nt",
                creationflags=creationflags,
            )
            if os.name == "nt" and not self._assign_windows_kill_job(process, job_handle):
                self._terminate_suspended_windows_process(process, job_handle, deadline_monotonic)
                job_handle = None
                raise OSError("process could not be assigned to the validation Job Object")
            if os.name == "nt" and not self._resume_windows_process(process):
                self._terminate_process_tree(process, job_handle, deadline_monotonic)
                job_handle = None
                raise OSError("assigned validation process could not be resumed")
            stdout_thread = threading.Thread(
                target=self._drain_stream,
                args=(process.stdout, stdout_buffer),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=self._drain_stream,
                args=(process.stderr, stderr_buffer),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            # CRITICAL: a child must never extend the enclosing gate deadline.
            effective_timeout = self._effective_timeout(stage.timeout_seconds, deadline_monotonic)
            if effective_timeout <= 0:
                raise subprocess.TimeoutExpired(execution_argv, effective_timeout)
            process.wait(timeout=effective_timeout)
            if os.name == "nt":
                self._close_windows_job(job_handle)
                job_handle = None
            elif not self._terminate_process_tree(process, deadline_monotonic=deadline_monotonic):
                raise OSError("validation process group could not be terminated")
            self._join_drain_thread(stdout_thread, deadline_monotonic)
            self._join_drain_thread(stderr_thread, deadline_monotonic)
        except subprocess.TimeoutExpired:
            cleanup_succeeded = True
            if process is not None:
                cleanup_succeeded = self._terminate_process_tree(process, job_handle, deadline_monotonic)
            if stdout_thread is not None:
                self._join_drain_thread(stdout_thread, deadline_monotonic)
            if stderr_thread is not None:
                self._join_drain_thread(stderr_thread, deadline_monotonic)
            if cleanup_succeeded:
                return self._timed_out_result(stage, started, started_at)
            return StageResult(
                stage_id=stage.id,
                status="failed",
                exit_code=None,
                duration_ms=round((time.monotonic() - started) * 1000),
                argv=stage.argv,
                started_at=started_at,
                ended_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            )
        except OSError:
            if process is not None and process.poll() is None:
                self._terminate_process_tree(process, job_handle, deadline_monotonic)
            else:
                self._close_windows_job(job_handle)
            return StageResult(
                stage_id=stage.id,
                status="failed",
                exit_code=None,
                duration_ms=round((time.monotonic() - started) * 1000),
                argv=stage.argv,
                started_at=started_at,
                ended_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            )
        return_code = process.returncode if process is not None else None
        diagnostic = self._redact_diagnostic(
            f"{stderr_buffer.decode('utf-8', errors='replace')}\n"
            f"{stdout_buffer.decode('utf-8', errors='replace')}"
        )
        if return_code != 0:
            if diagnostic:
                print(f"validation stage {stage.id} failed:\n{diagnostic}", file=sys.stderr)
        elif diagnostic:
            print(diagnostic)
        return StageResult(
            stage_id=stage.id,
            status="passed" if return_code == 0 else "failed",
            exit_code=return_code,
            duration_ms=round((time.monotonic() - started) * 1000),
            argv=stage.argv,
            started_at=started_at,
            ended_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )

    @staticmethod
    def _effective_timeout(stage_timeout_seconds: int, deadline_monotonic: float | None) -> float:
        if deadline_monotonic is None:
            return stage_timeout_seconds
        return min(stage_timeout_seconds, deadline_monotonic - time.monotonic())

    @staticmethod
    def _timed_out_result(stage: Stage, started: float, started_at: str) -> StageResult:
        return StageResult(
            stage_id=stage.id,
            status="timed_out",
            exit_code=None,
            duration_ms=round((time.monotonic() - started) * 1000),
            argv=stage.argv,
            started_at=started_at,
            ended_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )

    def _join_drain_thread(
        self,
        thread: threading.Thread,
        deadline_monotonic: float | None,
    ) -> None:
        timeout = self._effective_timeout(5, deadline_monotonic)
        if timeout > 0:
            thread.join(timeout=timeout)

    @staticmethod
    def _drain_stream(stream: io.BufferedReader | None, destination: bytearray) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            remaining = 65536 - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])

    @staticmethod
    def _create_windows_kill_job() -> int | None:
        if os.name != "nt":
            return None

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
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

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
        information.BasicLimitInformation.LimitFlags = 0x00002000
        configured = kernel32.SetInformationJobObject(
            job,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )
        if not configured:
            kernel32.CloseHandle(job)
            return None
        return int(job)

    @staticmethod
    def _assign_windows_kill_job(
        process: subprocess.Popen[bytes],
        job_handle: int | None,
    ) -> bool:
        if os.name != "nt" or not job_handle:
            return False
        kernel32 = ctypes.windll.kernel32
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        return bool(
            kernel32.AssignProcessToJobObject(
                wintypes.HANDLE(job_handle),
                wintypes.HANDLE(process._handle),
            )
        )

    @staticmethod
    def _resume_windows_process(process: subprocess.Popen[bytes]) -> bool:
        if os.name != "nt":
            return False

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
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if not snapshot or int(snapshot) == invalid_handle:
            return False
        try:
            entry = THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            found = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
            while found:
                if entry.th32OwnerProcessID == process.pid:
                    thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)
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

    @staticmethod
    def _terminate_suspended_windows_process(
        process: subprocess.Popen[bytes],
        job_handle: int | None,
        deadline_monotonic: float | None = None,
    ) -> None:
        try:
            if process.poll() is None:
                process.kill()
            timeout = StageRunner._effective_timeout(5, deadline_monotonic)
            if timeout > 0:
                process.wait(timeout=timeout)
        finally:
            StageRunner._close_windows_job(job_handle)

    @staticmethod
    def _close_windows_job(job_handle: int | None) -> None:
        if os.name == "nt" and job_handle:
            ctypes.windll.kernel32.CloseHandle(job_handle)

    def _terminate_process_tree(
        self,
        process: subprocess.Popen[bytes],
        job_handle: int | None = None,
        deadline_monotonic: float | None = None,
    ) -> bool:
        # CRITICAL: Windows timeout must terminate Job descendants. POSIX can
        # terminate only the initial process group; it is not a full escaped-
        # descendant boundary and cannot support authoritative compat_118 campaigns.
        if os.name == "nt":
            terminated = bool(
                job_handle
                and ctypes.windll.kernel32.TerminateJobObject(job_handle, 1)
            )
            if not terminated:
                try:
                    taskkill_timeout = self._effective_timeout(15, deadline_monotonic)
                    completed = None
                    if taskkill_timeout > 0:
                        completed = subprocess.run(
                            ("taskkill", "/PID", str(process.pid), "/T", "/F"),
                            cwd=self._repository_root,
                            env=self._environment,
                            capture_output=True,
                            timeout=taskkill_timeout,
                            check=False,
                            shell=False,
                        )
                    if (completed is None or completed.returncode != 0) and process.poll() is None:
                        process.kill()
                except (OSError, subprocess.TimeoutExpired):
                    if process.poll() is None:
                        process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                timeout = self._effective_timeout(2, deadline_monotonic)
                if timeout > 0:
                    process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
            # Always escalate the group independently of leader state. A child
            # may ignore SIGTERM after the direct process has already exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            timeout = self._effective_timeout(5, deadline_monotonic)
            if timeout > 0:
                process.wait(timeout=timeout)
            elif process.poll() is None:
                process.kill()
        except subprocess.TimeoutExpired:
            process.kill()
            timeout = self._effective_timeout(5, deadline_monotonic)
            if timeout > 0:
                process.wait(timeout=timeout)
        finally:
            self._close_windows_job(job_handle)
        if os.name == "nt":
            return process.poll() is not None
        containment_deadline = time.monotonic() + 5
        if deadline_monotonic is not None:
            containment_deadline = min(containment_deadline, deadline_monotonic)
        while time.monotonic() < containment_deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return True
            remaining = containment_deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.05, remaining))
        return False

    def _redact_diagnostic(self, value: str) -> str:
        bounded = value[:4096]
        root_values = {
            str(self._repository_root),
            str(self._repository_root).replace("\\", "/"),
        }
        for root_value in root_values:
            bounded = bounded.replace(root_value, "<repo>")
        bounded = re.sub(
            r'''(?ix)(?<![a-z0-9])((?:[a-z0-9]+[_-])*(?:secret[_-]?access[_-]?key|access[_-]?key[_-]?id|api[_-]?(?:key|token)|refresh[_-]?token|client[_-]?secret|private[_-]?key|session[_-]?id|token|secret|password|credential|cookie))(\s*[:=]\s*)((?:["'])?)[^\s,"']+\3''',
            r"\1\2<redacted>",
            bounded,
        )
        bounded = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@", r"\1<redacted>@", bounded)
        bounded = re.sub(
            r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+",
            r"\1<redacted>",
            bounded,
        )
        bounded = re.sub(r"(?i)((?:set-)?cookie\s*:\s*)[^\r\n]+", r"\1<redacted>", bounded)
        bounded = re.sub(
            r'''(?ix)(["']?(?:[a-z0-9]+[_-])*(?:secret[_-]?access[_-]?key|access[_-]?key[_-]?id|api[_-]?(?:key|token)|refresh[_-]?token|client[_-]?secret|private[_-]?key|session[_-]?id|token|secret|password|credential)["']?\s*:\s*["'])[^"']+''',
            r"\1<redacted>",
            bounded,
        )
        return bounded.strip()


def load_stage_registry(path: Path) -> StageRegistry:
    from redagent_platform.validation.config import load_strict_json

    payload = load_strict_json(path)
    allowed_top = {"schema_version", "registry_revision", "stages"}
    unknown = set(payload) - allowed_top
    missing = allowed_top - set(payload)
    if unknown:
        raise ValidationConfigError(f"unknown stage-registry keys: {sorted(unknown)}")
    if missing:
        raise ValidationConfigError(f"missing stage-registry keys: {sorted(missing)}")
    if payload["schema_version"] != "1":
        raise ValidationConfigError("unsupported stage-registry schema version")
    if payload["registry_revision"] != STAGE_REGISTRY_REVISION:
        raise ValidationConfigError("unsupported stage registry revision")
    raw_stages = payload["stages"]
    if not isinstance(raw_stages, list) or not raw_stages:
        raise ValidationConfigError("stage registry must contain stages")
    stages: list[Stage] = []
    allowed_stage = {"id", "argv", "gates", "timeout_seconds", "planes"}
    for raw_stage in raw_stages:
        if not isinstance(raw_stage, dict) or set(raw_stage) != allowed_stage:
            raise ValidationConfigError("stage has unknown or missing keys")
        argv_value = raw_stage["argv"]
        gates_value = raw_stage["gates"]
        planes_value = raw_stage["planes"]
        if not isinstance(argv_value, list) or any(not isinstance(item, str) for item in argv_value):
            raise ValidationConfigError("stage argv must be a string list")
        if not isinstance(gates_value, list) or any(not isinstance(item, str) for item in gates_value):
            raise ValidationConfigError("stage gates must be a string list")
        if not isinstance(planes_value, list) or any(not isinstance(item, str) for item in planes_value):
            raise ValidationConfigError("stage planes must be a string list")
        timeout = raw_stage["timeout_seconds"]
        if not isinstance(timeout, int) or isinstance(timeout, bool):
            raise ValidationConfigError("stage timeout must be an integer")
        stage = Stage(
            id=raw_stage["id"],
            argv=tuple(argv_value),
            gates=tuple(gates_value),
            timeout_seconds=timeout,
            planes=tuple(planes_value),
        )
        stages.append(stage)
    parsed = tuple(stages)
    registry = StageRegistry(parsed, revision=payload["registry_revision"])
    if parsed != DEFAULT_STAGE_CONTRACT:
        raise ValidationConfigError("stage registry does not match the exact stage contract")
    return registry


def build_default_registry(repository_root: Path) -> StageRegistry:
    root = Path(repository_root).resolve()
    return load_stage_registry(root / "config" / "validation" / "r118-stage-registry.json")
