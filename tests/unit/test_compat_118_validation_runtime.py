from __future__ import annotations

import io
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest

from redagent_platform.gate_lease import (
    ValidationLease,
    ValidationLeaseError,
    authoritative_validation_lease_path,
    bind_authoritative_validation_platform,
)
from redagent_platform.gate_runtime import (
    EvidenceParentGuard,
    GateRuntimeError,
    attest_project_venv_layout,
    prepare_authoritative_runtime,
    run_bounded_stdout,
)


def test_validation_lease_creates_its_missing_parent_before_locking(tmp_path: Path) -> None:
    lock_path = tmp_path / "fresh" / ".tmp" / "validation" / "authoritative-validation.lock"

    with ValidationLease(lock_path):
        assert lock_path.is_file()


def test_validation_lease_rejects_a_file_where_its_parent_directory_is_required(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("blocked", encoding="utf-8")

    with pytest.raises(ValidationLeaseError, match="parent"):
        with ValidationLease(blocker / "authoritative-validation.lock"):
            pass


def test_project_venv_layout_rejects_system_site_packages(tmp_path: Path) -> None:
    venv = tmp_path / ".venv"
    (venv / ("Scripts" if os.name == "nt" else "bin")).mkdir(parents=True)
    configuration = venv / "pyvenv.cfg"
    configuration.write_text("include-system-site-packages = true\n", encoding="utf-8")

    with pytest.raises(GateRuntimeError, match="include-system-site-packages"):
        attest_project_venv_layout(tmp_path, ".venv")


def test_runtime_scratch_paths_are_created_only_by_the_authoritative_runtime_helper(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import redagent_platform.gate_runtime as gate_runtime

    venv = tmp_path / ".venv"
    scripts = venv / ("Scripts" if os.name == "nt" else "bin")
    scripts.mkdir(parents=True)
    monkeypatch.setattr(gate_runtime, "attest_active_project_venv", lambda _root: venv)
    monkeypatch.setenv("PATH", "C:\\safe-bin")

    with ValidationLease(authoritative_validation_lease_path(tmp_path)) as lease:
        updates = prepare_authoritative_runtime(tmp_path, lease_capability=lease.capability())

    assert Path(updates["PRE_COMMIT_HOME"]).is_dir()
    assert updates["PATH"].startswith(str(scripts))


def test_runtime_uses_a_forward_slash_pre_commit_home_on_windows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Pre-commit persists this path in SQLite, so native backslashes are unsafe here."""

    import redagent_platform.gate_runtime as gate_runtime

    venv = tmp_path / ".venv"
    scripts = venv / "Scripts"
    scripts.mkdir(parents=True)
    monkeypatch.setattr(gate_runtime, "attest_active_project_venv", lambda _root: venv)
    monkeypatch.setattr(gate_runtime, "_uses_windows_runtime_paths", lambda: True)
    monkeypatch.setenv("PATH", "C:\\safe-bin")

    with ValidationLease(authoritative_validation_lease_path(tmp_path)) as lease:
        updates = prepare_authoritative_runtime(tmp_path, lease_capability=lease.capability())

    assert "\\" not in updates["PRE_COMMIT_HOME"]
    assert updates["PRE_COMMIT_HOME"].endswith("/.tmp/pre-commit-r118-windows-v1")


def test_runtime_rejects_absent_or_noncanonical_lease_capabilities(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import redagent_platform.gate_runtime as gate_runtime

    venv = tmp_path / ".venv"
    (venv / ("Scripts" if os.name == "nt" else "bin")).mkdir(parents=True)
    monkeypatch.setattr(gate_runtime, "attest_active_project_venv", lambda _root: venv)

    with pytest.raises(ValidationLeaseError, match="capability"):
        prepare_authoritative_runtime(tmp_path, lease_capability=None)

    with ValidationLease(tmp_path / "other.lock") as lease:
        with pytest.raises(ValidationLeaseError, match="canonical"):
            prepare_authoritative_runtime(tmp_path, lease_capability=lease.capability())


def test_workspace_platform_context_fails_closed_when_windows_and_posix_share_a_checkout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import redagent_platform.gate_lease as gate_lease

    path = authoritative_validation_lease_path(tmp_path)
    monkeypatch.setattr(gate_lease, "_validation_platform", lambda: "windows")
    with ValidationLease(path) as lease:
        assert bind_authoritative_validation_platform(tmp_path, lease.capability()) == "windows"

    monkeypatch.setattr(gate_lease, "_validation_platform", lambda: "posix")
    with ValidationLease(path) as lease:
        with pytest.raises(ValidationLeaseError, match="unqualified"):
            bind_authoritative_validation_platform(tmp_path, lease.capability())


def test_platform_context_rejects_a_reparse_marker_before_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A leaf reparse marker must never become a cross-platform authority."""

    import redagent_platform.gate_lease as gate_lease

    context = tmp_path / ".tmp" / "validation" / "authoritative-validation-platform.json"
    context.parent.mkdir(parents=True)
    context.write_text('{"platform":"windows","schema_version":"r118-validation-platform-v1"}', encoding="utf-8")
    original_is_linklike = gate_lease._is_linklike
    monkeypatch.setattr(
        gate_lease,
        "_is_linklike",
        lambda path, metadata: path == context or original_is_linklike(path, metadata),
    )

    with pytest.raises(ValidationLeaseError, match="regular file"):
        gate_lease._read_platform_context(context)


def test_platform_context_rejects_a_descriptor_swapped_after_path_attestation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Opening a replacement descriptor must not silently bind another file's OS claim."""

    import redagent_platform.gate_lease as gate_lease

    context = tmp_path / ".tmp" / "validation" / "authoritative-validation-platform.json"
    context.parent.mkdir(parents=True)
    context.write_text('{"platform":"windows","schema_version":"r118-validation-platform-v1"}', encoding="utf-8")
    replacement = tmp_path / "replacement-platform-context.json"
    replacement.write_text('{"platform":"posix","schema_version":"r118-validation-platform-v1"}', encoding="utf-8")
    real_open = gate_lease.os.open

    def swapped_open(path: str | Path, flags: int, *args: object, **kwargs: object) -> int:
        if Path(path) == context:
            return real_open(replacement, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(gate_lease.os, "open", swapped_open)

    with pytest.raises(ValidationLeaseError, match="changed while reading"):
        gate_lease._read_platform_context(context)


def test_project_venv_layout_rejects_an_oversize_config_before_content_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Attestation must bound size before any pathname content read."""

    import redagent_platform.gate_runtime as gate_runtime

    venv = tmp_path / ".venv"
    (venv / ("Scripts" if os.name == "nt" else "bin")).mkdir(parents=True)
    configuration = venv / "pyvenv.cfg"
    configuration.write_text("x" * (gate_runtime._MAX_VENV_CONFIG_BYTES + 1), encoding="utf-8")
    original_read_text = Path.read_text

    def fail_if_opened(self: Path, *args: object, **kwargs: object) -> str:
        if self == configuration:
            raise AssertionError("oversize configuration content must not be opened")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_if_opened)

    with pytest.raises(GateRuntimeError, match="exceeds the bounded size"):
        attest_project_venv_layout(tmp_path, ".venv")


def test_project_venv_layout_rejects_a_descriptor_swapped_after_path_attestation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The attested config descriptor must still name the pinned local file."""

    import redagent_platform.gate_runtime as gate_runtime

    venv = tmp_path / ".venv"
    (venv / ("Scripts" if os.name == "nt" else "bin")).mkdir(parents=True)
    configuration = venv / "pyvenv.cfg"
    configuration.write_text("include-system-site-packages = false\n", encoding="utf-8")
    replacement = tmp_path / "replacement-pyvenv.cfg"
    replacement.write_text("include-system-site-packages = false\n", encoding="utf-8")
    real_open = gate_runtime.os.open

    def swapped_open(path: str | Path, flags: int, *args: object, **kwargs: object) -> int:
        if Path(path) == configuration:
            return real_open(replacement, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(gate_runtime.os, "open", swapped_open)

    with pytest.raises(GateRuntimeError, match="changed while reading"):
        attest_project_venv_layout(tmp_path, ".venv")


def test_evidence_parent_guard_pins_and_atomically_replaces_direct_receipts(tmp_path: Path) -> None:
    with ValidationLease(authoritative_validation_lease_path(tmp_path)) as lease:
        with EvidenceParentGuard.create(tmp_path, lease_capability=lease.capability()) as guard:
            receipt = guard.atomic_replace("verification.json", b'{"result":"first"}\n')
            assert receipt.read_bytes() == b'{"result":"first"}\n'
            guard.atomic_replace("verification.json", b'{"result":"second"}\n')
            assert guard.read_bounded("verification.json", 1024) == b'{"result":"second"}\n'
            guard.assert_intact()

    assert receipt.read_bytes() == b'{"result":"second"}\n'


def test_bounded_command_transport_kills_oversized_or_stalled_git_style_output(tmp_path: Path) -> None:
    environment = {"PATH": os.environ.get("PATH", "")}

    oversized = run_bounded_stdout(
        (sys.executable, "-I", "-c", "import sys; sys.stdout.write('x' * 4096)"),
        cwd=tmp_path,
        environment=environment,
        timeout_seconds=5,
        max_output_bytes=64,
    )
    assert oversized is None

    started = time.monotonic()
    stalled = run_bounded_stdout(
        (sys.executable, "-I", "-c", "import time; time.sleep(5)"),
        cwd=tmp_path,
        environment=environment,
        timeout_seconds=1,
        max_output_bytes=64,
    )
    assert stalled is None
    assert time.monotonic() - started < 4


def test_bounded_command_transport_terminates_the_contained_tree_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import redagent_platform.gate_runtime as gate_runtime

    class PendingProcess:
        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return self.returncode if self.returncode is not None else -9

        def kill(self) -> None:
            self.returncode = -9

    process = PendingProcess()
    containment = SimpleNamespace(process=process, windows_job_handle=None)
    started: list[object] = []
    terminated: list[object] = []

    monkeypatch.setattr(
        gate_runtime,
        "start_contained_process",
        lambda *args, **_kwargs: started.append(args[0]) or containment,
        raising=False,
    )
    monkeypatch.setattr(
        gate_runtime,
        "terminate_contained_process",
        lambda value, **_kwargs: terminated.append(value) or True,
        raising=False,
    )
    monkeypatch.setattr(gate_runtime.subprocess, "Popen", lambda *_args, **_kwargs: process)

    assert (
        gate_runtime.run_bounded_stdout(
            ("trusted-tool", "--status"),
            cwd=tmp_path,
            environment={"PATH": os.environ.get("PATH", "")},
            timeout_seconds=1,
            max_output_bytes=64,
        )
        is None
    )

    assert started == [("trusted-tool", "--status")]
    assert terminated == [containment]


def test_contained_process_uses_a_posix_session_and_kills_its_process_group(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import redagent_platform.gate_runtime as gate_runtime

    starter = getattr(gate_runtime, "start_contained_process", None)
    assert callable(starter)

    class Process:
        pid = 4242
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return self.returncode if self.returncode is not None else -9

        def kill(self) -> None:
            self.returncode = -9

    process = Process()
    observed: dict[str, object] = {}
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(gate_runtime, "_uses_windows_process_containment", lambda: False, raising=False)
    def fake_killpg(pid: int, value: int) -> None:
        signals.append((pid, value))
        if value == 0:
            raise ProcessLookupError
        process.returncode = -9

    monkeypatch.setattr(gate_runtime.os, "killpg", fake_killpg, raising=False)

    def fake_popen(argv: tuple[str, ...], **kwargs: object) -> Process:
        observed["argv"] = argv
        observed.update(kwargs)
        return process

    containment = starter(
        ("trusted-tool", "--status"),
        cwd=tmp_path,
        environment={"PATH": os.environ.get("PATH", "")},
        stdin=None,
        stdout=None,
        stderr=None,
        popen_factory=fake_popen,
    )

    assert observed["argv"] == ("trusted-tool", "--status")
    assert observed["start_new_session"] is True
    assert gate_runtime.terminate_contained_process(containment, wait_timeout_seconds=0)
    assert signals


def test_contained_process_assigns_a_windows_kill_job_before_resuming(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import redagent_platform.gate_runtime as gate_runtime

    starter = getattr(gate_runtime, "start_contained_process", None)
    assert callable(starter)

    class Process:
        pid = 5151
        _handle = 3131

        def poll(self) -> int | None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return -9

        def kill(self) -> None:
            pass

    process = Process()
    observed: dict[str, object] = {}
    lifecycle: list[str] = []
    monkeypatch.setattr(gate_runtime, "_uses_windows_process_containment", lambda: True, raising=False)
    monkeypatch.setattr(gate_runtime, "_create_windows_kill_job", lambda: 99, raising=False)
    monkeypatch.setattr(
        gate_runtime,
        "_assign_windows_kill_job",
        lambda _process, handle: lifecycle.append(f"assign:{handle}") or True,
        raising=False,
    )
    monkeypatch.setattr(
        gate_runtime,
        "_resume_windows_process",
        lambda _process: lifecycle.append("resume") or True,
        raising=False,
    )

    def fake_popen(argv: tuple[str, ...], **kwargs: object) -> Process:
        observed["argv"] = argv
        observed.update(kwargs)
        return process

    containment = starter(
        ("trusted-tool",),
        cwd=tmp_path,
        environment={"PATH": os.environ.get("PATH", "")},
        stdin=None,
        stdout=None,
        stderr=None,
        popen_factory=fake_popen,
    )

    assert containment.windows_job_handle == 99
    assert observed["creationflags"] & gate_runtime._CREATE_NEW_PROCESS_GROUP
    assert observed["creationflags"] & gate_runtime._CREATE_SUSPENDED
    assert lifecycle == ["assign:99", "resume"]


def test_active_project_venv_attestation_rejects_an_external_site_packages_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import redagent_platform.gate_runtime as gate_runtime

    expected = tmp_path / ".venv"
    scripts = expected / ("Scripts" if os.name == "nt" else "bin")
    scripts.mkdir(parents=True)
    outside = tmp_path / "outside-site-packages"
    outside.mkdir()
    monkeypatch.setattr(gate_runtime, "attest_project_venv_layout", lambda _root, _name: expected)
    monkeypatch.setattr(gate_runtime.sys, "prefix", str(expected))
    monkeypatch.setattr(gate_runtime.sys, "base_prefix", str(tmp_path / "base"))
    monkeypatch.setattr(gate_runtime.sys, "executable", str(scripts / "python"))
    monkeypatch.setattr(
        gate_runtime.sysconfig,
        "get_paths",
        lambda: {"purelib": str(outside), "platlib": str(outside)},
    )

    with pytest.raises(GateRuntimeError, match="destination is unsafe"):
        gate_runtime.attest_active_project_venv(tmp_path)
