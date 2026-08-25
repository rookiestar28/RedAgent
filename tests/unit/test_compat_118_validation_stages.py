from __future__ import annotations

from dataclasses import replace
import ctypes
import io
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from redagent_platform.validation import (
    ChangeRequest,
    Stage,
    StageRegistry,
    StageRunner,
    ValidationConfigError,
    build_default_registry,
    classify_change,
)
from redagent_platform.validation.stages import STAGE_REGISTRY_REVISION


ROOT = Path(__file__).resolve().parents[2]


def test_default_gate_plans_deduplicate_security_typecheck_and_audit_intents() -> None:
    registry = build_default_registry(ROOT)

    g0 = registry.plan("G0")
    g2 = registry.plan("G2")

    assert [stage.id for stage in g0].count("changed-file-hooks") == 1
    assert "detect-secrets-all-files" not in [stage.id for stage in g2]
    assert [stage.id for stage in g2].count("pre-commit-all-files") == 1
    assert [stage.id for stage in g2].count("frontend-typecheck") == 1
    assert [stage.id for stage in g2].count("frontend-audit") == 1
    assert all(stage.argv for stage in g2)
    assert all(isinstance(stage.argv, tuple) for stage in g2)


def test_default_registry_reads_the_contract_from_the_execution_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import redagent_platform.validation.stages as stages_module

    observed: list[Path] = []
    expected = StageRegistry(
        (Stage(id="safe", argv=("python", "-V"), gates=("G0",), timeout_seconds=30),)
    )
    monkeypatch.setattr(
        stages_module,
        "load_stage_registry",
        lambda path: observed.append(path) or expected,
    )

    assert build_default_registry(tmp_path) is expected
    assert observed == [tmp_path / "config" / "validation" / "r118-stage-registry.json"]


def test_stage_runner_execution_contract_binds_resolved_argv_and_allowlisted_environment() -> None:
    stage = Stage("backend-tests", ("python", "-m", "pytest", "tests"), ("G1",), 60)
    first = StageRunner(
        ROOT,
        inherited_environment={"PATH": os.environ["PATH"], "CI": "true", "SECRET": "forbidden"},
    ).execution_contract(stage, source_oid="a" * 40)
    reordered = StageRunner(
        ROOT,
        inherited_environment={"CI": "true", "PATH": os.environ["PATH"]},
    ).execution_contract(stage, source_oid="a" * 40)
    changed_environment = StageRunner(
        ROOT,
        inherited_environment={"PATH": os.environ["PATH"], "CI": "false"},
    ).execution_contract(stage, source_oid="a" * 40)
    changed_argv = StageRunner(
        ROOT,
        inherited_environment={"PATH": os.environ["PATH"], "CI": "true"},
    ).execution_contract(
        Stage("backend-tests", ("python", "-m", "pytest", "tests/unit"), ("G1",), 60),
        source_oid="a" * 40,
    )

    assert first == reordered
    assert first["source_oid"] == "a" * 40
    assert first["stage_registry_revision"] == STAGE_REGISTRY_REVISION
    assert first["stage_id"] == "backend-tests"
    assert set(first) == {
        "source_oid",
        "stage_registry_revision",
        "stage_id",
        "argv_sha256",
        "environment_sha256",
    }
    assert first["environment_sha256"] != changed_environment["environment_sha256"]
    assert first["argv_sha256"] != changed_argv["argv_sha256"]
    assert "SECRET" not in first


def test_registry_rejects_duplicate_ids_shell_commands_and_invalid_timeouts() -> None:
    safe = Stage(id="safe", argv=("python", "-V"), gates=("G0",), timeout_seconds=30)

    with pytest.raises(ValidationConfigError, match="duplicate stage id"):
        StageRegistry((safe, safe))
    with pytest.raises(ValidationConfigError, match="shell"):
        StageRegistry((replace(safe, id="shell", argv=("cmd.exe", "/c", "echo unsafe")),))
    with pytest.raises(ValidationConfigError, match="timeout"):
        StageRegistry((replace(safe, id="timeout", timeout_seconds=0),))


def test_registry_selects_exact_decision_stage_ids_and_rejects_unknown_ids() -> None:
    registry = build_default_registry(ROOT)

    selected = registry.plan_ids(("changed-file-hooks", "frontend-unit"))

    assert tuple(stage.id for stage in selected) == ("changed-file-hooks", "frontend-unit")
    with pytest.raises(ValidationConfigError, match="unknown stage"):
        registry.plan_ids(("changed-file-hooks", "not-registered"))


@pytest.mark.parametrize(
    "path",
    [
        "PUBLIC_RELEASE.md",
        "redagent_platform/finding_operations/lifecycle.py",
        "frontend/src/App.tsx",
        "redagent_platform/policy_service/enforcement.py",
    ],
)
def test_classifier_registry_and_execution_share_exact_stage_composition(path: str) -> None:
    decision = classify_change(
        ChangeRequest(
            base_revision="a" * 40,
            head_revision="b" * 40,
            changed_paths=(path,),
        )
    )
    registry = build_default_registry(ROOT)

    planned = registry.plan(decision.selected_gate, decision.planes)
    executed = registry.plan_ids(decision.required_stage_ids)

    assert tuple(stage.id for stage in planned) == decision.required_stage_ids
    assert executed == planned


def test_runner_uses_bounded_environment_without_shell_and_records_terminal_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[dict[str, object]] = []

    real_popen = subprocess.Popen

    def recording_popen(argv: tuple[str, ...], **kwargs: object) -> subprocess.Popen[bytes]:
        calls.append({"argv": argv, **kwargs})
        return real_popen(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", recording_popen)
    stage = Stage(
        id="safe",
        argv=("python", "-c", "import os; print(os.environ.get('PRE_COMMIT_HOME', 'missing'))"),
        gates=("G0",),
        timeout_seconds=30,
    )

    result = StageRunner(
        ROOT,
        inherited_environment={
            "PATH": "bounded",
            "PRE_COMMIT_HOME": "repo-local-cache",
            "TMPDIR": "repo-local-playwright-temp",
            "APPDATA": "app-data",
            "LOCALAPPDATA": "local-app-data",
            "ProgramData": "program-data",
            "ProgramFiles": "program-files",
            "ProgramFiles(x86)": "program-files-x86",
            "ProgramW6432": "program-w6432",
            "TOKEN": "secret",
        },
    ).run(stage)

    assert result.status == "passed"
    assert result.exit_code == 0
    assert calls[0]["shell"] is False
    assert calls[0]["env"] == {
        "PATH": "bounded",
        "PRE_COMMIT_HOME": "repo-local-cache",
        "TMPDIR": "repo-local-playwright-temp",
        "APPDATA": "app-data",
        "LOCALAPPDATA": "local-app-data",
        "ProgramData": "program-data",
        "ProgramFiles": "program-files",
        "ProgramFiles(x86)": "program-files-x86",
        "ProgramW6432": "program-w6432",
    }
    assert "stdout" not in result.__dict__
    assert "stderr" not in result.__dict__
    assert result.started_at is not None
    assert result.ended_at is not None
    assert "repo-local-cache" in capsys.readouterr().out


def test_runner_preserves_only_exact_code_owned_git_hardening_values() -> None:
    fixed_git_environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    probe = (
        "import os,sys; expected="
        f"{fixed_git_environment!r}; "
        "sys.exit(0 if all(os.environ.get(key) == value for key, value in expected.items()) else 1)"
    )
    stage = Stage(
        id="git-environment-probe",
        argv=("python", "-c", probe),
        gates=("G2",),
        timeout_seconds=30,
    )

    runner = StageRunner(
        ROOT,
        inherited_environment={
            "PATH": os.environ["PATH"],
            "GIT_CONFIG_NOSYSTEM": "0",
            "GIT_TERMINAL_PROMPT": "1",
        },
        fixed_environment=fixed_git_environment,
    )

    assert runner.run(stage).status == "passed"
    with pytest.raises(ValidationConfigError, match="fixed environment"):
        StageRunner(
            ROOT,
            inherited_environment={"PATH": os.environ["PATH"]},
            fixed_environment={"GIT_TERMINAL_PROMPT": "1"},
        )
    with pytest.raises(ValidationConfigError, match="fixed environment"):
        StageRunner(
            ROOT,
            inherited_environment={"PATH": os.environ["PATH"]},
            fixed_environment={"GIT_CONFIG_NOSYSTEM": "1"},
        )


def _pid_exists(pid: int) -> bool:
    if os.name == "nt":
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            exit_code = ctypes.c_ulong()
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return exit_code.value == 259
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_runner_fails_closed_on_timeout_and_terminates_descendant_tree(tmp_path: Path) -> None:
    grandchild_pid = tmp_path / "grandchild.pid"
    grandchild_code = (
        "import os,time; from pathlib import Path; "
        f"Path({str(grandchild_pid)!r}).write_text(str(os.getpid()), encoding='utf-8'); "
        "time.sleep(60)"
    )
    child_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild_code!r}]); "
        "time.sleep(60)"
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "time.sleep(60)"
    )
    stage = Stage(id="slow", argv=("python", "-c", parent_code), gates=("G2",), timeout_seconds=1)

    result = StageRunner(ROOT, inherited_environment={"PATH": os.environ["PATH"]}).run(stage)

    assert result.status == "timed_out"
    assert result.exit_code is None
    assert grandchild_pid.is_file()
    pid = int(grandchild_pid.read_text(encoding="utf-8"))
    for _ in range(20):
        if not _pid_exists(pid):
            break
        time.sleep(0.1)
    assert not _pid_exists(pid)


def test_runner_does_not_launch_a_stage_after_its_absolute_deadline_expires(tmp_path: Path) -> None:
    marker = tmp_path / "expired-stage-ran.marker"
    stage = Stage(
        id="expired",
        argv=("python", "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"),
        gates=("G2",),
        timeout_seconds=30,
    )

    result = StageRunner(ROOT, inherited_environment={"PATH": os.environ["PATH"]}).run(
        stage,
        deadline_monotonic=time.monotonic() - 1,
    )

    assert result.status == "timed_out"
    assert result.exit_code is None
    assert not marker.exists()


def test_runner_clips_stage_timeout_to_remaining_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import redagent_platform.validation.stages as stages_module

    observed_timeouts: list[float] = []

    class BlockingProcess:
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        returncode = None

        def wait(self, timeout: float | None = None) -> None:
            observed_timeouts.append(float(timeout))
            raise subprocess.TimeoutExpired("blocked-stage", timeout)

        def poll(self) -> None:
            return None

    process = BlockingProcess()
    monkeypatch.setattr(stages_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(StageRunner, "_terminate_process_tree", lambda *_args: True)
    monkeypatch.setattr(StageRunner, "_create_windows_kill_job", staticmethod(lambda: 1))
    monkeypatch.setattr(StageRunner, "_assign_windows_kill_job", staticmethod(lambda *_args: True))
    monkeypatch.setattr(StageRunner, "_resume_windows_process", staticmethod(lambda *_args: True))
    monkeypatch.setattr(StageRunner, "_close_windows_job", staticmethod(lambda *_args: None))
    stage = Stage(id="clipped", argv=("python", "-V"), gates=("G2",), timeout_seconds=30)

    result = StageRunner(ROOT, inherited_environment={"PATH": os.environ["PATH"]}).run(
        stage,
        deadline_monotonic=time.monotonic() + 5,
    )

    assert result.status == "timed_out"
    assert len(observed_timeouts) == 1
    assert 0 < observed_timeouts[0] <= 5


def test_runner_skips_stream_drain_joins_after_absolute_deadline_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import redagent_platform.validation.stages as stages_module

    now = {"value": 100.0}
    process_wait_timeouts: list[float] = []
    joined_timeouts: list[float] = []

    class FakeTime:
        @staticmethod
        def monotonic() -> float:
            return now["value"]

    class ExpiringProcess:
        pid = 123
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        returncode = None

        def wait(self, timeout: float | None = None) -> None:
            process_wait_timeouts.append(float(timeout))
            if len(process_wait_timeouts) == 1:
                now["value"] = 102.0
                raise subprocess.TimeoutExpired("expired-stage", timeout)

        def poll(self) -> int:
            return 0

        def kill(self) -> None:
            pytest.fail("expired cleanup must not wait before checking the process state")

    class FakeOS:
        name = "posix"

        @staticmethod
        def killpg(_pid: int, _signal: int) -> None:
            pass

    class FakeSignal:
        SIGTERM = 15
        SIGKILL = 9

    class RecordingThread:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def join(self, timeout: float | None = None) -> None:
            joined_timeouts.append(float(timeout))

    monkeypatch.setattr(stages_module, "time", FakeTime)
    monkeypatch.setattr(stages_module, "os", FakeOS)
    monkeypatch.setattr(stages_module, "signal", FakeSignal)
    monkeypatch.setattr(stages_module.threading, "Thread", RecordingThread)
    monkeypatch.setattr(stages_module.subprocess, "Popen", lambda *_args, **_kwargs: ExpiringProcess())
    stage = Stage(id="drain-deadline", argv=("python", "-V"), gates=("G2",), timeout_seconds=30)

    result = StageRunner(ROOT, inherited_environment={"PATH": os.environ["PATH"]}).run(
        stage,
        deadline_monotonic=101.0,
    )

    assert result.status == "failed"
    assert process_wait_timeouts == [1.0]
    assert joined_timeouts == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group escalation path")
def test_runner_sigkills_descendant_that_ignores_sigterm_after_leader_exit(tmp_path: Path) -> None:
    grandchild_pid = tmp_path / "ignoring-grandchild.pid"
    grandchild_code = (
        "import os,signal,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"Path({str(grandchild_pid)!r}).write_text(str(os.getpid()), encoding='utf-8'); "
        "time.sleep(60)"
    )
    parent_code = (
        "import subprocess,sys,time; from pathlib import Path; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild_code!r}]); "
        f"marker=Path({str(grandchild_pid)!r}); "
        "[(time.sleep(0.01)) for _ in range(500) if not marker.exists()]"
    )
    stage = Stage(id="successful", argv=("python", "-c", parent_code), gates=("G2",), timeout_seconds=30)

    result = StageRunner(ROOT, inherited_environment={"PATH": os.environ["PATH"]}).run(stage)

    assert result.status == "passed"
    pid = int(grandchild_pid.read_text(encoding="utf-8"))
    for _ in range(20):
        if not _pid_exists(pid):
            break
        time.sleep(0.1)
    assert not _pid_exists(pid)


def test_runner_surfaces_bounded_redacted_failure_diagnostic(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = (
        "import sys; "
        f"print('failed at ' + {str(ROOT)!r} + ' api_token=unsafe-value'); "
        "print('Authorization: Bearer bearer-value', file=sys.stderr); "
        "print('Cookie: session=cookie-value', file=sys.stderr); "
        "print('actionable validator failure', file=sys.stderr); sys.exit(1)"
    )
    stage = Stage(id="safe", argv=("python", "-c", code), gates=("G1",), timeout_seconds=30)

    result = StageRunner(ROOT, inherited_environment={"PATH": "bounded"}).run(stage)
    output = capsys.readouterr().err

    assert result.status == "failed"
    assert "actionable validator failure" in output
    assert "<repo>" in output
    assert str(ROOT) not in output
    assert "unsafe-value" not in output
    assert "bearer-value" not in output
    assert "cookie-value" not in output


def test_runner_redacts_common_assignment_json_cloud_and_connection_credentials() -> None:
    runner = StageRunner(ROOT, inherited_environment={"PATH": "bounded"})
    diagnostic = runner._redact_diagnostic(
        'api_key=KEY123 refresh_token: REFRESH123 client_secret="CLIENT123" '  # pragma: allowlist secret
        'AWS_SECRET_ACCESS_KEY=AWS123 {"private_key":"PRIVATE123"} '  # pragma: allowlist secret
        'postgresql://operator:DBPASS@localhost/database session_id=SESSION123 '  # pragma: allowlist secret
        'OPENAI_API_KEY=OPENAI123 GITHUB_TOKEN=GITHUB123 AZURE_CLIENT_SECRET=AZURE123'  # pragma: allowlist secret
    )

    for secret in (
        "KEY123", "REFRESH123", "CLIENT123", "AWS123", "PRIVATE123", "DBPASS", "SESSION123",
        "OPENAI123", "GITHUB123", "AZURE123",
    ):
        assert secret not in diagnostic


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended creation and Job assignment path")
def test_runner_does_not_execute_child_before_successful_job_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "pre-assignment.marker"
    original_assign = StageRunner._assign_windows_kill_job
    observed_before_assignment: list[bool] = []

    def delayed_assign(process: subprocess.Popen[bytes], job_handle: int | None) -> bool:
        time.sleep(0.3)
        observed_before_assignment.append(marker.exists())
        return original_assign(process, job_handle)

    monkeypatch.setattr(StageRunner, "_assign_windows_kill_job", staticmethod(delayed_assign))
    stage = Stage(
        id="contained",
        argv=("python", "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"),
        gates=("G2",),
        timeout_seconds=30,
    )

    result = StageRunner(ROOT, inherited_environment={"PATH": os.environ["PATH"]}).run(stage)

    assert result.status == "passed"
    assert observed_before_assignment == [False]
    assert marker.read_text(encoding="utf-8") == "ran"


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended assignment-failure path")
def test_runner_never_executes_child_when_job_assignment_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "assignment-failed.marker"
    monkeypatch.setattr(
        StageRunner,
        "_assign_windows_kill_job",
        staticmethod(lambda process, job_handle: False),
    )
    stage = Stage(
        id="contained",
        argv=("python", "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('escaped')"),
        gates=("G2",),
        timeout_seconds=30,
    )

    result = StageRunner(ROOT, inherited_environment={"PATH": os.environ["PATH"]}).run(stage)
    time.sleep(0.2)

    assert result.status == "failed"
    assert result.exit_code is None
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object failure path")
def test_runner_fails_stage_when_windows_job_containment_cannot_be_established(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(StageRunner, "_create_windows_kill_job", staticmethod(lambda: None))
    stage = Stage(id="contained", argv=("python", "-c", "print('must-not-pass')"), gates=("G2",), timeout_seconds=30)

    result = StageRunner(ROOT, inherited_environment={"PATH": os.environ["PATH"]}).run(stage)

    assert result.status == "failed"
    assert result.exit_code is None


def test_runner_stream_capture_is_memory_bounded() -> None:
    destination = bytearray()

    StageRunner._drain_stream(io.BytesIO(b"x" * 200_000), destination)

    assert len(destination) == 65_536
