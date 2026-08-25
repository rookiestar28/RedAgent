from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_canonical_lease_path_refuses_ignore_policy_drift_without_creating_runtime_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import redagent_platform.gate_lease as gate_lease

    observed: dict[str, object] = {}

    def rejected_git(*args: object, **kwargs: object) -> SimpleNamespace:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(gate_lease.subprocess, "run", rejected_git)

    with pytest.raises(gate_lease.ValidationLeaseError, match="ignored by Git"):
        gate_lease.validated_authoritative_validation_lease_path(tmp_path)

    assert not (tmp_path / ".tmp").exists()
    expected_prefix = [
        "git",
        "--no-replace-objects",
        "-c",
        f"safe.directory={tmp_path.absolute()}",
    ]
    if os.name == "nt":
        expected_prefix.extend(("-c", "core.autocrlf=true"))
    expected_prefix.extend(("check-ignore", "--quiet"))
    assert observed["args"][0][: len(expected_prefix)] == tuple(expected_prefix)


def test_unsupported_host_python_fails_before_venv_lease_or_platform_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import prepare_validation_venv

    target = "windows" if sys.platform == "win32" else "posix"
    monkeypatch.setattr(prepare_validation_venv, "ROOT", tmp_path)
    monkeypatch.setattr(prepare_validation_venv.sys, "version_info", (3, 10, 0))
    monkeypatch.setattr(
        prepare_validation_venv,
        "validated_authoritative_validation_lease_path",
        lambda _root: (_ for _ in ()).throw(AssertionError("must not acquire a lease")),
    )
    monkeypatch.setattr(
        prepare_validation_venv,
        "bind_authoritative_validation_platform",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not bind a platform")),
    )

    with pytest.raises(prepare_validation_venv.VenvPreparationError, match="Python 3.11"):
        prepare_validation_venv.prepare_project_venv(target)

    assert not (tmp_path / ".tmp").exists()
    assert not (tmp_path / ".venv").exists()
    assert not (tmp_path / ".venv-wsl").exists()


def test_full_gate_wrappers_leave_dependency_bootstrap_to_the_leased_gate_runners() -> None:
    windows = (ROOT / "scripts" / "run_full_tests_windows.ps1").read_text(encoding="utf-8")
    linux = (ROOT / "scripts" / "run_full_tests_linux.sh").read_text(encoding="utf-8")
    current = (ROOT / "scripts" / "run_validation_gate.py").read_text(encoding="utf-8")
    legacy = (ROOT / "scripts" / "run_legacy_full_gate.py").read_text(encoding="utf-8")

    assert "scripts/install_validation_dependencies.py" not in windows
    assert "scripts/install_validation_dependencies.py" not in linux
    assert "-m pip install" not in windows
    assert "-m pip install" not in linux
    assert "scripts/prepare_validation_venv.py" in windows
    assert "scripts/prepare_validation_venv.py" in linux
    assert "python -m venv .venv" not in windows
    assert 'virtualenv --python "$python_cmd" --no-download .venv-wsl' not in linux
    assert "New-Item -ItemType Directory -Force -Path $env:PRE_COMMIT_HOME" not in windows
    assert 'mkdir -p "$repo_root/.tmp/playwright"' not in linux
    assert "ln -sfn" not in linux
    assert "_bootstrap_validation_dependencies" in current
    assert "run_validation_gate.main" in legacy
    assert "_bootstrap_validation_dependencies" not in legacy


def test_first_run_venv_creation_occurs_while_the_authoritative_lease_is_held(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from scripts import prepare_validation_venv

    events: list[str] = []

    class RecordingLease:
        def __init__(self, _path: Path) -> None:
            pass

        def __enter__(self) -> "RecordingLease":
            events.append("lease-enter")
            return self

        def __exit__(self, *_args: object) -> None:
            events.append("lease-exit")

        def capability(self) -> object:
            return object()

    target = "windows" if sys.platform == "win32" else "posix"
    venv_path = tmp_path / (".venv" if target == "windows" else ".venv-wsl")
    monkeypatch.setattr(prepare_validation_venv, "ROOT", tmp_path)
    monkeypatch.setattr(prepare_validation_venv, "ValidationLease", RecordingLease)
    monkeypatch.setattr(
        prepare_validation_venv,
        "bind_authoritative_validation_platform",
        lambda *_args: "windows",
    )
    monkeypatch.setattr(
        prepare_validation_venv,
        "validated_authoritative_validation_lease_path",
        lambda root: root / ".tmp" / "validation" / "authoritative-validation.lock",
    )
    monkeypatch.setattr(
        prepare_validation_venv,
        "_create_project_venv",
        lambda path: events.append("create") or path,
    )
    monkeypatch.setattr(
        prepare_validation_venv,
        "attest_project_venv_layout",
        lambda root, name: venv_path,
    )

    assert prepare_validation_venv.prepare_project_venv(target) == venv_path
    assert events == ["lease-enter", "create", "lease-exit"]


def test_first_run_venv_creation_refuses_a_held_authoritative_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from redagent_platform.gate_lease import ValidationLease, authoritative_validation_lease_path
    from scripts import prepare_validation_venv

    target = "windows" if sys.platform == "win32" else "posix"
    monkeypatch.setattr(prepare_validation_venv, "ROOT", tmp_path)
    monkeypatch.setattr(
        prepare_validation_venv,
        "validated_authoritative_validation_lease_path",
        lambda root: authoritative_validation_lease_path(root),
    )
    monkeypatch.setattr(
        prepare_validation_venv,
        "_create_project_venv",
        lambda _path: (_ for _ in ()).throw(AssertionError("must not create while leased")),
    )

    with ValidationLease(authoritative_validation_lease_path(tmp_path)):
        with pytest.raises(prepare_validation_venv.VenvPreparationError, match="already active"):
            prepare_validation_venv.prepare_project_venv(target)


def test_locked_dependency_bootstrap_uses_contained_stage_runner_and_a_total_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from redagent_platform.gate_lease import ValidationLease, authoritative_validation_lease_path
    from scripts import install_validation_dependencies

    runtime = tmp_path / "requirements-runtime.lock"
    development = tmp_path / "requirements-dev.lock"
    runtime.write_text("# synthetic runtime lock\n", encoding="utf-8")
    development.write_text("# synthetic development lock\n", encoding="utf-8")
    stages: list[object] = []

    def contained_runner(command: tuple[str, ...], timeout_seconds: int) -> str:
        stages.append(SimpleNamespace(argv=command, timeout_seconds=timeout_seconds, id="validation-dependency-bootstrap"))
        return "passed"

    monkeypatch.setattr(install_validation_dependencies, "_run_with_stage_runner", contained_runner)
    monkeypatch.setattr(
        install_validation_dependencies,
        "time",
        SimpleNamespace(monotonic=lambda: 100.0),
    )

    with ValidationLease(authoritative_validation_lease_path(tmp_path)) as lease:
        install_validation_dependencies.install_locked_dependencies(
            (runtime, development),
            timeout_seconds=47,
            lease_capability=lease.capability(),
            root=tmp_path,
        )

    assert [stage.argv for stage in stages] == [
        (
            "python",
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--require-virtualenv",
            "--no-cache-dir",
            "-r",
            str(runtime),
        ),
        (
            "python",
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--require-virtualenv",
            "--no-cache-dir",
            "-r",
            str(development),
        ),
    ]
    assert all(stage.timeout_seconds == 47 for stage in stages)
    assert all(stage.id == "validation-dependency-bootstrap" for stage in stages)
    assert all("--upgrade" not in stage.argv for stage in stages)
    assert all("--no-input" in stage.argv and "--isolated" in stage.argv for stage in stages)


def test_locked_dependency_bootstrap_clips_to_the_caller_absolute_deadline_and_keeps_two_argument_runners(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Legacy test runners receive a clipped duration without a new required argument."""

    from redagent_platform.gate_lease import ValidationLease, authoritative_validation_lease_path
    from scripts import install_validation_dependencies

    runtime = tmp_path / "requirements-runtime.lock"
    development = tmp_path / "requirements-dev.lock"
    runtime.write_text("# synthetic runtime lock\n", encoding="utf-8")
    development.write_text("# synthetic development lock\n", encoding="utf-8")
    observed: list[int] = []

    def two_argument_runner(_command: tuple[str, ...], timeout_seconds: int) -> str:
        observed.append(timeout_seconds)
        return "passed"

    monkeypatch.setattr(
        install_validation_dependencies,
        "time",
        SimpleNamespace(monotonic=lambda: 100.0),
    )

    with ValidationLease(authoritative_validation_lease_path(tmp_path)) as lease:
        install_validation_dependencies.install_locked_dependencies(
            (runtime, development),
            timeout_seconds=47,
            deadline_monotonic=105.9,
            lease_capability=lease.capability(),
            command_runner=two_argument_runner,
            root=tmp_path,
        )

    assert observed == [5, 5]


def test_locked_dependency_bootstrap_does_not_round_a_callback_past_the_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from redagent_platform.gate_lease import ValidationLease, authoritative_validation_lease_path
    from scripts import install_validation_dependencies

    runtime = tmp_path / "requirements-runtime.lock"
    development = tmp_path / "requirements-dev.lock"
    runtime.write_text("# synthetic runtime lock\n", encoding="utf-8")
    development.write_text("# synthetic development lock\n", encoding="utf-8")
    monkeypatch.setattr(
        install_validation_dependencies,
        "time",
        SimpleNamespace(monotonic=lambda: 100.0),
    )

    with ValidationLease(authoritative_validation_lease_path(tmp_path)) as lease:
        with pytest.raises(install_validation_dependencies.DependencyInstallError, match="timed out"):
            install_validation_dependencies.install_locked_dependencies(
                (runtime, development),
                timeout_seconds=47,
                deadline_monotonic=100.9,
                lease_capability=lease.capability(),
                command_runner=lambda *_args: pytest.fail("deadline exhausted runner must not launch"),
                root=tmp_path,
            )


def test_current_bootstrap_stage_declares_only_the_full_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import install_validation_dependencies
    from redagent_platform.validation import stages as validation_stages

    observed: list[object] = []

    class RecordingRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, stage: object) -> SimpleNamespace:
            observed.append(stage)
            return SimpleNamespace(status="passed")

    monkeypatch.setattr(validation_stages, "StageRunner", RecordingRunner)

    assert install_validation_dependencies._run_with_stage_runner(("python", "-V"), 47) == "passed"
    assert len(observed) == 1
    assert observed[0].gates == ("G2",)


def test_current_bootstrap_stage_forwards_the_exact_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import install_validation_dependencies
    from redagent_platform.validation import stages as validation_stages

    observed: dict[str, object] = {}

    class RecordingRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, stage: object, *, deadline_monotonic: float | None = None) -> SimpleNamespace:
            observed["stage"] = stage
            observed["deadline"] = deadline_monotonic
            return SimpleNamespace(status="passed")

    monkeypatch.setattr(validation_stages, "StageRunner", RecordingRunner)

    assert (
        install_validation_dependencies._run_with_stage_runner(
            ("python", "-V"),
            47,
            deadline_monotonic=123.4,
        )
        == "passed"
    )
    assert observed["deadline"] == 123.4


def test_project_venv_creation_uses_the_contained_stage_runner_and_a_total_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from scripts import prepare_validation_venv
    from redagent_platform.validation import stages as validation_stages

    observed: list[object] = []

    class RecordingRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, stage: object) -> SimpleNamespace:
            observed.append(stage)
            return SimpleNamespace(status="passed")

    monkeypatch.setattr(validation_stages, "StageRunner", RecordingRunner)

    assert prepare_validation_venv._create_project_venv(tmp_path / ".venv") == tmp_path / ".venv"
    assert len(observed) == 1
    assert observed[0].id == "validation-venv-preparation"
    assert observed[0].argv == (
        sys.executable,
        "-I",
        "-m",
        "venv",
        str(tmp_path / ".venv"),
    )
    assert observed[0].gates == ("G0", "G1", "G2")
    assert observed[0].timeout_seconds == prepare_validation_venv.VENV_CREATION_TIMEOUT_SECONDS


def test_project_venv_creation_fails_closed_when_contained_creation_times_out(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from scripts import prepare_validation_venv
    from redagent_platform.validation import stages as validation_stages

    class TimedOutRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, _stage: object) -> SimpleNamespace:
            return SimpleNamespace(status="timed_out")

    monkeypatch.setattr(validation_stages, "StageRunner", TimedOutRunner)

    with pytest.raises(prepare_validation_venv.VenvPreparationError, match="timed out"):
        prepare_validation_venv._create_project_venv(tmp_path / ".venv")


def test_locked_dependency_bootstrap_fails_closed_when_the_contained_stage_times_out(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from redagent_platform.gate_lease import ValidationLease, authoritative_validation_lease_path
    from scripts import install_validation_dependencies

    runtime = tmp_path / "requirements-runtime.lock"
    development = tmp_path / "requirements-dev.lock"
    runtime.write_text("# synthetic runtime lock\n", encoding="utf-8")
    development.write_text("# synthetic development lock\n", encoding="utf-8")

    monkeypatch.setattr(
        install_validation_dependencies,
        "_run_with_stage_runner",
        lambda *_args: "timed_out",
    )

    with ValidationLease(authoritative_validation_lease_path(tmp_path)) as lease:
        with pytest.raises(install_validation_dependencies.DependencyInstallError, match="timed out"):
            install_validation_dependencies.install_locked_dependencies(
                (runtime, development),
                timeout_seconds=47,
                lease_capability=lease.capability(),
                root=tmp_path,
            )


def test_locked_dependency_bootstrap_rejects_a_missing_or_inactive_lease_capability(
    tmp_path: Path,
) -> None:
    from scripts import install_validation_dependencies

    runtime = tmp_path / "requirements-runtime.lock"
    development = tmp_path / "requirements-dev.lock"
    runtime.write_text("# synthetic runtime lock\n", encoding="utf-8")
    development.write_text("# synthetic development lock\n", encoding="utf-8")

    with pytest.raises(install_validation_dependencies.DependencyInstallError, match="lease"):
        install_validation_dependencies.install_locked_dependencies(
            (runtime, development),
            lease_capability=None,
            root=tmp_path,
        )


def test_locked_dependency_bootstrap_rejects_a_capability_from_another_lock(
    tmp_path: Path,
) -> None:
    from redagent_platform.gate_lease import ValidationLease
    from scripts import install_validation_dependencies

    runtime = tmp_path / "requirements-runtime.lock"
    development = tmp_path / "requirements-dev.lock"
    runtime.write_text("# synthetic runtime lock\n", encoding="utf-8")
    development.write_text("# synthetic development lock\n", encoding="utf-8")

    with ValidationLease(tmp_path / "other.lock") as lease:
        with pytest.raises(install_validation_dependencies.DependencyInstallError, match="canonical"):
            install_validation_dependencies.install_locked_dependencies(
                (runtime, development),
                lease_capability=lease.capability(),
                root=tmp_path,
            )


def test_authoritative_validation_emits_flushed_stage_and_bootstrap_progress() -> None:
    current = (ROOT / "scripts" / "run_validation_gate.py").read_text(encoding="utf-8")
    bootstrap = (ROOT / "scripts" / "install_validation_dependencies.py").read_text(encoding="utf-8")

    assert '"[started] {executable_stage.id}' in current
    assert '"[started] validation-dependency-bootstrap' in bootstrap
    assert "flush=True" in current
    assert "flush=True" in bootstrap


def test_standalone_bootstrap_refuses_to_bypass_the_authoritative_lease(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scripts import install_validation_dependencies

    monkeypatch.setattr(
        install_validation_dependencies,
        "install_locked_dependencies",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    assert install_validation_dependencies.main() == 2
    assert "authoritative gate" in capsys.readouterr().err
