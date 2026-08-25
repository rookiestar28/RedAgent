from __future__ import annotations

import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import subprocess
import sys

import pytest

from redagent_platform import gate_lease
from redagent_platform.validation.stages import StageRunner
from scripts import run_validation_gate


ROOT = Path(__file__).resolve().parents[2]
POSIX_VENV_GUARD = ROOT / "scripts/verify_posix_venv_layout.sh"


def _config_values(command: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(command[index + 1] for index, token in enumerate(command[:-1]) if token == "-c")


def test_direct_git_queries_trust_only_the_exact_authoritative_root() -> None:
    command = run_validation_gate._isolated_git_command(("status", "--porcelain=v1"))

    safe_values = tuple(
        value for value in _config_values(command) if value.startswith("safe.directory=")
    )
    assert safe_values == (f"safe.directory={ROOT.absolute()}",)
    assert "safe.directory=*" not in command


def test_nested_stage_git_environment_replaces_ambient_config_injection() -> None:
    inherited = dict(os.environ)
    inherited.update(
        {
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": "*",
            "GIT_CONFIG_KEY_1": "credential.helper",
            "GIT_CONFIG_VALUE_1": "unsafe-helper",
        }
    )

    runner = StageRunner(
        ROOT,
        inherited,
        fixed_environment=StageRunner._FIXED_ENVIRONMENT_VALUES,
    )

    assert runner._environment["GIT_CONFIG_COUNT"] == "1"
    assert runner._environment["GIT_CONFIG_KEY_0"] == "safe.directory"
    assert runner._environment["GIT_CONFIG_VALUE_0"] == str(ROOT.resolve())
    assert "GIT_CONFIG_KEY_1" not in runner._environment
    assert "GIT_CONFIG_VALUE_1" not in runner._environment
    different_owner = dict(runner._environment)
    different_owner["GIT_TEST_ASSUME_DIFFERENT_OWNER"] = "1"
    completed = subprocess.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=normal"),
        cwd=ROOT,
        env=different_owner,
        capture_output=True,
        check=False,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")


def test_lease_ignore_query_uses_only_the_exact_workspace_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def completed(command: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(gate_lease.subprocess, "run", completed)

    target = gate_lease.validated_authoritative_validation_lease_path(tmp_path)

    command = observed["command"]
    assert isinstance(command, tuple)
    assert f"safe.directory={tmp_path.absolute()}" in _config_values(command)
    environment = observed["environment"]
    assert isinstance(environment, dict)
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert not any(key.startswith("GIT_CONFIG_KEY_") for key in environment)
    assert target == tmp_path / ".tmp/validation/authoritative-validation.lock"


def test_worktree_state_distinguishes_git_query_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        run_validation_gate,
        "_git",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=128, stdout=b""),
    )

    state = run_validation_gate._worktree_state()

    assert state.kind == "query_failed"
    assert state.entries == ()
    assert run_validation_gate._worktree_failure_summary(state) == "git_source_state_query_failed"


def test_worktree_state_reports_only_bounded_encoded_status_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [b"?? generated-" + str(index).encode("ascii") + b".txt" for index in range(80)]
    entries.insert(0, b"?? line\nbreak.txt")
    payload = b"\0".join(entries) + b"\0"
    monkeypatch.setattr(
        run_validation_gate,
        "_git",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=payload),
    )

    state = run_validation_gate._worktree_state()
    summary = run_validation_gate._worktree_failure_summary(state)

    assert state.kind == "dirty"
    assert len(state.entries) == 81
    assert summary.startswith("worktree_dirty total=81 entries=")
    assert "\\n" in summary
    assert "\n" not in summary
    assert len(summary.encode("utf-8")) <= 4096


def test_posix_guard_revalidates_the_single_allowed_link_before_interpreter_use() -> None:
    source = POSIX_VENV_GUARD.read_text(encoding="utf-8")

    assert source.count("assert_exact_lib64_compatibility_link") == 3
    final_check = source.rindex("assert_exact_lib64_compatibility_link")
    site_validation = source.rindex('assert_contained_real_path "$site_dir"')
    success = source.index('echo "posix_venv_layout_ok=true"')
    assert site_validation < final_check < success


@pytest.mark.skipif(sys.platform == "win32", reason="native POSIX symlink semantics required")
def test_posix_guard_allows_only_the_standard_contained_lib64_link(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    guard = scripts / POSIX_VENV_GUARD.name
    shutil.copyfile(POSIX_VENV_GUARD, guard)
    venv = repository / ".venv-wsl"
    primary = venv / "lib/python3.13/site-packages"
    primary.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text(
        "include-system-site-packages = false\n",
        encoding="utf-8",
    )
    compatibility = venv / "lib64"
    compatibility.symlink_to("lib", target_is_directory=True)

    accepted = subprocess.run(
        ("bash", str(guard)),
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert accepted.returncode == 0, accepted.stderr
    compatibility.unlink()
    outside = tmp_path / "outside"
    outside.mkdir()
    compatibility.symlink_to(outside, target_is_directory=True)

    rejected = subprocess.run(
        ("bash", str(guard)),
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert rejected.returncode != 0
    assert any(token in rejected.stderr.casefold() for token in ("symlink", "escaped", "lib64"))
    compatibility.unlink()
    compatibility.symlink_to(venv / "lib", target_is_directory=True)
    absolute = subprocess.run(
        ("bash", str(guard)),
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    assert absolute.returncode != 0
    compatibility.unlink()
    bridge = venv / "bridge"
    bridge.symlink_to("lib", target_is_directory=True)
    compatibility.symlink_to("bridge", target_is_directory=True)
    chained = subprocess.run(
        ("bash", str(guard)),
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    assert chained.returncode != 0
