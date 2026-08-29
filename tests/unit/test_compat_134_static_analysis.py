from __future__ import annotations

import json
from pathlib import Path
import tomllib

import pytest

from redagent_platform.validation import build_default_registry
from redagent_platform.validation import static_analysis
from redagent_platform.validation.static_analysis import (
    MYPY_PLATFORMS,
    MYPY_TARGETS,
    StaticAnalysisError,
    build_broad_exception_inventory,
    run_mypy_gate,
    run_mypy_matrix,
    run_ruff_gate,
    sync_mypy_baseline,
    sync_mypy_matrix,
    sync_ruff_baseline,
    validate_broad_exception_triage,
)


ROOT = Path(__file__).resolve().parents[2]
RUFF_BASELINE = ROOT / "config/validation/backend-static-analysis/ruff-baseline.json"
BROAD_EXCEPTION_TRIAGE = ROOT / "config/validation/backend-static-analysis/broad-exception-triage.json"


def test_backend_static_analysis_stages_are_blocking_and_precede_backend_tests() -> None:
    stages = build_default_registry(ROOT).plan("G2")
    by_id = {stage.id: stage for stage in stages}

    assert by_id["backend-lint"].argv == (
        "python",
        "-m",
        "redagent_platform.validation.static_analysis",
        "lint",
    )
    assert by_id["backend-typecheck"].argv == (
        "python",
        "-m",
        "redagent_platform.validation.static_analysis",
        "typecheck",
    )
    assert by_id["backend-lint"].gates == ("G1", "G2")
    assert by_id["backend-typecheck"].gates == ("G1", "G2")
    ids = tuple(stage.id for stage in stages)
    assert ids.index("backend-lint") < ids.index("backend-tests")
    assert ids.index("backend-typecheck") < ids.index("backend-tests")


def test_ruff_baseline_is_an_exact_ratchet_for_new_findings(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    baseline = tmp_path / "ruff-baseline.json"
    source.write_text("def answer() -> int:\n    return 42\n", encoding="utf-8")

    sync_ruff_baseline(tmp_path, ("sample.py",), baseline)
    assert b"\r\n" not in baseline.read_bytes()
    run_ruff_gate(tmp_path, ("sample.py",), baseline)
    source.write_text("def answer() -> int:\n    return missing_name\n", encoding="utf-8")

    with pytest.raises(StaticAnalysisError, match="new Ruff finding"):
        run_ruff_gate(tmp_path, ("sample.py",), baseline)


def test_mypy_baseline_is_an_exact_ratchet_for_new_errors(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    baseline = tmp_path / "mypy-baseline.txt"
    source.write_text("def answer() -> int:\n    return 42\n", encoding="utf-8")

    for platform in MYPY_PLATFORMS:
        target_baseline = baseline.with_stem(f"{baseline.stem}-{platform}")
        source.write_text("def answer() -> int:\n    return 42\n", encoding="utf-8")
        sync_mypy_baseline(
            tmp_path,
            ("sample.py",),
            target_baseline,
            config_path=None,
            platform=platform,
        )
        assert b"\r\n" not in target_baseline.read_bytes()
        run_mypy_gate(
            tmp_path,
            ("sample.py",),
            target_baseline,
            config_path=None,
            platform=platform,
        )
        source.write_text('def answer() -> int:\n    return "wrong"\n', encoding="utf-8")

        with pytest.raises(StaticAnalysisError, match="new Mypy error"):
            run_mypy_gate(
                tmp_path,
                ("sample.py",),
                target_baseline,
                config_path=None,
                platform=platform,
            )


def test_mypy_platform_stubs_are_bound_to_the_matching_baseline(tmp_path: Path) -> None:
    source = tmp_path / "platform_sample.py"
    windows_baseline = tmp_path / "mypy-baseline.txt"
    linux_baseline = tmp_path / "mypy-baseline-linux.txt"
    source.write_text("import ctypes\nwindows_loader = ctypes.windll\n", encoding="utf-8")

    sync_mypy_baseline(
        tmp_path,
        ("platform_sample.py",),
        windows_baseline,
        config_path=None,
        platform="win32",
    )
    sync_mypy_baseline(
        tmp_path,
        ("platform_sample.py",),
        linux_baseline,
        config_path=None,
        platform="linux",
    )

    assert windows_baseline.read_bytes() != linux_baseline.read_bytes()
    run_mypy_gate(
        tmp_path,
        ("platform_sample.py",),
        windows_baseline,
        config_path=None,
        platform="win32",
    )
    run_mypy_gate(
        tmp_path,
        ("platform_sample.py",),
        linux_baseline,
        config_path=None,
        platform="linux",
    )
    with pytest.raises(StaticAnalysisError, match="new Mypy error"):
        run_mypy_gate(
            tmp_path,
            ("platform_sample.py",),
            windows_baseline,
            config_path=None,
            platform="linux",
        )


def test_mypy_target_matrix_is_explicit_ordered_and_uses_distinct_baselines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, Path]] = []

    def fake_run_mypy_gate(
        repository_root: Path,
        source_paths: tuple[str, ...],
        baseline_path: Path,
        *,
        config_path: Path | None,
        platform: str,
    ) -> None:
        assert repository_root == tmp_path
        assert source_paths == ("sample.py",)
        assert config_path is None
        observed.append((platform, baseline_path))

    targets = (
        ("win32", tmp_path / "mypy-baseline.txt"),
        ("linux", tmp_path / "mypy-baseline-linux.txt"),
    )
    monkeypatch.setattr(static_analysis, "run_mypy_gate", fake_run_mypy_gate)

    run_mypy_matrix(tmp_path, ("sample.py",), targets, config_path=None)

    assert observed == list(targets)
    assert tuple(platform for platform, _path in MYPY_TARGETS) == MYPY_PLATFORMS
    with pytest.raises(StaticAnalysisError, match="win32 then linux exactly once"):
        run_mypy_matrix(tmp_path, ("sample.py",), tuple(reversed(targets)), config_path=None)
    shared = tmp_path / "shared-baseline.txt"
    with pytest.raises(StaticAnalysisError, match="distinct paths"):
        run_mypy_matrix(
            tmp_path,
            ("sample.py",),
            (("win32", shared), ("linux", shared)),
            config_path=None,
        )
    with pytest.raises(StaticAnalysisError, match="canonical repo-contained"):
        run_mypy_matrix(
            tmp_path,
            ("sample.py",),
            (("win32", targets[1][1]), ("linux", targets[0][1])),
            config_path=None,
        )


def test_mypy_sync_matrix_covers_both_canonical_targets_and_labels_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, Path]] = []

    def fake_sync_mypy_baseline(
        repository_root: Path,
        source_paths: tuple[str, ...],
        baseline_path: Path,
        *,
        config_path: Path | None,
        platform: str,
    ) -> None:
        assert repository_root == tmp_path
        assert source_paths == ("sample.py",)
        assert config_path is None
        observed.append((platform, baseline_path))

    targets = (
        ("win32", tmp_path / "mypy-baseline.txt"),
        ("linux", tmp_path / "mypy-baseline-linux.txt"),
    )
    monkeypatch.setattr(static_analysis, "sync_mypy_baseline", fake_sync_mypy_baseline)

    sync_mypy_matrix(tmp_path, ("sample.py",), targets, config_path=None)

    assert observed == list(targets)

    def fail_linux_sync(
        repository_root: Path,
        source_paths: tuple[str, ...],
        baseline_path: Path,
        *,
        config_path: Path | None,
        platform: str,
    ) -> None:
        if platform == "linux":
            raise StaticAnalysisError("fixture sync failure")

    monkeypatch.setattr(static_analysis, "sync_mypy_baseline", fail_linux_sync)
    with pytest.raises(StaticAnalysisError, match="Mypy target linux failed"):
        sync_mypy_matrix(tmp_path, ("sample.py",), targets, config_path=None)

    swapped = (("win32", targets[1][1]), ("linux", targets[0][1]))
    with pytest.raises(StaticAnalysisError, match="canonical repo-contained"):
        sync_mypy_matrix(tmp_path, ("sample.py",), swapped, config_path=None)


def test_mypy_target_failure_names_the_failed_platform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_mypy_gate(
        repository_root: Path,
        source_paths: tuple[str, ...],
        baseline_path: Path,
        *,
        config_path: Path | None,
        platform: str,
    ) -> None:
        if platform == "linux":
            raise StaticAnalysisError("fixture failure")

    monkeypatch.setattr(static_analysis, "run_mypy_gate", fake_run_mypy_gate)
    targets = (
        ("win32", tmp_path / "mypy-baseline.txt"),
        ("linux", tmp_path / "mypy-baseline-linux.txt"),
    )

    with pytest.raises(StaticAnalysisError, match="Mypy target linux failed"):
        run_mypy_matrix(tmp_path, ("sample.py",), targets, config_path=None)


def test_broad_exception_triage_detects_missing_or_changed_sites(tmp_path: Path) -> None:
    source = tmp_path / "boundary.py"
    manifest = tmp_path / "triage.json"
    source.write_text(
        "def boundary() -> None:\n"
        "    try:\n"
        "        raise RuntimeError('fixture')\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    sites = build_broad_exception_inventory(tmp_path, ("boundary.py",))
    assert len(sites) == 1
    fingerprint = str(sites[0]["fingerprint"])
    assert fingerprint.startswith("ast-v1-")
    assert all(len(group) == 8 for group in fingerprint.removeprefix("ast-v1-").split("-"))
    classified = dict(sites[0])
    classified.update(
        classification="legitimate_cleanup",
        rationale="Synthetic bounded cleanup fixture.",
    )
    manifest.write_text(
        json.dumps({"schema_version": "1", "sites": [classified]}),
        encoding="utf-8",
    )

    validate_broad_exception_triage(tmp_path, ("boundary.py",), manifest)
    manifest.write_text(
        json.dumps({"schema_version": "1", "sites": []}),
        encoding="utf-8",
    )

    with pytest.raises(StaticAnalysisError, match="broad-exception triage drift"):
        validate_broad_exception_triage(tmp_path, ("boundary.py",), manifest)


def test_repository_static_analysis_configuration_and_triage_are_current() -> None:
    requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "ruff==0.16.4" in requirements
    assert "mypy==2.3.1" in requirements
    assert "mypy-baseline==0.7.4" in requirements
    assert config["tool"]["ruff"]["lint"]["select"] == ["E4", "E7", "E9", "F", "BLE001", "TID251"]
    banned = config["tool"]["ruff"]["lint"]["flake8-tidy-imports"]["banned-api"]
    assert "redagent_platform.api._route_support" in banned
    baseline = json.loads(RUFF_BASELINE.read_text(encoding="utf-8"))
    assert all(finding["code"] != "BLE001" for finding in baseline["findings"])
    validate_broad_exception_triage(
        ROOT,
        ("redagent_platform",),
        BROAD_EXCEPTION_TRIAGE,
    )
