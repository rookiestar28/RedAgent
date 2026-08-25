from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
import hashlib
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
import yaml

from scripts import run_validation_gate, verify_venv_boundary
from redagent_platform.validation import (
    ChangeRequest,
    StageResult,
    build_verification_receipt,
    classify_change,
)


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/r118-validation.yml"
GATE_WORKFLOW = ROOT / ".github/workflows/r118-validation-gate.yml"
WINDOWS = ROOT / "scripts/run_full_tests_windows.ps1"
LINUX = ROOT / "scripts/run_full_tests_linux.sh"
PACKAGE = ROOT / "package.json"
STAGE_CONFIG = ROOT / "config/validation/r118-stage-registry.json"
VENV_GUARD = ROOT / "scripts/verify_venv_boundary.py"
TEST_SOP = ROOT / "docs/TESTING.md"
POSIX_VENV_GUARD = ROOT / "scripts/verify_posix_venv_layout.sh"
GATE_RUNTIME = ROOT / "redagent_platform/gate_runtime.py"


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", *args),
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
        shell=False,
    )
    return completed.stdout.strip()


def test_validation_workflow_is_always_started_pinned_and_least_privilege() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    uses = re.findall(r"^\s*uses:\s*([^\s]+)$", text, flags=re.MULTILINE)

    assert set(document["on"]) >= {"pull_request", "push", "workflow_dispatch"}
    assert "paths" not in text and "paths-ignore" not in text
    assert document["permissions"] == {"contents": "read"}
    external_uses = [value for value in uses if not value.startswith("./")]
    assert external_uses and all(
        re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", value) for value in external_uses
    )
    assert document["jobs"]["aggregate"]["if"] == "${{ always() }}"
    assert set(document["jobs"]["aggregate"]["needs"]) == {"classify", "g0", "g1", "g2"}
    assert document["jobs"]["classify"]["timeout-minutes"] == 10
    classifier_upload = next(
        step for step in document["jobs"]["classify"]["steps"] if "upload-artifact@" in step.get("uses", "")
    )
    assert classifier_upload["if"] == "${{ always() }}"

    gate_text = GATE_WORKFLOW.read_text(encoding="utf-8")
    gate = yaml.safe_load(gate_text)
    gate_job = gate["jobs"]["run"]
    assert gate_job["timeout-minutes"] == 60
    assert gate_job["permissions"] == {"contents": "read"}
    setup_python = next(step for step in gate_job["steps"] if "setup-python@" in step.get("uses", ""))
    assert setup_python["with"] == {"python-version": "3.13"}
    provision = next(
        step for step in gate_job["steps"] if step["name"].startswith("Explicitly provision")
    )
    assert provision["if"] == "${{ inputs.gate == 'G0' || inputs.gate == 'G1' }}"
    assert provision["run"] == "bash scripts/run_full_tests_linux.sh --provision-dependencies"
    run_step = next(step for step in gate_job["steps"] if step["name"].startswith("Run the selected"))
    steps = gate_job["steps"]
    assert steps.index(setup_python) < steps.index(provision) < steps.index(run_step)
    assert run_step["env"]["SELECTED_GATE"] == "${{ inputs.gate }}"
    assert '${{ inputs.gate }}' not in run_step["run"]
    assert '--gate "$SELECTED_GATE"' in run_step["run"]
    verifier = next(step for step in gate_job["steps"] if step["name"].startswith("Verify externally"))
    assert "run_validation_gate.py verify" in verifier["run"]
    assert '--source-revision "$HEAD_REVISION"' in verifier["run"]
    evidence_steps = [
        step for step in gate_job["steps"] if "upload-artifact@" in step.get("uses", "")
    ]
    assert len(evidence_steps) == 2
    receipt_evidence, product_evidence = evidence_steps
    assert receipt_evidence["with"]["path"] == ".tmp/validation/verification.json"
    assert "inputs.gate == 'G2'" in product_evidence["if"]
    for path in (
        ".tmp/sbom/redagent-sbom.json",
        "frontend/dist/index.html",
        "frontend/cli-dist/cli/redagent.js",
        "frontend/openapi.json",
    ):
        assert path in product_evidence["with"]["path"]


def test_cold_ci_provision_and_selected_gate_budgets_fit_the_workflow_ceiling() -> None:
    from redagent_platform.gate_deadline import GATE_EXECUTION_BUDGET_SECONDS
    from scripts.prepare_validation_venv import VENV_CREATION_TIMEOUT_SECONDS
    from scripts.install_validation_dependencies import DEFAULT_TIMEOUT_SECONDS

    workflow = yaml.safe_load(GATE_WORKFLOW.read_text(encoding="utf-8"))
    ceiling_seconds = workflow["jobs"]["run"]["timeout-minutes"] * 60

    assert VENV_CREATION_TIMEOUT_SECONDS + DEFAULT_TIMEOUT_SECONDS + GATE_EXECUTION_BUDGET_SECONDS["G0"] < ceiling_seconds
    assert VENV_CREATION_TIMEOUT_SECONDS + DEFAULT_TIMEOUT_SECONDS + GATE_EXECUTION_BUDGET_SECONDS["G1"] < ceiling_seconds
    assert VENV_CREATION_TIMEOUT_SECONDS + GATE_EXECUTION_BUDGET_SECONDS["G2"] < ceiling_seconds


def test_wrappers_delegate_to_one_runner_and_frontend_build_does_not_recheck_types() -> None:
    windows = WINDOWS.read_text(encoding="utf-8")
    linux = LINUX.read_text(encoding="utf-8")
    runtime = GATE_RUNTIME.read_text(encoding="utf-8")
    package = PACKAGE.read_text(encoding="utf-8")
    stages = json.loads(STAGE_CONFIG.read_text(encoding="utf-8"))["stages"]

    assert "scripts/run_validation_gate.py" in windows
    assert "scripts/run_validation_gate.py" in linux
    assert "--provision-dependencies" in windows
    assert "--provision-dependencies" in linux
    assert 'if ($args.Count -eq 0)' in windows
    assert 'if [[ "$#" -eq 0 ]]' in linux
    assert "python3.14 python3.13 python3.12 python3.11" in linux
    assert "python3 -m venv" not in linux
    assert "existing .venv-wsl uses incompatible Python" in linux
    assert 'scripts/prepare_validation_venv.py --target posix' in linux
    assert "existing .venv-wsl is incomplete" in linux
    assert 'Path(".tmp") / "playwright"' in runtime
    assert '"TMPDIR": str(playwright)' in runtime
    assert '"TMP": str(playwright)' in runtime and '"TEMP": str(playwright)' in runtime
    assert "ReparsePoint" in windows
    assert "validate project Python 3.11+" in windows
    assert "pre-commit-r118-windows-v1" in runtime
    assert "pre-commit-r118-linux-v1" in runtime
    assert "PRE_COMMIT_HOME" in runtime
    assert "pre-commit run detect-secrets" not in windows
    assert "pre-commit run detect-secrets" not in linux
    assert "assert_safe_ancestor" in linux
    assert "Assert-SafeAncestor" in windows
    assert "GetRelativePath" not in windows
    assert "scripts/verify_venv_boundary.py" in windows
    assert "scripts/verify_venv_boundary.py" in linux
    assert "source .venv-wsl/bin/activate" not in linux
    first_venv_execution = min(
        linux.index(".venv-wsl/bin/python -c"),
        linux.index('"$venv_python" scripts/verify_venv_boundary.py'),
    )
    assert linux.index("scripts/verify_posix_venv_layout.sh") < first_venv_execution
    assert linux.index("unset PYTHONPATH PYTHONHOME PYTHONUSERBASE") < first_venv_execution
    assert linux.index("PYTHONPYCACHEPREFIX") < first_venv_execution
    assert linux.index("PYTHONDONTWRITEBYTECODE=1") < first_venv_execution
    assert linux.index('assert_safe_ancestor "$repo_root/.venv-wsl/bin"') < first_venv_execution
    assert linux.index('assert_safe_ancestor "$repo_root/.venv-wsl/pyvenv.cfg"') < first_venv_execution
    first_windows_venv_execution = windows.index('& $Python -c')
    first_windows_venv_creation = windows.index("scripts/prepare_validation_venv.py --target windows")
    assert windows.index('"PYTHONPATH"') < first_windows_venv_creation
    assert windows.index('Remove-Item -LiteralPath "Env:$PythonStartupVariable"') < windows.index(
        "scripts/prepare_validation_venv.py --target windows"
    )
    assert windows.index('"PYTHONPYCACHEPREFIX"') < first_windows_venv_creation
    assert windows.index('$env:PYTHONDONTWRITEBYTECODE = "1"') < windows.index(
        "scripts/prepare_validation_venv.py --target windows"
    )
    assert "include-system-site-packages = false exactly once" in windows
    assert windows.index('Assert-SafeAncestor $VenvSitePackages') < first_windows_venv_execution
    assert "--legacy-full" in linux
    assert "--legacy-full" in windows
    assert '"build": "vite build' in package
    install = next(stage for stage in stages if stage["id"] == "frontend-install")
    assert install["argv"] == ["npm", "ci", "--audit=false"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink behavior is exercised in WSL")
def test_posix_native_venv_layout_guard_rejects_alternate_external_site_directory(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    guard = scripts / POSIX_VENV_GUARD.name
    shutil.copyfile(POSIX_VENV_GUARD, guard)
    primary = repository / ".venv-wsl/lib/python3.11/site-packages"
    primary.mkdir(parents=True)
    (repository / ".venv-wsl/pyvenv.cfg").write_text(
        "include-system-site-packages = false\n",
        encoding="utf-8",
    )
    alternate_parent = repository / ".venv-wsl/local/lib/python3.11"
    alternate_parent.mkdir(parents=True)
    alternate = alternate_parent / "dist-packages"
    alternate.symlink_to(tmp_path / "outside", target_is_directory=True)

    completed = subprocess.run(
        ("bash", str(guard)),
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert completed.returncode != 0
    assert any(
        message in completed.stderr.casefold()
        for message in ("symlink", "escaped", "not a real directory")
    )

    source = POSIX_VENV_GUARD.read_text(encoding="utf-8")
    for fragment in (
        "/lib/python*/site-packages",
        "/lib/python*/dist-packages",
        "/lib64/python*/site-packages",
        "/local/lib/python*/dist-packages",
        "/local/lib64/python*/dist-packages",
    ):
        assert fragment in source


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX startup behavior is exercised in WSL")
def test_posix_native_venv_layout_guard_rejects_system_site_packages(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    guard = scripts / POSIX_VENV_GUARD.name
    shutil.copyfile(POSIX_VENV_GUARD, guard)
    (repository / ".venv-wsl/lib/python3.11/site-packages").mkdir(parents=True)
    (repository / ".venv-wsl/pyvenv.cfg").write_text(
        "include-system-site-packages = true\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        ("bash", str(guard)),
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert completed.returncode != 0
    assert "include-system-site-packages" in completed.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX startup behavior is exercised in WSL")
def test_linux_wrapper_sanitizes_python_startup_environment_before_venv_interpreter_start(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    for source in (LINUX, POSIX_VENV_GUARD, VENV_GUARD):
        shutil.copyfile(source, scripts / source.name)
    venv = repository / ".venv-wsl"
    (venv / "bin").mkdir(parents=True)
    (venv / "lib/python3.11/site-packages").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text(
        "include-system-site-packages = false\n",
        encoding="utf-8",
    )
    (venv / "bin/python").symlink_to(Path(sys.executable))
    injection = tmp_path / "injection"
    injection.mkdir()
    marker = tmp_path / "sitecustomize-executed"
    (injection / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(injection)
    external_pycache = tmp_path / "external-pycache"
    environment["PYTHONPYCACHEPREFIX"] = str(external_pycache)

    completed = subprocess.run(
        ("bash", str(scripts / LINUX.name), "--help"),
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert completed.returncode != 0
    assert not marker.exists()
    assert not external_pycache.exists()


def test_venv_boundary_guard_attests_exact_project_environment(tmp_path: Path) -> None:
    accepted = subprocess.run(
        (sys.executable, str(VENV_GUARD), "--expected", sys.prefix),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    rejected = subprocess.run(
        (sys.executable, str(VENV_GUARD), "--expected", str(tmp_path / "external-venv")),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert accepted.returncode == 0, accepted.stderr
    assert rejected.returncode != 0
    assert "venv boundary" in rejected.stderr.casefold()

    source = VENV_GUARD.read_text(encoding="utf-8")
    assert "sysconfig" in source
    assert '"purelib"' in source and '"platlib"' in source
    assert "site-packages" in source


def test_venv_boundary_rejects_linklike_pip_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = tmp_path / ".venv"
    scripts = expected / ("Scripts" if sys.platform == "win32" else "bin")
    site_packages = expected / "Lib/site-packages"
    scripts.mkdir(parents=True)
    site_packages.mkdir(parents=True)
    (tmp_path / "base").mkdir()
    (expected / "pyvenv.cfg").write_text(
        "home = test\ninclude-system-site-packages = false\n",
        encoding="utf-8",
    )
    executable = scripts / ("python.exe" if sys.platform == "win32" else "python")
    executable.write_bytes(b"")
    monkeypatch.setattr(verify_venv_boundary, "ROOT", tmp_path)
    monkeypatch.setattr(verify_venv_boundary.sys, "prefix", str(expected))
    monkeypatch.setattr(verify_venv_boundary.sys, "base_prefix", str(tmp_path / "base"))
    monkeypatch.setattr(verify_venv_boundary.sys, "executable", str(executable))
    monkeypatch.setattr(
        verify_venv_boundary.sysconfig,
        "get_paths",
        lambda: {"purelib": str(site_packages), "platlib": str(site_packages)},
    )
    original_is_linklike = verify_venv_boundary._is_linklike
    monkeypatch.setattr(
        verify_venv_boundary,
        "_is_linklike",
        lambda path: path == site_packages or original_is_linklike(path),
    )

    with pytest.raises(RuntimeError, match="site-packages"):
        verify_venv_boundary.attest(str(expected))


def test_classifier_artifact_minimizes_path_evidence() -> None:
    source = inspect.getsource(run_validation_gate.classify_command)

    assert '"paths": decision.normalized_paths' not in source
    assert '"changed_path_count"' in source
    assert '"changed_path_digest"' in source


def test_classifier_receipt_path_cannot_target_an_authoritative_receipt() -> None:
    with pytest.raises(RuntimeError, match="decision receipt"):
        run_validation_gate._validated_decision_receipt_path(
            str(run_validation_gate.DEFAULT_RECEIPT)
        )


def test_classifier_defaults_to_the_separate_decision_receipt_namespace() -> None:
    parser = run_validation_gate.build_parser()

    classifier = parser.parse_args(["classify"])
    authoritative = parser.parse_args(["run"])

    assert Path(classifier.receipt).name == "decision.json"
    assert Path(authoritative.receipt).name == "verification.json"


def test_dependency_provisioning_cli_is_explicit_and_receipt_free() -> None:
    parser = run_validation_gate.build_parser()
    args = parser.parse_args(["provision"])
    source = inspect.getsource(run_validation_gate.provision_command)

    assert args.handler is run_validation_gate.provision_command
    assert "build_verification_receipt" not in source
    assert "_bootstrap_validation_dependencies" in source


def test_authoritative_receipt_parent_is_revalidated_after_stages() -> None:
    source = inspect.getsource(run_validation_gate._run_command_locked)
    last_stage = source.index("for stage in stages")
    publication = source.index("_write_json(receipt_path, receipt, evidence_parent=evidence_parent)")
    validations = [
        match.start()
        for match in re.finditer("_validated_authoritative_receipt_path", source)
    ]

    assert any(last_stage < position < publication for position in validations)
    assert any(position > publication for position in validations)


def test_sop_describes_the_legacy_name_as_a_canonical_receipt_alias() -> None:
    text = TEST_SOP.read_text(encoding="utf-8")

    assert "thin compatibility alias" in text
    assert "canonical forced-G2 runner" in text
    assert "legacy-verification.json" not in text
    assert "--verify-report" not in text


def test_classifier_cli_runs_from_the_supported_repository_root_invocation(tmp_path: Path) -> None:
    receipt = ROOT / ".tmp/validation" / f"pytest-{tmp_path.name}-decision.json"
    receipt.unlink(missing_ok=True)
    try:
        head = _git(ROOT, "rev-parse", "HEAD")
    except subprocess.CalledProcessError:
        pytest.skip("public bootstrap has no committed source revision yet")
    base = run_validation_gate.ZERO_REVISION
    expected = classify_change(
        ChangeRequest(
            base_revision=base,
            head_revision=head,
            changed_paths=run_validation_gate._changed_paths(base, head),
        )
    )
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/run_validation_gate.py",
            "classify",
            "--base",
            base,
            "--head",
            head,
            "--receipt",
            str(receipt),
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == expected.selected_gate
    assert receipt.is_file()
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "2"
    assert payload["base_revision"] == base
    assert payload["source_revision"] == head
    assert payload["decision"]["planes"] == list(expected.planes)
    assert payload["decision"]["reasons"] == list(expected.reasons)
    assert set(payload["decision"]) == {
        "planes",
        "reasons",
        "changed_path_count",
        "changed_path_digest",
    }
    receipt.unlink()


def test_offline_verifier_cli_rejects_unresolvable_receipt_and_replay(tmp_path: Path) -> None:
    source_revision = "b" * 40
    decision = classify_change(
        ChangeRequest(
            base_revision="a" * 40,
            head_revision=source_revision,
            changed_paths=("PUBLIC_RELEASE.md",),
        )
    )
    receipt = build_verification_receipt(
        decision=decision,
        base_revision="a" * 40,
        source_revision=source_revision,
        force_full=False,
        stage_results=(
            StageResult(
                "changed-file-hooks",
                "passed",
                0,
                1,
                ("python", "-m", "pre_commit", "run", "--files", "PUBLIC_RELEASE.md"),
                "2026-07-14T00:00:00Z",
                "2026-07-14T00:00:01Z",
            ),
        ),
        environment={"python": "3.13.9", "platform": "windows-x64"},
        artifact_digests={},
    )
    receipt_path = tmp_path / "verification.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    accepted = subprocess.run(
        (
            sys.executable,
            "scripts/run_validation_gate.py",
            "verify",
            "--receipt",
            str(receipt_path),
            "--source-revision",
            source_revision,
            "--base-revision",
            "a" * 40,
            "--expected-gate",
            "G0",
            "--expected-force-full",
            "false",
            "--expected-ci-context",
            "local",
            "--expected-mode",
            "risk_proportional",
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    replayed = subprocess.run(
        (
            sys.executable,
            "scripts/run_validation_gate.py",
            "verify",
            "--receipt",
            str(receipt_path),
            "--source-revision",
            "c" * 40,
            "--base-revision",
            "a" * 40,
            "--expected-gate",
            "G0",
            "--expected-force-full",
            "false",
            "--expected-ci-context",
            "local",
            "--expected-mode",
            "risk_proportional",
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    receipt["configuration_digests"]["path_mapping"] = "f" * 64
    content = dict(receipt)
    content.pop("receipt_digest")
    receipt["receipt_digest"] = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    forged_configuration = subprocess.run(
        (
            sys.executable,
            "scripts/run_validation_gate.py",
            "verify",
            "--receipt",
            str(receipt_path),
            "--source-revision",
            source_revision,
            "--base-revision",
            "a" * 40,
            "--expected-gate",
            "G0",
            "--expected-force-full",
            "false",
            "--expected-ci-context",
            "local",
            "--expected-mode",
            "risk_proportional",
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert accepted.returncode != 0
    assert "failed closed" in accepted.stderr
    assert replayed.returncode != 0
    assert "failed closed" in replayed.stderr
    assert forged_configuration.returncode != 0
    assert "failed closed" in forged_configuration.stderr


def test_successful_frontend_gate_hashes_only_known_bounded_artifacts(tmp_path: Path) -> None:
    expected = {
        "secure_sdlc_sbom": tmp_path / ".tmp/sbom/redagent-sbom.json",
        "frontend_index": tmp_path / "frontend/dist/index.html",
        "frontend_cli": tmp_path / "frontend/cli-dist/cli/redagent.js",
        "openapi_contract": tmp_path / "frontend/openapi.json",
    }
    for name, path in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name, encoding="utf-8")

    digests = run_validation_gate.collect_artifact_digests(tmp_path, "G2", succeeded=True)

    assert set(digests) == set(expected)
    assert all(len(value) == 64 for value in digests.values())
    assert run_validation_gate.collect_artifact_digests(tmp_path, "G0", succeeded=True) == {}
    assert run_validation_gate.collect_artifact_digests(tmp_path, "G2", succeeded=False) == {}


def test_g2_artifact_collection_rejects_missing_symlink_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    monkeypatch.setattr(
        run_validation_gate,
        "_ARTIFACT_SPECS",
        {"frontend_index": (Path("artifact.bin"), 4)},
    )
    with pytest.raises(RuntimeError, match="missing"):
        run_validation_gate.collect_artifact_digests(tmp_path, "G2", succeeded=True)

    artifact.write_bytes(b"12345")
    with pytest.raises(RuntimeError, match="size limit"):
        run_validation_gate.collect_artifact_digests(tmp_path, "G2", succeeded=True)

    artifact.unlink()
    artifact.write_bytes(b"1234")
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda self: self == artifact or real_is_symlink(self),
    )
    with pytest.raises(RuntimeError, match="symlinked"):
        run_validation_gate.collect_artifact_digests(tmp_path, "G2", succeeded=True)


def test_artifact_stream_budget_rejects_growth_after_safe_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"1234")
    monkeypatch.setattr(
        run_validation_gate,
        "_ARTIFACT_SPECS",
        {"frontend_index": (Path("artifact.bin"), 4)},
    )
    real_fdopen = run_validation_gate.os.fdopen

    def grow_then_open(descriptor: int, *args: object, **kwargs: object):
        with artifact.open("ab") as writer:
            writer.write(b"5")
        return real_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(run_validation_gate.os, "fdopen", grow_then_open)

    with pytest.raises(RuntimeError, match="size limit"):
        run_validation_gate.collect_artifact_digests(tmp_path, "G2", succeeded=True)


def test_artifact_hash_rejects_same_size_in_place_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"1234")
    monkeypatch.setattr(
        run_validation_gate,
        "_ARTIFACT_SPECS",
        {"frontend_index": (Path("artifact.bin"), 4)},
    )
    real_lseek = run_validation_gate.os.lseek

    def rewrite_then_seek(descriptor: int, offset: int, whence: int) -> int:
        result = real_lseek(descriptor, offset, whence)
        artifact.write_bytes(b"5678")
        return result

    monkeypatch.setattr(run_validation_gate.os, "lseek", rewrite_then_seek)

    with pytest.raises(RuntimeError, match="changed while hashing"):
        run_validation_gate.collect_artifact_digests(tmp_path, "G2", succeeded=True)


def test_git_diff_collector_includes_delete_and_both_rename_endpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "compat_118@example.invalid")
    _git(tmp_path, "config", "user.name", "compat_118 Test")
    protected = tmp_path / "config/validation/policy.json"
    renamed = tmp_path / "redagent_platform/runner_service/dispatch.py"
    docs = tmp_path / "docs/guide.md"
    for path in (protected, renamed, docs):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(path.name, encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")

    protected.unlink()
    destination = tmp_path / "docs/renamed-runner.md"
    destination.write_text(renamed.read_text(encoding="utf-8"), encoding="utf-8")
    renamed.unlink()
    docs.write_text("changed", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "mixed delete rename docs")
    head = _git(tmp_path, "rev-parse", "HEAD")
    monkeypatch.setattr(run_validation_gate, "ROOT", tmp_path)

    paths = run_validation_gate._changed_paths(base, head)
    decision = classify_change(
        ChangeRequest(base_revision=base, head_revision=head, changed_paths=paths)
    )

    assert "config/validation/policy.json" in paths
    assert "redagent_platform/runner_service/dispatch.py" in paths
    assert "docs/renamed-runner.md" in paths
    assert decision.selected_gate == "G2"


def test_option_looking_revision_is_rejected_before_git_diff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def forbidden_run(argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        raise AssertionError("git must not receive an option-looking revision")

    monkeypatch.setattr(subprocess, "run", forbidden_run)

    assert run_validation_gate._changed_paths("--output=outside", "b" * 40) == ()
    assert calls == []


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (b"T\0redagent_platform/policy_service/enforcement.py\0", ("redagent_platform/policy_service/enforcement.py",)),
        (b"Q\0docs/guide.md\0", ()),
        (b"M\0\xff\0", ()),
        (b"M\0docs/guide.md\0D\0", ()),
    ],
)
def test_diff_status_parser_includes_type_changes_and_fails_closed_on_ambiguity(
    monkeypatch: pytest.MonkeyPatch,
    output: bytes,
    expected: tuple[str, ...],
) -> None:
    monkeypatch.setattr(
        run_validation_gate,
        "run_bounded_stdout",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output),
    )

    assert run_validation_gate._changed_paths("a" * 40, "b" * 40) == expected


def test_authoritative_request_rejects_path_substitution_and_mismatched_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = "a" * 40
    head = "b" * 40
    args = SimpleNamespace(
        head=head,
        base=base,
        changed_path=["docs/claimed.md"],
        force_full=False,
    )

    def resolve(
        value: str | None,
        fallback: str | None = None,
        *,
        allow_zero: bool = False,
        deadline: float | None = None,
    ) -> str | None:
        del fallback, allow_zero, deadline
        if value is None:
            return head
        return value

    monkeypatch.setattr(run_validation_gate, "_revision", resolve)
    monkeypatch.setattr(
        run_validation_gate,
        "_changed_paths",
        lambda _base, _head, **_kwargs: ("redagent_platform/policy_service/enforcement.py",),
    )
    with pytest.raises(RuntimeError, match="asserted changed paths"):
        run_validation_gate._request(args, authoritative=True)

    args.changed_path = None
    args.head = "c" * 40
    with pytest.raises(RuntimeError, match="checked-out HEAD"):
        run_validation_gate._request(args, authoritative=True)


def test_authoritative_request_preserves_an_explicit_missing_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head = "b" * 40
    observed: list[str | None] = []
    args = SimpleNamespace(
        head=head,
        base="",
        changed_path=None,
        force_full=False,
        legacy_full=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_revision",
        lambda value, fallback=None, *, allow_zero=False, deadline=None: head,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_changed_paths",
        lambda base, source, **_kwargs: observed.append(base) or (),
    )

    request = run_validation_gate._request(args, authoritative=True)

    assert request.base_revision is None
    assert observed == [None]
    assert classify_change(request).selected_gate == "G2"


def test_authoritative_run_rejects_dirty_or_untracked_source_before_any_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda: False)
    args = SimpleNamespace()

    with pytest.raises(RuntimeError, match="clean worktree"):
        run_validation_gate.run_command(args)


def test_authoritative_validation_lease_rejects_a_second_process_and_releases(
    tmp_path: Path,
) -> None:
    from redagent_platform.gate_lease import ValidationLease, ValidationLeaseError

    lock_path = tmp_path / "authoritative.lock"
    ready_path = tmp_path / "owner-ready"
    owner_code = (
        "from pathlib import Path\n"
        "import time\n"
        "from redagent_platform.gate_lease import ValidationLease\n"
        f"with ValidationLease(Path({str(lock_path)!r})):\n"
        f"    Path({str(ready_path)!r}).write_text('ready', encoding='utf-8')\n"
        "    time.sleep(60)\n"
    )
    owner = subprocess.Popen(
        (sys.executable, "-c", owner_code),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready_path.is_file() and owner.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready_path.is_file(), owner.stderr.read()
        with pytest.raises(ValidationLeaseError, match="authoritative validation already active"):
            with ValidationLease(lock_path):
                pass
    finally:
        if owner.poll() is None:
            owner.terminate()
        owner.wait(timeout=5)
        assert owner.returncode not in (None, 0)

    release_deadline = time.monotonic() + 5
    while True:
        try:
            with ValidationLease(lock_path):
                break
        except ValidationLeaseError:
            if time.monotonic() >= release_deadline:
                pytest.fail("OS-backed validation lease did not release after owner termination")
            time.sleep(0.05)


def test_authoritative_runner_refuses_a_held_lease_before_stage_planning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redagent_platform.gate_lease import ValidationLease, ValidationLeaseError

    lock_path = tmp_path / "authoritative.lock"
    monkeypatch.setattr(run_validation_gate, "_assert_reference_docs_only", lambda: None)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: True)
    monkeypatch.setattr(
        run_validation_gate,
        "_validated_authoritative_receipt_path",
        lambda _value, **_kwargs: tmp_path / "receipt.json",
    )
    monkeypatch.setattr(run_validation_gate, "_validation_lease_path", lambda: lock_path)
    monkeypatch.setattr(
        run_validation_gate,
        "_bootstrap_validation_dependencies",
        lambda: (_ for _ in ()).throw(AssertionError("must not bootstrap while leased")),
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not plan while leased")),
    )
    args = SimpleNamespace(legacy_full=False, receipt="ignored", gate=None, force_full=False)

    with ValidationLease(lock_path), pytest.raises(
        ValidationLeaseError,
        match="authoritative validation already active",
    ):
        run_validation_gate.run_command(args)


def test_current_runner_attests_the_project_venv_before_platform_or_evidence_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(run_validation_gate, "_assert_reference_docs_only", lambda: None)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: True)
    monkeypatch.setattr(run_validation_gate, "_validation_lease_path", lambda: tmp_path / "gate.lock")
    monkeypatch.setattr(
        run_validation_gate,
        "_attest_active_project_venv",
        lambda: (_ for _ in ()).throw(RuntimeError("wrong project venv")),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "bind_authoritative_validation_platform",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not bind platform")),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_open_authoritative_evidence_parent",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not create evidence parent")),
    )

    with pytest.raises(RuntimeError, match="wrong project venv"):
        run_validation_gate.run_command(
            SimpleNamespace(legacy_full=False, receipt="ignored", gate=None, force_full=False)
        )
    assert not (tmp_path / ".tmp").exists()


@pytest.mark.parametrize(
    ("selected_gate", "expected_events"),
    (
        ("G0", ["runtime", "run"]),
        ("G1", ["node", "runtime", "run"]),
        ("G2", ["node", "runtime", "bootstrap", "run"]),
    ),
)
def test_authoritative_current_runner_bootstraps_only_g2_inside_the_workspace_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selected_gate: str,
    expected_events: list[str],
) -> None:
    """Selective gates must never silently pay the full dependency-bootstrap cost."""

    events: list[str] = []
    monkeypatch.setattr(run_validation_gate, "_assert_reference_docs_only", lambda: None)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: True)
    monkeypatch.setattr(
        run_validation_gate,
        "_validated_authoritative_receipt_path",
        lambda _value, **_kwargs: tmp_path / "receipt.json",
    )
    monkeypatch.setattr(run_validation_gate, "_validation_lease_path", lambda: tmp_path / "gate.lock")
    monkeypatch.setattr(
        run_validation_gate,
        "_open_authoritative_evidence_parent",
        lambda *_args: nullcontext(None),
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "bind_authoritative_validation_platform",
        lambda *_args: "windows",
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_authoritative_selection",
        lambda _args, **_kwargs: (SimpleNamespace(head_revision="a" * 40), SimpleNamespace(), selected_gate),
        raising=False,
    )
    monkeypatch.setattr(run_validation_gate, "_revision", lambda *_args, **_kwargs: "a" * 40)
    monkeypatch.setattr(
        run_validation_gate,
        "_prepare_authoritative_runtime",
        lambda *_args, **_kwargs: events.append("runtime"),
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_assert_selective_dependencies_ready",
        lambda: None,
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_node_version",
        lambda *_args, **_kwargs: events.append("node") or "v22.0.0",
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_bootstrap_validation_dependencies",
        lambda *_args: events.append("bootstrap"),
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_run_command_locked",
        lambda *_args, **_kwargs: events.append("run") or 0,
    )

    assert run_validation_gate.run_command(
        SimpleNamespace(legacy_full=False, receipt="ignored", gate=None, force_full=False)
    ) == 0
    assert events == expected_events


def test_explicit_dependency_provisioning_bootstraps_under_the_lease_without_running_a_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []
    monkeypatch.setattr(run_validation_gate, "_assert_reference_docs_only", lambda: None)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: True)
    monkeypatch.setattr(run_validation_gate, "_validation_lease_path", lambda: tmp_path / "gate.lock")
    monkeypatch.setattr(
        run_validation_gate,
        "_open_authoritative_evidence_parent",
        lambda *_args: nullcontext(None),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "bind_authoritative_validation_platform",
        lambda *_args: "windows",
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_prepare_authoritative_runtime",
        lambda *_args: events.append("runtime"),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_bootstrap_validation_dependencies",
        lambda _capability, timeout: events.append(("bootstrap", timeout)),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_run_command_locked",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not run a gate")),
    )

    assert run_validation_gate.provision_command(SimpleNamespace()) == 0
    assert events == ["runtime", ("bootstrap", 900)]


@pytest.mark.parametrize(
    ("selected_gate", "expected_events"),
    (
        ("G0", ["ready"]),
        ("G1", ["node", "ready"]),
    ),
)
def test_authoritative_selective_gate_fails_fast_when_project_venv_is_not_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selected_gate: str,
    expected_events: list[str],
) -> None:
    """A selective gate must not hide a long dependency install behind user feedback."""

    events: list[str] = []

    def unavailable() -> None:
        events.append("ready")
        raise RuntimeError("project_venv_dependencies_unavailable; run G2 before G0/G1")

    monkeypatch.setattr(run_validation_gate, "_assert_reference_docs_only", lambda: None)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: True)
    monkeypatch.setattr(
        run_validation_gate,
        "_validated_authoritative_receipt_path",
        lambda _value, **_kwargs: tmp_path / "receipt.json",
    )
    monkeypatch.setattr(run_validation_gate, "_validation_lease_path", lambda: tmp_path / "gate.lock")
    monkeypatch.setattr(
        run_validation_gate,
        "_open_authoritative_evidence_parent",
        lambda *_args: nullcontext(None),
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_authoritative_selection",
        lambda _args, **_kwargs: (SimpleNamespace(head_revision="a" * 40), SimpleNamespace(), selected_gate),
        raising=False,
    )
    monkeypatch.setattr(run_validation_gate, "bind_authoritative_validation_platform", lambda *_args: "windows")
    monkeypatch.setattr(
        run_validation_gate,
        "_node_version",
        lambda *_args, **_kwargs: events.append("node") or "v22.0.0",
    )
    monkeypatch.setattr(run_validation_gate, "_assert_selective_dependencies_ready", unavailable)
    monkeypatch.setattr(
        run_validation_gate,
        "_prepare_authoritative_runtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not mutate runtime before prerequisite check")),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_bootstrap_validation_dependencies",
        lambda *_args: (_ for _ in ()).throw(AssertionError("selective gates must not bootstrap")),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_run_command_locked",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not run after prerequisite failure")),
    )

    with pytest.raises(RuntimeError, match="project_venv_dependencies_unavailable"):
        run_validation_gate.run_command(
            SimpleNamespace(legacy_full=False, receipt="ignored", gate=None, force_full=False)
        )
    assert events == expected_events


def test_selective_dependency_check_names_missing_project_venv_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        run_validation_gate.importlib.util,
        "find_spec",
        lambda module: None if module == "pytest" else object(),
    )

    with pytest.raises(RuntimeError, match=r"project_venv_dependencies_unavailable.*missing: pytest"):
        run_validation_gate._assert_selective_dependencies_ready()


@pytest.mark.parametrize(
    ("selected_gate", "phase"),
    (
        ("G0", "runtime preparation"),
        ("G1", "runtime preparation"),
        ("G2", "dependency bootstrap"),
    ),
)
def test_authoritative_gate_refuses_source_mutation_during_runtime_or_dependency_bootstrap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selected_gate: str,
    phase: str,
) -> None:
    cleanliness = iter((True, True, True, False))
    monkeypatch.setattr(run_validation_gate, "_assert_reference_docs_only", lambda: None)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: next(cleanliness))
    monkeypatch.setattr(
        run_validation_gate,
        "_validated_authoritative_receipt_path",
        lambda _value, **_kwargs: tmp_path / "receipt.json",
    )
    monkeypatch.setattr(run_validation_gate, "_validation_lease_path", lambda: tmp_path / "gate.lock")
    monkeypatch.setattr(
        run_validation_gate,
        "_open_authoritative_evidence_parent",
        lambda *_args: nullcontext(None),
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "bind_authoritative_validation_platform",
        lambda *_args: "windows",
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_authoritative_selection",
        lambda _args, **_kwargs: (SimpleNamespace(head_revision="a" * 40), SimpleNamespace(), selected_gate),
        raising=False,
    )
    monkeypatch.setattr(run_validation_gate, "_revision", lambda *_args, **_kwargs: "a" * 40)
    monkeypatch.setattr(run_validation_gate, "_assert_selective_dependencies_ready", lambda: None, raising=False)
    monkeypatch.setattr(run_validation_gate, "_node_version", lambda *_args, **_kwargs: "v22.0.0", raising=False)
    monkeypatch.setattr(
        run_validation_gate,
        "_prepare_authoritative_runtime",
        lambda *_args, **_kwargs: None,
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_bootstrap_validation_dependencies",
        lambda *_args: None,
        raising=False,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_run_command_locked",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not run after drift")),
    )

    with pytest.raises(RuntimeError, match=phase):
        run_validation_gate.run_command(
            SimpleNamespace(legacy_full=False, receipt="ignored", gate=None, force_full=False)
        )


def test_authoritative_g2_never_bootstraps_after_runtime_preparation_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    cleanliness = iter((True, True, False))
    monkeypatch.setattr(run_validation_gate, "_assert_reference_docs_only", lambda: None)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: next(cleanliness))
    monkeypatch.setattr(
        run_validation_gate,
        "_validated_authoritative_receipt_path",
        lambda _value, **_kwargs: tmp_path / "receipt.json",
    )
    monkeypatch.setattr(run_validation_gate, "_validation_lease_path", lambda: tmp_path / "gate.lock")
    monkeypatch.setattr(
        run_validation_gate,
        "_open_authoritative_evidence_parent",
        lambda *_args: nullcontext(None),
    )
    monkeypatch.setattr(run_validation_gate, "bind_authoritative_validation_platform", lambda *_args: "windows")
    monkeypatch.setattr(run_validation_gate, "_attest_active_project_venv", lambda: None)
    monkeypatch.setattr(
        run_validation_gate,
        "_authoritative_selection",
        lambda _args, **_kwargs: (SimpleNamespace(head_revision="a" * 40), SimpleNamespace(), "G2"),
    )
    monkeypatch.setattr(run_validation_gate, "_revision", lambda *_args, **_kwargs: "a" * 40)
    monkeypatch.setattr(
        run_validation_gate,
        "_prepare_authoritative_runtime",
        lambda *_args, **_kwargs: events.append("runtime"),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_bootstrap_validation_dependencies",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not bootstrap after runtime drift")),
    )

    with pytest.raises(RuntimeError, match="runtime preparation"):
        run_validation_gate.run_command(
            SimpleNamespace(legacy_full=False, receipt="ignored", gate=None, force_full=False)
        )
    assert events == ["runtime"]


def test_classifier_remains_usable_while_an_authoritative_full_gate_holds_its_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redagent_platform.gate_lease import ValidationLease

    lock_path = tmp_path / "authoritative.lock"
    monkeypatch.setattr(run_validation_gate, "_validated_decision_receipt_path", lambda _value: tmp_path / "receipt.json")
    monkeypatch.setattr(
        run_validation_gate,
        "_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("classifier reached planning")),
    )
    args = SimpleNamespace(receipt="ignored", github_output=None)

    with ValidationLease(lock_path), pytest.raises(RuntimeError, match="classifier reached planning"):
        run_validation_gate.classify_command(args)


def test_classifier_runs_while_the_real_workspace_authoritative_lease_is_held(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nested classifier calls must not reacquire the authoritative lease coordinate."""

    from redagent_platform.gate_lease import ValidationLease, authoritative_validation_lease_path

    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "compat_118@example.invalid")
    _git(tmp_path, "config", "user.name", "compat_118 Test")
    (tmp_path / ".gitignore").write_text(".tmp/\n", encoding="utf-8")
    (tmp_path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git(tmp_path, "add", ".gitignore", "tracked.txt")
    _git(tmp_path, "commit", "-m", "base")
    decision_path = tmp_path / ".tmp" / "validation" / "lease-test-decision.json"
    decision_path.parent.mkdir(parents=True)
    authoritative_receipt = tmp_path / ".tmp" / "validation" / "verification.json"

    monkeypatch.setattr(run_validation_gate, "ROOT", tmp_path)
    monkeypatch.setattr(
        run_validation_gate,
        "_request",
        lambda _args: SimpleNamespace(base_revision="a" * 40, head_revision="b" * 40),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "classify_change",
        lambda _request: SimpleNamespace(
            selected_gate="G2",
            decision_digest="c" * 64,
            planes=("validator_test",),
            reasons=("test",),
        ),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "decision_evidence_payload",
        lambda _decision: {"changed_path_count": 1, "changed_path_digest": "d" * 64},
    )
    args = SimpleNamespace(receipt=str(decision_path), github_output=None)

    with ValidationLease(authoritative_validation_lease_path(tmp_path)):
        assert run_validation_gate.classify_command(args) == 0

    assert decision_path.is_file()
    assert not authoritative_receipt.exists()


def test_authoritative_runner_uses_the_canonical_lease_path_constructor() -> None:
    from redagent_platform.gate_lease import authoritative_validation_lease_path

    expected = ROOT / ".tmp" / "validation" / "authoritative-validation.lock"

    assert authoritative_validation_lease_path(ROOT) == expected
    assert "validated_authoritative_validation_lease_path(ROOT)" in inspect.getsource(
        run_validation_gate._validation_lease_path
    )


def test_worktree_cleanliness_rejects_nonignored_untracked_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "compat_118@example.invalid")
    _git(tmp_path, "config", "user.name", "compat_118 Test")
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("tracked", encoding="utf-8")
    _git(tmp_path, "add", "tracked.txt")
    _git(tmp_path, "commit", "-m", "base")
    monkeypatch.setattr(run_validation_gate, "ROOT", tmp_path)

    assert run_validation_gate._worktree_is_clean()
    (tmp_path / "conftest.py").write_text("pytest_plugins = []", encoding="utf-8")
    assert not run_validation_gate._worktree_is_clean()


def test_authoritative_runner_checks_source_before_and_after_stages() -> None:
    source = inspect.getsource(run_validation_gate._run_command_locked)

    assert source.count("_worktree_is_clean(deadline=deadline)") >= 2
    assert "authoritative source changed during validation" in source
    assert "_validated_authoritative_receipt_path" in source
    assert source.index("_write_json") < source.rindex("_worktree_is_clean(deadline=deadline)")


def test_authoritative_runner_binds_configuration_digest_to_the_active_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Receipt construction must not start an unbounded configuration hash."""

    request = ChangeRequest(
        base_revision="a" * 40,
        head_revision="b" * 40,
        changed_paths=("docs/guide.md",),
        ci_context="local",
    )
    decision = classify_change(request)
    deadline = 9_999_999_999.0
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        run_validation_gate,
        "build_default_registry",
        lambda _root: SimpleNamespace(plan_ids=lambda _stage_ids: ()),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_worktree_is_clean",
        lambda *, deadline=None: True,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_revision",
        lambda _value, _fallback=None, *, allow_zero=False, deadline=None: request.head_revision,
    )

    def configuration_digests(*, deadline_monotonic: float | None = None) -> dict[str, str]:
        observed["configuration_deadline"] = deadline_monotonic
        return {"receipt_verifier": "a" * 64}

    monkeypatch.setattr(
        run_validation_gate,
        "current_configuration_digests",
        configuration_digests,
    )
    monkeypatch.setattr(
        run_validation_gate,
        "collect_artifact_digests",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        run_validation_gate,
        "build_verification_receipt",
        lambda **kwargs: observed.update(
            {"configuration": kwargs.get("configuration_digests")}
        )
        or {},
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_validated_authoritative_receipt_path",
        lambda *_args, **_kwargs: tmp_path / "verification.json",
    )
    monkeypatch.setattr(run_validation_gate, "_write_json", lambda *_args, **_kwargs: None)

    args = SimpleNamespace(receipt=str(tmp_path / "verification.json"))

    assert run_validation_gate._run_command_locked(
        args,
        tmp_path / "verification.json",
        request=request,
        decision=decision,
        selected_gate="G0",
        deadline=deadline,
    ) == 0
    assert observed == {
        "configuration_deadline": deadline,
        "configuration": {"receipt_verifier": "a" * 64},
    }


def test_verifier_uses_one_bounded_descriptor_read_instead_of_stat_then_read_text() -> None:
    source = inspect.getsource(run_validation_gate.verify_command)

    assert "_load_bounded_json" in source
    assert ".read_text(" not in source


def test_test_sop_documents_the_complete_authoritative_verifier_contract() -> None:
    text = TEST_SOP.read_text(encoding="utf-8")

    for argument in (
        "--source-revision",
        "--base-revision",
        "--expected-gate",
        "--expected-force-full",
        "--expected-ci-context",
        "--expected-mode",
    ):
        assert argument in text


def test_authoritative_verifier_supports_zero_and_missing_base_claims() -> None:
    assert run_validation_gate._revision(run_validation_gate.ZERO_REVISION, allow_zero=True) == (
        run_validation_gate.ZERO_REVISION
    )
    source = inspect.getsource(run_validation_gate.verify_command)
    assert "allow_zero=True" in source
    assert 'casefold() == "none"' in source


@pytest.mark.parametrize(
    ("base_argument", "expected_base"),
    [("none", None), (run_validation_gate.ZERO_REVISION, run_validation_gate.ZERO_REVISION)],
)
def test_authoritative_verifier_binds_zero_and_missing_base_claims(
    base_argument: str,
    expected_base: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head = "b" * 40
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        run_validation_gate,
        "_load_bounded_json",
        lambda _path, **_kwargs: {"aggregate_result": "passed"},
    )
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: True)
    monkeypatch.setattr(
        run_validation_gate,
        "_revision",
        lambda value, fallback=None, *, allow_zero=False, deadline=None: (
            run_validation_gate.ZERO_REVISION
            if value == run_validation_gate.ZERO_REVISION and allow_zero
            else head
        ),
    )
    monkeypatch.setattr(
        run_validation_gate,
        "_changed_paths",
        lambda base, source, *, deadline=None: (),
    )
    monkeypatch.setattr(run_validation_gate, "collect_artifact_digests", lambda *args, **kwargs: {})
    monkeypatch.setattr(run_validation_gate, "current_configuration_digests", lambda **_kwargs: {})
    monkeypatch.setattr(run_validation_gate, "_environment", lambda _node: {})
    monkeypatch.setattr(
        run_validation_gate,
        "verify_verification_receipt",
        lambda payload, **kwargs: observed.update(kwargs),
    )
    args = SimpleNamespace(
        receipt="ignored.json",
        source_revision=head,
        base_revision=base_argument,
        expected_gate="G0",
        expected_force_full="false",
        expected_ci_context="local",
        expected_mode="risk_proportional",
    )

    assert run_validation_gate.verify_command(args) == 0
    assert observed["expected_base_revision"] == expected_base
    assert observed["expected_changed_paths"] == ()


def test_receipt_json_loader_rejects_duplicate_keys_and_nonstandard_values() -> None:
    with pytest.raises(RuntimeError, match="duplicate JSON key"):
        run_validation_gate._closed_json_object([("source_revision", "a"), ("source_revision", "b")])
    with pytest.raises(RuntimeError, match="non-standard JSON"):
        run_validation_gate._reject_json_constant("NaN")


def test_benchmark_entrypoint_is_explicitly_non_authoritative_and_receipt_free() -> None:
    args = run_validation_gate.build_parser().parse_args(
        ["benchmark", "--gate", "G0", "--changed-path", "PUBLIC_RELEASE.md"]
    )
    source = inspect.getsource(run_validation_gate.benchmark_command)

    assert args.handler is run_validation_gate.benchmark_command
    assert args.gate == "G0"
    assert "NON_AUTHORITATIVE_BENCHMARK" in source
    assert "build_verification_receipt" not in source
    assert "G2" in source


@pytest.mark.parametrize("selected", ["G0", "G1", "G2"])
def test_aggregate_requires_exactly_one_selected_success_and_two_skips(selected: str) -> None:
    names = ("G0", "G1", "G2")
    valid = {name: ("success" if name == selected else "skipped") for name in names}
    args = type(
        "Args",
        (),
        {
            "selected": selected,
            "classify_result": "success",
            "g0_result": valid["G0"],
            "g1_result": valid["G1"],
            "g2_result": valid["G2"],
        },
    )()
    assert run_validation_gate.aggregate_command(args) == 0

    for non_selected in (name for name in names if name != selected):
        invalid = dict(valid)
        invalid[non_selected] = "failure"
        bad_args = type(
            "Args",
            (),
            {
                "selected": selected,
                "classify_result": "success",
                "g0_result": invalid["G0"],
                "g1_result": invalid["G1"],
                "g2_result": invalid["G2"],
            },
        )()
        assert run_validation_gate.aggregate_command(bad_args) == 1


def test_gate_git_preflight_is_bounded_and_fails_closed_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def timed_out(command: tuple[str, ...], **kwargs: object) -> object:
        calls.append((command, kwargs))
        return None

    monkeypatch.setattr(run_validation_gate, "run_bounded_stdout", timed_out)

    for function in (
        lambda: run_validation_gate._revision(None, "HEAD"),
        lambda: run_validation_gate._changed_paths("a" * 40, "b" * 40),
        run_validation_gate._worktree_is_clean,
    ):
        assert function() in {None, (), False}

    assert calls
    for command, kwargs in calls:
        assert command[:3] == ("git", "--no-pager", "--no-replace-objects")
        assert kwargs["timeout_seconds"] == run_validation_gate._GIT_TIMEOUT_SECONDS
        assert kwargs["max_output_bytes"] == run_validation_gate._MAX_GIT_OUTPUT_BYTES
        environment = kwargs["environment"]
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GIT_CONFIG_GLOBAL"] == os.devnull


def test_validation_gate_git_queries_disable_helper_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repository-local Git settings must not enable host helper programs."""

    observed: dict[str, object] = {}

    def completed(command: tuple[str, ...], **kwargs: object) -> object:
        observed["command"] = command
        observed.update(kwargs)
        return SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(run_validation_gate, "run_bounded_stdout", completed)

    assert run_validation_gate._git("diff", "--name-only") is not None
    assert observed["command"] == (
        "git",
        "--no-pager",
        "--no-replace-objects",
        "-c",
        f"safe.directory={ROOT.absolute()}",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
        "-c",
        "credential.helper=",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
    )


def test_node_preflight_is_bounded_and_fails_closed_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def timed_out(command: tuple[str, ...], **kwargs: object) -> object:
        observed["command"] = command
        observed.update(kwargs)
        raise subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(run_validation_gate.subprocess, "run", timed_out)

    with pytest.raises(RuntimeError, match="Node.js 18\\+"):
        run_validation_gate._node_version()

    assert observed["command"] == ("node", "-v")
    assert observed["timeout"] == run_validation_gate._TOOL_PREFLIGHT_TIMEOUT_SECONDS
