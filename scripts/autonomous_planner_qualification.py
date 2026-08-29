"""Run or offline-verify the fixed bounded planner qualification ceremony."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.validation.autonomous_planner_qualification import (  # noqa: E402
    MAX_BUNDLE_BYTES,
    MAX_PROJECTION_BYTES,
    QualificationError,
    QualificationMatrix,
    StageSpec,
    build_bundle,
    build_event_chain,
    canonical_bytes,
    compute_disposition,
    create_stage_result,
    decode_json_bytes,
    file_sha256,
    is_link_or_reparse,
    load_json_file,
    load_matrix,
    load_projection,
    parse_pins,
    verify_bundle,
    verify_preflight,
)


MATRIX_PATH = ROOT / "config/validation/autonomous-planner-qualification-v1.json"
OUTPUT_ROOT = ROOT / ".tmp/autonomous-planner-qualification"
RUNTIME_ROOT = OUTPUT_ROOT / "runtime"
STAGE_LOG_ROOT = OUTPUT_ROOT / "stages"
PROJECTION_PATH = OUTPUT_ROOT / "execution-projection.json"
PINS_PATH = OUTPUT_ROOT / "verification-pins.json"
PREFLIGHT_PATH = OUTPUT_ROOT / "preflight.json"
STAGE_RESULTS_PATH = OUTPUT_ROOT / "stage-results.json"
EVENTS_PATH = OUTPUT_ROOT / "events.jsonl"
BUNDLE_PATH = OUTPUT_ROOT / "qualification-bundle.json"
FORCED_G2_SOURCE = ROOT / ".tmp/validation/verification.json"
FORCED_G2_RETAINED = OUTPUT_ROOT / "forced-g2-verification.json"
MAX_STAGE_LOG_BYTES = 32 * 1024 * 1024

PYTEST_AUTHORITY_SELECTORS = (
    "tests/unit/test_autonomous_planner_qualification.py",
    "tests/unit/test_campaign_authority_envelope.py",
    "tests/unit/test_campaign_planning_contracts.py",
    "tests/unit/test_campaign_planning_serde.py",
    "tests/unit/test_campaign_planning_validator_separation.py",
    "tests/unit/test_campaign_attack_path_planner.py",
    "tests/unit/test_campaign_plan_admission.py",
    "tests/unit/test_campaign_dag_execution.py",
    "tests/unit/test_campaign_dag_effect_authority.py",
    "tests/unit/test_trusted_observations.py",
    "tests/unit/test_campaign_replanning.py",
    "tests/unit/test_planner_evidence.py",
    "tests/unit/test_attack_flow_export.py",
    "tests/unit/test_campaign_operations_api.py",
    "tests/unit/test_campaign_operations_projection.py",
    "tests/integration/test_campaign_dag_owned_loopback.py",
)


def _tool(name: str) -> str:
    candidate = shutil.which(name)
    if candidate is None and os.name == "nt":
        candidate = shutil.which(f"{name}.cmd") or shutil.which(f"{name}.exe")
    if candidate is None:
        raise QualificationError(f"required fixed tool unavailable: {name}")
    return candidate


def _runner_commands(runner_id: str, projection_commit: str, projection_parent: str) -> tuple[tuple[str, ...], ...]:
    python = str(Path(sys.executable).resolve())
    if runner_id == "pytest-authority-to-terminal":
        return ((python, "-m", "pytest", *PYTEST_AUTHORITY_SELECTORS),)
    if runner_id == "vitest-operations-component":
        return (
            (
                _tool("npm"),
                "run",
                "test:unit",
                "--",
                "frontend/src/features/campaigns/CampaignCoreFeature.test.tsx",
            ),
        )
    if runner_id == "playwright-operations-e2e":
        return (
            (
                _tool("npx"),
                "playwright",
                "test",
                "tests/e2e/compat_124-campaign-core.spec.js",
                "--grep",
                "R162|standing Tier-1 flow",
            ),
        )
    if runner_id == "windows-full-gate":
        return (
            (_tool("powershell"), "-NoProfile", "-File", "scripts/run_full_tests_windows.ps1"),
            (
                python,
                "scripts/run_validation_gate.py",
                "verify",
                "--receipt",
                ".tmp/validation/verification.json",
                "--source-revision",
                projection_commit,
                "--base-revision",
                projection_parent,
                "--expected-gate",
                "G2",
                "--expected-force-full",
                "true",
                "--expected-ci-context",
                "local",
                "--expected-mode",
                "risk_proportional",
            ),
        )
    if runner_id == "owned-runtime-cleanup":
        return (
            (python, "scripts/openbao_conformance.py", "reset"),
            (python, "scripts/opa_conformance.py", "reset"),
            (
                python,
                "scripts/redagent_local_stack.py",
                "reset",
                "--confirm-local-reset",
                "--json",
            ),
        )
    if runner_id == "pytest-offline-lineage":
        return ((python, "-m", "pytest", "tests/integration/test_planner_evidence_offline.py"),)
    if runner_id == "internal-residual-safety":
        return ()
    raise QualificationError("unknown qualification runner id")


def _assert_fixed_path(path: Path, expected: Path, *, must_exist: bool, directory: bool = False) -> None:
    if path.absolute() != expected.absolute():
        raise QualificationError("qualification path is not the fixed repository path")
    root = ROOT.absolute()
    try:
        relative = path.absolute().relative_to(root)
    except ValueError as exc:
        raise QualificationError("qualification path escaped the repository root") from exc
    current = root
    for component in relative.parts:
        current /= component
        if current.exists() and is_link_or_reparse(current):
            raise QualificationError("qualification path traverses a link or reparse point")
    if must_exist:
        if directory and not path.is_dir():
            raise QualificationError("qualification fixed directory is unavailable")
        if not directory and not path.is_file():
            raise QualificationError("qualification fixed file is unavailable")
    if path.exists() and directory != path.is_dir():
        raise QualificationError("qualification fixed path type invalid")


def _atomic_write(path: Path, payload: bytes) -> None:
    _assert_fixed_path(path, path, must_exist=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    _assert_fixed_path(path.parent, path.parent, must_exist=True, directory=True)
    # CRITICAL: every formal artifact is immutable once named; replacement would erase the first
    # attempt's evidence and could splice a later run into the retained ceremony.
    if path.exists():
        raise QualificationError("qualification output already exists")
    temporary = path.with_name(f"{path.name}.tmp")
    _assert_fixed_path(temporary, temporary, must_exist=False)
    if temporary.exists():
        raise QualificationError("qualification temporary output already exists")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary.is_file() and not is_link_or_reparse(temporary):
            temporary.unlink()
        raise


def _json_bytes(value: object) -> bytes:
    return canonical_bytes(value) + b"\n"


def _read_text_bounded(path: Path) -> str:
    if not path.is_file() or is_link_or_reparse(path) or path.stat().st_size > MAX_STAGE_LOG_BYTES:
        raise QualificationError("stage log byte contract invalid")
    return path.read_bytes().decode("utf-8", errors="replace")


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        (_tool("git"), *arguments),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"},
    )
    if completed.returncode != 0:
        raise QualificationError("fixed Git readback failed")
    return completed.stdout.strip()


def _source_digests(matrix: QualificationMatrix) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in matrix.source_paths:
        path = ROOT / Path(relative)
        _assert_fixed_path(path, ROOT / Path(relative), must_exist=True)
        result[relative] = file_sha256(path)
    return result


def _environment() -> dict[str, str]:
    node = subprocess.run(
        (_tool("node"), "--version"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if node.returncode != 0:
        raise QualificationError("fixed Node version readback failed")
    return {
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "node_version": node.stdout.strip().removeprefix("v"),
    }


def _observe_preflight(matrix: QualificationMatrix, projection) -> dict[str, object]:
    return verify_preflight(
        matrix,
        projection,
        observed_commit=_git("rev-parse", "HEAD"),
        observed_tree=_git("rev-parse", "HEAD^{tree}"),
        observed_parent=_git("rev-parse", "HEAD^"),
        observed_branch=_git("branch", "--show-current"),
        worktree_clean=_git("status", "--porcelain", "--untracked-files=all") == "",
        observed_source_sha256=_source_digests(matrix),
        observed_environment=_environment(),
    )


def _load_inputs():
    _assert_fixed_path(
        MATRIX_PATH, ROOT / "config/validation/autonomous-planner-qualification-v1.json", must_exist=True
    )
    _assert_fixed_path(
        PROJECTION_PATH, ROOT / ".tmp/autonomous-planner-qualification/execution-projection.json", must_exist=True
    )
    _assert_fixed_path(
        PINS_PATH, ROOT / ".tmp/autonomous-planner-qualification/verification-pins.json", must_exist=True
    )
    matrix = load_matrix(MATRIX_PATH)
    projection = load_projection(PROJECTION_PATH, matrix)
    pins = parse_pins(load_json_file(PINS_PATH, label="verification pins", maximum_bytes=MAX_PROJECTION_BYTES))
    bindings = {
        "matrix_sha256": matrix.matrix_sha256,
        "projection_sha256": projection.projection_sha256,
        "candidate_commit": projection.candidate_commit,
        "candidate_tree": projection.candidate_tree,
        "private_manifest_sha256": projection.private_manifest_sha256,
        "trust_anchor_sha256": projection.trust_anchor_sha256,
    }
    if any(pins[key] != value for key, value in bindings.items()):
        raise QualificationError("verification pins do not bind the frozen projection")
    return matrix, projection, pins


def preflight_command() -> int:
    matrix, projection, _pins = _load_inputs()
    preflight = _observe_preflight(matrix, projection)
    _atomic_write(PREFLIGHT_PATH, _json_bytes(preflight))
    print(json.dumps(preflight, sort_keys=True))
    return 0


def _parse_counts(stage: StageSpec, text: str, receipt: object | None) -> tuple[int | None, int]:
    if stage.result_kind == "forced-g2":
        if not isinstance(receipt, Mapping) or not isinstance(receipt.get("stages"), list):
            raise QualificationError("forced-G2 receipt stage inventory invalid")
        stages = receipt["stages"]
        passed = sum(1 for value in stages if isinstance(value, Mapping) and value.get("status") == "passed")
        return passed, 0
    if stage.result_kind == "cleanup":
        return text.count('"ok": true'), 0
    if stage.result_kind == "residual":
        value = decode_json_bytes(text.encode("utf-8"), label="residual report", maximum_bytes=1024 * 1024)
        if not isinstance(value, Mapping) or not isinstance(value.get("passed_check_count"), int):
            raise QualificationError("residual report invalid")
        return value["passed_check_count"], 0
    patterns = {
        "pytest": re.compile(r"(?m)(\d+) passed(?:, (\d+) skipped)?"),
        "vitest": re.compile(r"(?m)Tests\s+(\d+) passed(?:\s+\|\s+(\d+) skipped)?"),
        "playwright": re.compile(r"(?m)(\d+) passed"),
    }
    match = patterns[stage.result_kind].search(text)
    if match is None:
        raise QualificationError("stage success-count evidence missing")
    return int(match.group(1)), int(match.group(2) or 0)


def _stage_log_paths(stage: StageSpec) -> tuple[Path, Path]:
    return (
        STAGE_LOG_ROOT / f"{stage.stage_id}.stdout.log",
        STAGE_LOG_ROOT / f"{stage.stage_id}.stderr.log",
    )


def _run_processes(
    commands: Sequence[Sequence[str]],
    stage: StageSpec,
    formal_environment: Mapping[str, str],
) -> tuple[int, bool]:
    stdout_path, stderr_path = _stage_log_paths(stage)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    if stdout_path.exists() or stderr_path.exists():
        raise QualificationError("formal stage log already exists")
    completed_count = 0
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        for command in commands:
            child_environment = {**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1"}
            # CRITICAL: ambient REDAGENT_* values can redirect the owned-lab topology;
            # every formal child must receive only the source-pinned projection values.
            for name in tuple(child_environment):
                if name.upper().startswith("REDAGENT_"):
                    del child_environment[name]
            child_environment.update(formal_environment)
            try:
                completed = subprocess.run(
                    tuple(command),
                    cwd=ROOT,
                    check=False,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=stage.timeout_seconds,
                    env=child_environment,
                )
            except (OSError, subprocess.TimeoutExpired):
                return completed_count, True
            if completed.returncode != 0:
                return completed_count, False
            completed_count += 1
        stdout.flush()
        stderr.flush()
        os.fsync(stdout.fileno())
        os.fsync(stderr.fileno())
    return completed_count, False


def _remove_item_runtime_paths(matrix: QualificationMatrix) -> None:
    for relative in matrix.cleanup_paths:
        path = ROOT / Path(relative)
        expected = ROOT / Path(relative)
        _assert_fixed_path(path, expected, must_exist=False, directory=True)
        if not path.exists():
            continue
        _assert_fixed_path(path, expected, must_exist=True, directory=True)
        shutil.rmtree(path)
        if path.exists():
            raise QualificationError("item-owned qualification runtime cleanup incomplete")


def _port_closed(port: int) -> bool:
    for host, family in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)):
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.25)
            if probe.connect_ex((host, port)) == 0:
                return False
    return True


def _residual_report(matrix: QualificationMatrix, projection) -> dict[str, object]:
    checks: dict[str, bool] = {
        "candidate_commit_unchanged": _git("rev-parse", "HEAD") == projection.candidate_commit,
        "candidate_tree_unchanged": _git("rev-parse", "HEAD^{tree}") == projection.candidate_tree,
        "source_inventory_unchanged": _source_digests(matrix) == dict(projection.source_sha256),
        "tracked_worktree_clean": _git("status", "--porcelain", "--untracked-files=all") == "",
        "item_runtime_paths_removed": all(not (ROOT / Path(path)).exists() for path in matrix.cleanup_paths),
        "declared_ports_and_processes_absent": False,
    }
    docker = subprocess.run(
        (_tool("docker"), "ps", "--format", "{{.Names}}"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    names = docker.stdout.lower().splitlines() if docker.returncode == 0 else []
    processes_absent = docker.returncode == 0 and all(
        not any(marker in name for name in names) for marker in projection.residual_process_markers
    )
    ports_closed = all(_port_closed(port) for port in projection.residual_ports)
    checks["declared_ports_and_processes_absent"] = processes_absent and ports_closed
    return {
        "schema_version": "redagent.autonomous-planner-qualification-residual/v1",
        "checks": checks,
        "passed_check_count": sum(checks.values()),
        "required_check_count": len(checks),
        "unapproved_assessment_contacts": 0,
        "cleanup_complete": all(checks.values()),
    }


def _execute_stage(stage: StageSpec, matrix: QualificationMatrix, projection) -> dict[str, object]:
    stdout_path, stderr_path = _stage_log_paths(stage)
    commands = _runner_commands(stage.runner_id, projection.candidate_commit, projection.candidate_parent_commit)
    launch_aborted = False
    completed_count = 0
    if stage.result_kind == "residual":
        report = _residual_report(matrix, projection)
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(stdout_path, _json_bytes(report))
        _atomic_write(stderr_path, b"")
    else:
        completed_count, launch_aborted = _run_processes(commands, stage, projection.formal_environment)
        if stage.result_kind == "cleanup" and not launch_aborted and completed_count == len(commands):
            _remove_item_runtime_paths(matrix)

    stdout_text = _read_text_bounded(stdout_path)
    stderr_text = _read_text_bounded(stderr_path)
    receipt: object | None = None
    artifacts: dict[str, str] = {}
    if stage.result_kind == "forced-g2" and FORCED_G2_SOURCE.is_file() and not is_link_or_reparse(FORCED_G2_SOURCE):
        receipt_bytes = FORCED_G2_SOURCE.read_bytes()
        receipt = decode_json_bytes(receipt_bytes, label="forced-G2 receipt", maximum_bytes=MAX_BUNDLE_BYTES)
        _atomic_write(FORCED_G2_RETAINED, receipt_bytes)
        artifacts["forced-g2-verification.json"] = hashlib.sha256(receipt_bytes).hexdigest()
    try:
        passed_count, skipped_count = _parse_counts(stage, stdout_text + "\n" + stderr_text, receipt)
        count_valid = stage.expected_pass_count is None or passed_count == stage.expected_pass_count
        count_valid = count_valid and skipped_count == stage.allowed_skip_count
    except QualificationError:
        passed_count, skipped_count, count_valid = None, 0, False

    exit_ok = completed_count == len(commands) if commands else True
    cleanup_complete = exit_ok and count_valid
    if launch_aborted:
        status = "aborted"
        detail = "fixed_runner_launch_timeout_or_environment_failure"
        exit_code = None
    elif exit_ok and count_valid:
        status = "passed"
        detail = "all_fixed_runner_contracts_passed"
        exit_code = 0
    else:
        status = "failed"
        detail = "mandatory_fixed_runner_or_result_contract_failed"
        exit_code = 1
    return create_stage_result(
        stage,
        status=status,
        exit_code=exit_code,
        passed_count=passed_count,
        skipped_count=skipped_count,
        stdout_sha256=file_sha256(stdout_path),
        stderr_sha256=file_sha256(stderr_path),
        artifact_sha256=artifacts,
        unapproved_assessment_contacts=0,
        cleanup_complete=cleanup_complete,
        detail=detail,
    )


def _aborted_stage_result(stage: StageSpec, detail: str) -> dict[str, object]:
    stdout_path, stderr_path = _stage_log_paths(stage)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    if not stdout_path.exists():
        _atomic_write(stdout_path, b"")
    if not stderr_path.exists():
        _atomic_write(stderr_path, (detail + "\n").encode("utf-8"))
    return create_stage_result(
        stage,
        status="aborted",
        exit_code=None,
        passed_count=None,
        skipped_count=0,
        stdout_sha256=file_sha256(stdout_path),
        stderr_sha256=file_sha256(stderr_path),
        artifact_sha256={},
        unapproved_assessment_contacts=0,
        cleanup_complete=False,
        detail=detail,
    )


def _artifact_payloads(matrix: QualificationMatrix) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for relative in matrix.retained_artifacts:
        path = OUTPUT_ROOT / Path(relative)
        if path.is_file() and not is_link_or_reparse(path):
            payloads[relative] = path.read_bytes()
    return payloads


def run_command() -> int:
    matrix, projection, _pins = _load_inputs()
    formal_outputs = (
        STAGE_LOG_ROOT,
        STAGE_RESULTS_PATH,
        EVENTS_PATH,
        BUNDLE_PATH,
        FORCED_G2_RETAINED,
    )
    if any(path.exists() for path in formal_outputs):
        raise QualificationError("formal attempt output already exists; retries are forbidden")
    observed_preflight = _observe_preflight(matrix, projection)
    retained_preflight = load_json_file(PREFLIGHT_PATH, label="retained preflight", maximum_bytes=MAX_PROJECTION_BYTES)
    if retained_preflight != observed_preflight:
        raise QualificationError("retained preflight is absent or stale")

    stage_results: list[dict[str, object]] = []
    protocol_drift = False
    for index, stage in enumerate(matrix.stages):
        if protocol_drift:
            result = _aborted_stage_result(stage, "not_run_after_formal_protocol_drift")
        else:
            try:
                result = _execute_stage(stage, matrix, projection)
            except (QualificationError, OSError, subprocess.SubprocessError):
                # IMPORTANT: after formal start, fixed-tool or environment failure is evidence,
                # not an unrecorded CLI crash; preserve it and abort every remaining stage.
                result = _aborted_stage_result(
                    stage,
                    "fixed_runner_contract_or_environment_unavailable",
                )
                protocol_drift = True
            if result["status"] == "aborted":
                protocol_drift = True
            try:
                if _observe_preflight(matrix, projection) != observed_preflight:
                    raise QualificationError("preflight digest changed")
            except QualificationError:
                protocol_drift = True
                result = _aborted_stage_result(
                    stage,
                    "candidate_source_or_environment_drift_after_stage",
                )
        stage_results.append(result)
        if protocol_drift:
            for pending in matrix.stages[index + 1 :]:
                stage_results.append(_aborted_stage_result(pending, "not_run_after_formal_protocol_drift"))
            break

    _atomic_write(STAGE_RESULTS_PATH, _json_bytes(stage_results))
    provisional_payloads = _artifact_payloads(matrix)
    expected_without_events = set(matrix.retained_artifacts) - {"events.jsonl"}
    artifacts_complete = set(provisional_payloads) == expected_without_events
    result = compute_disposition(
        matrix,
        stage_results,
        protocol_drift=protocol_drift,
        artifacts_complete=artifacts_complete,
    )
    event_inputs: list[tuple[str, Mapping[str, object]]] = [
        ("preflight_passed", {"preflight_sha256": observed_preflight["preflight_sha256"]}),
        ("attempt_started", {"attempt_id": projection.attempt_id}),
    ]
    event_inputs.extend(
        ("stage_completed", {"stage_id": stage.stage_id, "stage_result_sha256": stage_result["stage_result_sha256"]})
        for stage, stage_result in zip(matrix.stages, stage_results, strict=True)
    )
    event_inputs.append(("attempt_terminal", {"result_sha256": result["result_sha256"]}))
    events = build_event_chain(event_inputs)
    _atomic_write(EVENTS_PATH, b"".join(canonical_bytes(event) + b"\n" for event in events))

    artifact_payloads = _artifact_payloads(matrix)
    artifact_digests = {
        relative: hashlib.sha256(payload).hexdigest() for relative, payload in artifact_payloads.items()
    }
    bundle = build_bundle(
        matrix,
        projection,
        observed_preflight,
        stage_results,
        artifact_digests,
        events,
        protocol_drift=protocol_drift,
    )
    _atomic_write(BUNDLE_PATH, _json_bytes(bundle))
    terminal_result = bundle["result"]
    if not isinstance(terminal_result, Mapping):
        raise QualificationError("qualification terminal result invalid")
    print(json.dumps(terminal_result, sort_keys=True))
    return 0 if terminal_result.get("disposition") == "AUTONOMOUS_PLANNER_QUALIFIED" else 1


def verify_command() -> int:
    matrix, projection, pins = _load_inputs()
    bundle = load_json_file(BUNDLE_PATH, label="qualification bundle", maximum_bytes=MAX_BUNDLE_BYTES)
    payloads = _artifact_payloads(matrix)
    result = verify_bundle(matrix, projection, bundle, pins, payloads)
    print(json.dumps(result, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "run", "verify"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "preflight":
            return preflight_command()
        if args.command == "run":
            return run_command()
        return verify_command()
    except (QualificationError, OSError, subprocess.SubprocessError) as exc:
        print(f"autonomous planner qualification: FAIL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
