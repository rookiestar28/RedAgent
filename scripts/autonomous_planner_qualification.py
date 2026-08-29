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
import stat
import subprocess
import sys
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.validation.autonomous_planner_qualification import (  # noqa: E402
    MAX_BUNDLE_BYTES,
    MAX_PROJECTION_BYTES,
    MATRIX_SCHEMA_V4,
    MATRIX_SCHEMA_V5,
    MATRIX_SCHEMA_V6,
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


MATRIX_PATH = ROOT / "config/validation/autonomous-planner-qualification-v6.json"
# IMPORTANT: keep this formal writer root short; deep atomic filenames fail under legacy Windows
# MAX_PATH when the qualification namespace consumes the path budget before product tests run.
OUTPUT_ROOT = ROOT / ".tmp/apq-06"
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
RUNTIME_COORDINATE_SNAPSHOT = OUTPUT_ROOT / "runtime-coordinate-snapshot.json"
MAX_STAGE_LOG_BYTES = 32 * 1024 * 1024
MAX_RUNTIME_COORDINATE_BYTES = 128 * 1024
RUNTIME_COORDINATE_SCHEMA = "redagent.autonomous-planner-runtime-coordinate-snapshot/v1"
LOCAL_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
QUALIFICATION_INVOCATION_ID = re.compile(r"^invocation-planner-[0-9a-f]{12}$")
DOCKER_RESOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
DOCKER_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
V5_DEFAULT_FULL_GATE_VOLUMES = (
    ("redagent-local-postgres-data", "redagent_postgres_data"),
    ("redagent-local-keycloak-data", "redagent_keycloak_data"),
    ("redagent-local-temporal-data", "redagent_temporal_data"),
    ("redagent-local-rustfs-data", "redagent_rustfs_data"),
)

PYTHON_STARTUP_VARIABLES = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONUSERBASE",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONWARNINGS",
        "PYTHONBREAKPOINT",
        "PYTHONPLATLIBDIR",
        "PYTHONCASEOK",
        "PYTHONEXECUTABLE",
        "PYTHONPYCACHEPREFIX",
        "PYTHONSAFEPATH",
    }
)

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
    "--deselect=tests/unit/test_planner_evidence.py::test_file_symlink_artifact_fails_before_parsing",
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
    if runner_id == "owned-runtime-provision":
        return (
            (python, "scripts/redagent_local_stack.py", "start", "--json"),
            (python, "scripts/openbao_conformance.py", "provision"),
            (python, "scripts/opa_conformance.py", "provision"),
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
    if runner_id == "internal-runtime-coordinate-snapshot":
        return ()
    if runner_id == "internal-residual-safety":
        return ()
    raise QualificationError("unknown qualification runner id")


def _stage_commands(
    stage: StageSpec,
    matrix: QualificationMatrix,
    projection,
) -> tuple[tuple[str, ...], ...]:
    commands = _runner_commands(
        stage.runner_id,
        projection.candidate_commit,
        projection.candidate_parent_commit,
    )
    if matrix.schema_version not in (MATRIX_SCHEMA_V4, MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6) or stage.runner_id != "windows-full-gate":
        return commands
    # CRITICAL: the Full Gate can leave default persisted coordinates. V4-V6 must reset that exact
    # synthetic runtime only after both gate commands pass, or provision can combine 55432 state
    # with the frozen 55472 environment. Keep V1-V3 command behavior unchanged.
    return (
        *commands,
        *_runner_commands(
            "owned-runtime-cleanup",
            projection.candidate_commit,
            projection.candidate_parent_commit,
        ),
    )


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
    # CRITICAL: keep all three exact input paths synchronized with the active attempt constants.
    # A stale prior-attempt literal mixes immutable evidence into a fresh qualification setup.
    _assert_fixed_path(
        MATRIX_PATH, ROOT / "config/validation/autonomous-planner-qualification-v6.json", must_exist=True
    )
    _assert_fixed_path(
        PROJECTION_PATH,
        ROOT / ".tmp/apq-06/execution-projection.json",
        must_exist=True,
    )
    _assert_fixed_path(
        PINS_PATH,
        ROOT / ".tmp/apq-06/verification-pins.json",
        must_exist=True,
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
    _assert_formal_start_ready(matrix)
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
    if stage.result_kind in {"cleanup", "provision"}:
        return text.count('"ok": true'), 0
    if stage.result_kind in {"residual", "runtime-snapshot"}:
        value = decode_json_bytes(
            text.encode("utf-8"),
            label=f"{stage.result_kind} report",
            maximum_bytes=1024 * 1024,
        )
        if not isinstance(value, Mapping) or not isinstance(value.get("passed_check_count"), int):
            raise QualificationError(f"{stage.result_kind} report invalid")
        return value["passed_check_count"], 0
    patterns = {
        "pytest": re.compile(r"(?m)(?P<passed>\d+) passed(?:, (?P<skipped>\d+) skipped)?"),
        "vitest": re.compile(r"(?m)Tests\s+(?P<passed>\d+) passed(?:\s+\|\s+(?P<skipped>\d+) skipped)?"),
        "playwright": re.compile(r"(?m)(?P<passed>\d+) passed"),
    }
    match = patterns[stage.result_kind].search(text)
    if match is None:
        raise QualificationError("stage success-count evidence missing")
    # IMPORTANT: not every runner exposes a skipped capture; missing named groups are zero,
    # never an out-of-range capture access that can escape the terminal evidence lifecycle.
    skipped = match.groupdict().get("skipped")
    return int(match.group("passed")), int(skipped or 0)


def _stage_log_paths(stage: StageSpec) -> tuple[Path, Path]:
    return (
        STAGE_LOG_ROOT / f"{stage.stage_id}.stdout.log",
        STAGE_LOG_ROOT / f"{stage.stage_id}.stderr.log",
    )


def _fixed_child_environment(matrix: QualificationMatrix, stage: StageSpec) -> dict[str, str]:
    if stage.runner_id not in matrix.runner_environment:
        raise QualificationError("formal runner environment binding missing")
    child_environment = dict(os.environ)
    fixed_writer_names = {
        "TEMP",
        "TMP",
        "TMPDIR",
        "PRE_COMMIT_HOME",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    }
    # CRITICAL: ambient Python and REDAGENT values can redirect trusted imports, runtime topology,
    # or writers. Strip them before adding only the closed matrix bindings below.
    for name in tuple(child_environment):
        upper_name = name.upper()
        if (
            upper_name in PYTHON_STARTUP_VARIABLES
            or upper_name in fixed_writer_names
            or upper_name.startswith("REDAGENT_")
        ):
            del child_environment[name]

    runtime_paths = {name: ROOT / Path(value) for name, value in matrix.formal_runtime_paths.items()}
    if set(runtime_paths) != {"home", "pre_commit_home", "temp"}:
        raise QualificationError("formal runtime path binding incomplete")
    for path in runtime_paths.values():
        _assert_fixed_path(path, path, must_exist=False, directory=True)
        path.mkdir(parents=True, exist_ok=True)
        _assert_fixed_path(path, path, must_exist=True, directory=True)
    appdata = runtime_paths["home"] / "AppData/Roaming"
    localappdata = runtime_paths["home"] / "AppData/Local"
    for path in (appdata, localappdata):
        _assert_fixed_path(path, path, must_exist=False, directory=True)
        path.mkdir(parents=True, exist_ok=True)
        _assert_fixed_path(path, path, must_exist=True, directory=True)

    temp = str(runtime_paths["temp"].resolve())
    home = str(runtime_paths["home"].resolve())
    child_environment.update(
        {
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEMP": temp,
            "TMP": temp,
            "TMPDIR": temp,
            "PRE_COMMIT_HOME": str(runtime_paths["pre_commit_home"].resolve()),
            "HOME": home,
            "USERPROFILE": home,
            "APPDATA": str(appdata.resolve()),
            "LOCALAPPDATA": str(localappdata.resolve()),
        }
    )
    child_environment.update(matrix.formal_environment)
    child_environment.update(matrix.runner_environment[stage.runner_id])
    return child_environment


def _run_processes(
    commands: Sequence[Sequence[str]],
    stage: StageSpec,
    matrix: QualificationMatrix,
) -> tuple[int, bool]:
    stdout_path, stderr_path = _stage_log_paths(stage)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    if stdout_path.exists() or stderr_path.exists():
        raise QualificationError("formal stage log already exists")
    completed_count = 0
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        for command in commands:
            child_environment = _fixed_child_environment(matrix, stage)
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


def _v5_cleanup_onerror(cleanup_root: Path):
    root = cleanup_root.absolute()

    def handle(function, failed_path, exc_info) -> None:
        failed = Path(failed_path).absolute()
        try:
            relative = failed.relative_to(root)
        except ValueError as exc:
            raise QualificationError("V5 cleanup path escaped the declared root") from exc
        if not relative.parts or platform.system() != "Windows":
            raise QualificationError("V5 cleanup platform or descendant contract invalid")
        if function not in (os.unlink, os.remove):
            raise QualificationError("V5 cleanup callback function invalid")
        if not isinstance(exc_info, tuple) or len(exc_info) != 3 or not isinstance(exc_info[1], PermissionError):
            raise QualificationError("V5 cleanup exception contract invalid")

        if is_link_or_reparse(root):
            raise QualificationError("V5 cleanup path traverses a link or reparse point")
        current = root
        for component in relative.parts:
            current /= component
            if is_link_or_reparse(current):
                raise QualificationError("V5 cleanup path traverses a link or reparse point")
        if not failed.is_file():
            raise QualificationError("V5 cleanup target is not a regular file")
        attributes = getattr(failed.lstat(), "st_file_attributes", 0)
        readonly = getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x1)
        if not attributes & readonly:
            raise QualificationError("V5 cleanup target is not read-only")

        # CRITICAL: pytest can leave read-only Git objects in the declared Windows temp tree. Clear
        # only that exact regular descendant and retry its failed unlink once; widening this callback
        # can traverse reparse points or delete state owned by another workspace.
        os.chmod(failed, stat.S_IWRITE)
        function(failed)

    return handle


def _remove_item_runtime_paths(matrix: QualificationMatrix) -> None:
    for relative in matrix.cleanup_paths:
        path = ROOT / Path(relative)
        expected = ROOT / Path(relative)
        _assert_fixed_path(path, expected, must_exist=False, directory=True)
        if not path.exists():
            continue
        _assert_fixed_path(path, expected, must_exist=True, directory=True)
        if matrix.schema_version in (MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6):
            shutil.rmtree(path, onerror=_v5_cleanup_onerror(path))
        else:
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


def _read_fixed_bytes(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    _assert_fixed_path(path, path, must_exist=True)
    size = path.stat().st_size
    if size < 1 or size > maximum_bytes:
        raise QualificationError(f"{label} byte contract invalid")
    return path.read_bytes()


def _qualification_zap_state() -> tuple[tuple[Path, Path], ...]:
    runtime = ROOT / ".local/redagent/r123-zap"
    _assert_fixed_path(runtime, runtime, must_exist=False, directory=True)
    if not runtime.exists():
        return ()
    _assert_fixed_path(runtime, runtime, must_exist=True, directory=True)
    entries = tuple(runtime.iterdir())
    if len(entries) > 128 or any(is_link_or_reparse(path) for path in entries):
        raise QualificationError("qualification runtime inventory invalid")
    records: list[tuple[Path, Path]] = []
    for receipt in entries:
        if not receipt.name.startswith("receipt-") or receipt.suffix != ".json":
            continue
        value = load_json_file(
            receipt,
            label="qualification receipt",
            maximum_bytes=1024 * 1024,
        )
        if not isinstance(value, Mapping):
            raise QualificationError("qualification receipt invalid")
        invocation_id = value.get("invocation_id")
        if not isinstance(invocation_id, str) or QUALIFICATION_INVOCATION_ID.fullmatch(invocation_id) is None:
            continue
        digest = hashlib.sha256(invocation_id.encode("utf-8")).hexdigest()
        if receipt.name != f"receipt-{digest}.json":
            raise QualificationError("qualification receipt binding invalid")
        run_root = runtime / digest[:24]
        _assert_fixed_path(run_root, run_root, must_exist=True, directory=True)
        records.append((receipt, run_root))
    return tuple(records)


def _remove_owned_zap_qualification_state() -> int:
    records = _qualification_zap_state()
    for receipt, run_root in records:
        # CRITICAL: only a receipt-bound qualification invocation authorizes recursive removal of its exact
        # workspace-contained run directory; never generalize this to the shared R123 runtime.
        shutil.rmtree(run_root)
        receipt.unlink()
    runtime = ROOT / ".local/redagent/r123-zap"
    if runtime.is_dir() and not any(runtime.iterdir()):
        runtime.rmdir()
    if _qualification_zap_state():
        raise QualificationError("qualification runtime cleanup incomplete")
    return len(records)


def _zap_qualification_state_absent() -> bool:
    runtime = ROOT / ".local/redagent/r123-zap"
    records = _qualification_zap_state()
    if records:
        return False
    if not runtime.exists():
        return True
    # Any unbound 24-hex run root is ambiguous state and must deny qualification, not be deleted.
    return not any(re.fullmatch(r"[0-9a-f]{24}", path.name) for path in runtime.iterdir())


def _remove_v5_empty_state_root(matrix: QualificationMatrix) -> int:
    if matrix.schema_version not in (MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6):
        raise QualificationError("empty state-root cleanup schema invalid")
    state_root = ROOT / Path(matrix.formal_environment["REDAGENT_STATE_DIR"])
    _assert_fixed_path(state_root, ROOT / ".local/redagent", must_exist=False, directory=True)
    if not state_root.exists():
        return 0
    _assert_fixed_path(state_root, ROOT / ".local/redagent", must_exist=True, directory=True)
    try:
        # CRITICAL: keep this nonrecursive and V5/V6-only. Broadening it to rmtree would erase
        # ambiguous product state that must deny readiness after receipt-bound child cleanup.
        state_root.rmdir()
    except OSError as exc:
        raise QualificationError("empty state-root cleanup failed") from exc
    if state_root.exists():
        raise QualificationError("empty state-root cleanup incomplete")
    return 1


def _workspace_compose_project(prefix: str) -> str:
    try:
        root = ROOT.resolve(strict=True)
    except OSError as exc:
        raise QualificationError("runtime coordinate workspace invalid") from exc
    if not root.is_dir():
        raise QualificationError("runtime coordinate workspace invalid")
    identity = os.path.normcase(str(root)).replace("\\", "/")
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def _v5_docker_lines(command: Sequence[str], *, label: str) -> tuple[str, ...]:
    completed = subprocess.run(
        tuple(command),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    lines = tuple(completed.stdout.splitlines())
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > 1024 * 1024
        or len(lines) > 4096
        or any(line != line.strip() for line in lines)
    ):
        raise QualificationError(f"default Full Gate volume {label} invalid")
    return lines


def _remove_v5_default_full_gate_volumes(matrix: QualificationMatrix) -> int:
    if matrix.schema_version not in (MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6):
        raise QualificationError("default Full Gate volume cleanup schema invalid")
    docker = _tool("docker")
    expected = dict(V5_DEFAULT_FULL_GATE_VOLUMES)
    inventory = _v5_docker_lines(
        (docker, "volume", "ls", "--format", "{{.Name}}"),
        label="name inventory",
    )
    if len(set(inventory)) != len(inventory) or any(DOCKER_RESOURCE_NAME.fullmatch(name) is None for name in inventory):
        raise QualificationError("default Full Gate volume name inventory invalid")
    present = set(inventory).intersection(expected)
    if not present:
        return 0
    if present != set(expected):
        raise QualificationError("default Full Gate volume inventory incomplete")

    inspect_format = (
        '{{.Name}}\t{{.Driver}}\t{{index .Labels "com.docker.compose.project"}}'
        '\t{{index .Labels "com.docker.compose.volume"}}'
    )
    inspect_lines = _v5_docker_lines(
        (
            docker,
            "volume",
            "inspect",
            "--format",
            inspect_format,
            *(name for name, _volume_key in V5_DEFAULT_FULL_GATE_VOLUMES),
        ),
        label="inventory",
    )
    observed: dict[str, str] = {}
    for line in inspect_lines:
        fields = line.split("\t")
        if len(fields) != 4:
            raise QualificationError("default Full Gate volume inventory invalid")
        name, driver, project, volume_key = fields
        if (
            name in observed
            or name not in expected
            or DOCKER_RESOURCE_NAME.fullmatch(name) is None
            or driver != "local"
            or project != "redagent-local"
            or volume_key != expected[name]
        ):
            raise QualificationError("default Full Gate volume ownership invalid")
        observed[name] = volume_key
    if observed != expected:
        raise QualificationError("default Full Gate volume inventory incomplete")

    # CRITICAL: validate the complete exact ownership and zero-attachment set before the first
    # destructive call. Deleting incrementally while still discovering ownership can erase an
    # ambiguous volume and leave a partial runtime that a later provision would misclassify.
    for name, _volume_key in V5_DEFAULT_FULL_GATE_VOLUMES:
        attachments = _v5_docker_lines(
            (
                docker,
                "ps",
                "-a",
                "--filter",
                f"volume={name}",
                "--format",
                "{{.ID}}",
            ),
            label="attachment inventory",
        )
        if any(DOCKER_CONTAINER_ID.fullmatch(container_id) is None for container_id in attachments):
            raise QualificationError("default Full Gate volume attachment inventory invalid")
        if attachments:
            raise QualificationError("default Full Gate volume is attached")

    for name, _volume_key in V5_DEFAULT_FULL_GATE_VOLUMES:
        removed = _v5_docker_lines(
            (docker, "volume", "rm", name),
            label="removal",
        )
        if removed != (name,):
            raise QualificationError("default Full Gate volume removal readback invalid")

    remaining = _v5_docker_lines(
        (docker, "volume", "ls", "--format", "{{.Name}}"),
        label="absence readback",
    )
    if any(DOCKER_RESOURCE_NAME.fullmatch(name) is None for name in remaining):
        raise QualificationError("default Full Gate volume absence inventory invalid")
    if any(name in expected for name in remaining):
        raise QualificationError("default Full Gate volume cleanup incomplete")
    return len(V5_DEFAULT_FULL_GATE_VOLUMES)


def _assert_formal_start_ready(matrix: QualificationMatrix) -> None:
    if matrix.schema_version not in (MATRIX_SCHEMA_V4, MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6):
        return

    state_root = ROOT / Path(matrix.formal_environment["REDAGENT_STATE_DIR"])
    _assert_fixed_path(state_root, ROOT / ".local/redagent", must_exist=False, directory=True)
    if state_root.exists():
        raise QualificationError("formal start owned state is present")

    port_names = (
        "REDAGENT_POSTGRES_PORT",
        "REDAGENT_KEYCLOAK_PORT",
        "REDAGENT_TEMPORAL_PORT",
        "REDAGENT_RUSTFS_PORT",
        "REDAGENT_OPA_HOST_PORT",
    )
    try:
        ports = tuple(int(matrix.formal_environment[name], 10) for name in port_names) + (58200,)
    except (KeyError, ValueError) as exc:
        raise QualificationError("formal start declared port inventory invalid") from exc
    if len(set(ports)) != 6 or any(not 1024 <= port <= 65535 for port in ports):
        raise QualificationError("formal start declared port inventory invalid")
    if any(not _port_closed(port) for port in ports):
        raise QualificationError("formal start declared port is open")

    docker = _tool("docker")
    inventories: list[tuple[str, ...]] = []
    for arguments in (
        ("ps", "-a", "--format", "{{.Names}}"),
        ("network", "ls", "--format", "{{.Name}}"),
        ("volume", "ls", "--format", "{{.Name}}"),
    ):
        completed = subprocess.run(
            (docker, *arguments),
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        lines = tuple(completed.stdout.splitlines())
        if (
            completed.returncode != 0
            or len(completed.stdout) > 1024 * 1024
            or len(lines) > 4096
            or any(name != name.strip() or DOCKER_RESOURCE_NAME.fullmatch(name) is None for name in lines)
        ):
            raise QualificationError("formal start Docker inventory invalid")
        inventories.append(lines)

    markers = (
        matrix.formal_environment["REDAGENT_COMPOSE_PROJECT_NAME"],
        _workspace_compose_project("redagent-opa"),
        _workspace_compose_project("redagent-openbao"),
        "redagent-r123-zap",
        *(("redagent-local",) if matrix.schema_version in (MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6) else ()),
    )
    # CRITICAL: this is a startup-only denial check. Reusing it after a formal stage would classify
    # expected provisioned state as drift and abort a valid lifecycle before its fixed cleanup stage.
    if any(
        name.lower() == marker.lower()
        or name.lower().startswith(marker.lower() + "-")
        or name.lower().startswith(marker.lower() + "_")
        for names in inventories
        for name in names
        for marker in markers
    ):
        raise QualificationError("formal start owned Docker resource is present")


def _complete_v4_full_gate_transition(matrix: QualificationMatrix, stdout_path: Path) -> None:
    if matrix.schema_version != MATRIX_SCHEMA_V4:
        raise QualificationError("formal Full Gate transition schema invalid")
    removed_receipts = _remove_owned_zap_qualification_state()
    _remove_item_runtime_paths(matrix)
    _assert_formal_start_ready(matrix)
    with stdout_path.open("ab") as stdout:
        stdout.write(
            (
                json.dumps(
                    {
                        "formal_full_gate_transition_ready": True,
                        "removed_qualification_receipts": removed_receipts,
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
        )
        stdout.flush()
        os.fsync(stdout.fileno())


def _complete_v5_full_gate_transition(matrix: QualificationMatrix, stdout_path: Path) -> None:
    if matrix.schema_version not in (MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6):
        raise QualificationError("V5/V6 formal Full Gate transition schema invalid")
    removed_receipts = _remove_owned_zap_qualification_state()
    _remove_item_runtime_paths(matrix)
    removed_empty_state_root = _remove_v5_empty_state_root(matrix)
    removed_volumes = _remove_v5_default_full_gate_volumes(matrix)
    _assert_formal_start_ready(matrix)
    with stdout_path.open("ab") as stdout:
        stdout.write(
            (
                json.dumps(
                    {
                        "formal_full_gate_transition_ready": True,
                        "removed_default_full_gate_volumes": removed_volumes,
                        "removed_empty_state_root": removed_empty_state_root,
                        "removed_qualification_receipts": removed_receipts,
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
        )
        stdout.flush()
        os.fsync(stdout.fileno())


def _runtime_environment_coordinates() -> tuple[str, dict[str, int]]:
    path = ROOT / ".local/redagent/runtime/local-stack.env"
    try:
        text = _read_fixed_bytes(
            path,
            maximum_bytes=MAX_RUNTIME_COORDINATE_BYTES,
            label="local-stack runtime coordinates",
        ).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QualificationError("local-stack runtime coordinates invalid") from exc
    required = {
        "REDAGENT_COMPOSE_PROJECT_NAME",
        "REDAGENT_BIND_HOST",
        "REDAGENT_POSTGRES_PORT",
        "REDAGENT_KEYCLOAK_PORT",
        "REDAGENT_TEMPORAL_PORT",
        "REDAGENT_RUSTFS_PORT",
    }
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if separator and name in required:
            if name in values:
                raise QualificationError("local-stack runtime coordinate duplicate")
            values[name] = value
    if set(values) != required:
        raise QualificationError("local-stack runtime coordinate inventory invalid")
    project = values["REDAGENT_COMPOSE_PROJECT_NAME"]
    if LOCAL_COMPOSE_PROJECT.fullmatch(project) is None or values["REDAGENT_BIND_HOST"] != "127.0.0.1":
        raise QualificationError("local-stack runtime coordinate identity invalid")
    ports: dict[str, int] = {}
    for service, name in (
        ("postgres", "REDAGENT_POSTGRES_PORT"),
        ("keycloak", "REDAGENT_KEYCLOAK_PORT"),
        ("temporal", "REDAGENT_TEMPORAL_PORT"),
        ("rustfs", "REDAGENT_RUSTFS_PORT"),
    ):
        try:
            port = int(values[name], 10)
        except ValueError as exc:
            raise QualificationError("local-stack runtime port invalid") from exc
        if not 1024 <= port <= 65535:
            raise QualificationError("local-stack runtime port invalid")
        ports[service] = port
    if len(set(ports.values())) != len(ports):
        raise QualificationError("local-stack runtime ports overlap")
    return project, dict(sorted(ports.items()))


def _opa_runtime_port() -> int:
    path = ROOT / ".local/redagent/opa/opa-endpoint.json"
    value = decode_json_bytes(
        _read_fixed_bytes(path, maximum_bytes=4096, label="OPA runtime coordinate"),
        label="OPA runtime coordinate",
        maximum_bytes=4096,
    )
    if not isinstance(value, Mapping) or set(value) != {"port"}:
        raise QualificationError("OPA runtime coordinate invalid")
    port = value["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise QualificationError("OPA runtime coordinate invalid")
    return port


def _parse_runtime_coordinate_snapshot(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "local_stack",
        "opa",
        "openbao",
        "ports",
        "resource_markers",
        "snapshot_sha256",
    }:
        raise QualificationError("runtime coordinate snapshot invalid")
    body = {key: item for key, item in value.items() if key != "snapshot_sha256"}
    supplied_digest = value["snapshot_sha256"]
    if (
        value["schema_version"] != RUNTIME_COORDINATE_SCHEMA
        or not isinstance(supplied_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", supplied_digest) is None
        or hashlib.sha256(canonical_bytes(body)).hexdigest() != supplied_digest
    ):
        raise QualificationError("runtime coordinate snapshot digest invalid")
    local_stack = value["local_stack"]
    opa = value["opa"]
    openbao = value["openbao"]
    if not isinstance(local_stack, Mapping) or set(local_stack) != {"project_name", "ports"}:
        raise QualificationError("runtime coordinate local-stack invalid")
    if not isinstance(opa, Mapping) or set(opa) != {"project_name", "port"}:
        raise QualificationError("runtime coordinate OPA invalid")
    if not isinstance(openbao, Mapping) or set(openbao) != {"project_name", "port"}:
        raise QualificationError("runtime coordinate OpenBao invalid")
    project = local_stack["project_name"]
    local_ports = local_stack["ports"]
    if not isinstance(project, str) or LOCAL_COMPOSE_PROJECT.fullmatch(project) is None:
        raise QualificationError("runtime coordinate local-stack invalid")
    if not isinstance(local_ports, Mapping) or set(local_ports) != {"postgres", "keycloak", "temporal", "rustfs"}:
        raise QualificationError("runtime coordinate local-stack invalid")
    typed_ports = tuple(local_ports[key] for key in sorted(local_ports))
    if any(isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535 for port in typed_ports):
        raise QualificationError("runtime coordinate port invalid")
    expected_opa_project = _workspace_compose_project("redagent-opa")
    expected_openbao_project = _workspace_compose_project("redagent-openbao")
    if opa["project_name"] != expected_opa_project or openbao != {
        "project_name": expected_openbao_project,
        "port": 58200,
    }:
        raise QualificationError("runtime coordinate workspace identity invalid")
    opa_port = opa["port"]
    if isinstance(opa_port, bool) or not isinstance(opa_port, int) or not 1024 <= opa_port <= 65535:
        raise QualificationError("runtime coordinate OPA invalid")
    expected_ports = sorted({*typed_ports, opa_port, 58200})
    if value["ports"] != expected_ports or len(expected_ports) != 6:
        raise QualificationError("runtime coordinate port inventory invalid")
    expected_markers = sorted({project, expected_opa_project, expected_openbao_project, "redagent-r123-zap"})
    if value["resource_markers"] != expected_markers:
        raise QualificationError("runtime coordinate resource inventory invalid")
    return value


def _capture_runtime_coordinate_snapshot() -> Mapping[str, object]:
    local_project, local_ports = _runtime_environment_coordinates()
    opa_port = _opa_runtime_port()
    opa_project = _workspace_compose_project("redagent-opa")
    openbao_project = _workspace_compose_project("redagent-openbao")
    ports = sorted({*local_ports.values(), opa_port, 58200})
    if len(ports) != 6:
        raise QualificationError("runtime coordinate port inventory invalid")
    body: dict[str, object] = {
        "schema_version": RUNTIME_COORDINATE_SCHEMA,
        "local_stack": {"project_name": local_project, "ports": local_ports},
        "opa": {"project_name": opa_project, "port": opa_port},
        "openbao": {"project_name": openbao_project, "port": 58200},
        "ports": ports,
        "resource_markers": sorted({local_project, opa_project, openbao_project, "redagent-r123-zap"}),
    }
    snapshot = {**body, "snapshot_sha256": hashlib.sha256(canonical_bytes(body)).hexdigest()}
    _parse_runtime_coordinate_snapshot(snapshot)
    _atomic_write(RUNTIME_COORDINATE_SNAPSHOT, _json_bytes(snapshot))
    return snapshot


def _load_runtime_coordinate_snapshot() -> Mapping[str, object]:
    return _parse_runtime_coordinate_snapshot(
        load_json_file(
            RUNTIME_COORDINATE_SNAPSHOT,
            label="runtime coordinate snapshot",
            maximum_bytes=MAX_RUNTIME_COORDINATE_BYTES,
        )
    )


def _residual_report(matrix: QualificationMatrix, projection) -> dict[str, object]:
    snapshot = _load_runtime_coordinate_snapshot()
    checks: dict[str, bool] = {
        "candidate_commit_unchanged": _git("rev-parse", "HEAD") == projection.candidate_commit,
        "candidate_tree_unchanged": _git("rev-parse", "HEAD^{tree}") == projection.candidate_tree,
        "source_inventory_unchanged": _source_digests(matrix) == dict(projection.source_sha256),
        "tracked_worktree_clean": _git("status", "--porcelain", "--untracked-files=all") == "",
        "item_runtime_paths_removed": all(not (ROOT / Path(path)).exists() for path in matrix.cleanup_paths),
        "owned_zap_qualification_state_absent": _zap_qualification_state_absent(),
        "snapshotted_ports_absent": False,
        "owned_containers_absent": False,
        "owned_networks_absent": False,
    }
    containers = subprocess.run(
        (_tool("docker"), "ps", "-a", "--format", "{{.Names}}"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    networks = subprocess.run(
        (_tool("docker"), "network", "ls", "--format", "{{.Name}}"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    markers_value = snapshot["resource_markers"]
    ports_value = snapshot["ports"]
    if not isinstance(markers_value, list) or not isinstance(ports_value, list):
        raise QualificationError("runtime coordinate snapshot inventory invalid")
    markers = tuple(str(marker).lower() for marker in markers_value)
    container_names = containers.stdout.lower().splitlines() if containers.returncode == 0 else []
    network_names = networks.stdout.lower().splitlines() if networks.returncode == 0 else []
    checks["snapshotted_ports_absent"] = all(_port_closed(int(port)) for port in ports_value)
    checks["owned_containers_absent"] = containers.returncode == 0 and all(
        not any(marker in name for name in container_names) for marker in markers
    )
    checks["owned_networks_absent"] = networks.returncode == 0 and all(
        not any(marker in name for name in network_names) for marker in markers
    )
    return {
        "schema_version": "redagent.autonomous-planner-qualification-residual/v2",
        "checks": checks,
        "passed_check_count": sum(checks.values()),
        "required_check_count": len(checks),
        "unapproved_assessment_contacts": 0,
        "cleanup_complete": all(checks.values()),
    }


def _execute_stage(stage: StageSpec, matrix: QualificationMatrix, projection) -> dict[str, object]:
    stdout_path, stderr_path = _stage_log_paths(stage)
    commands = _stage_commands(stage, matrix, projection)
    launch_aborted = False
    completed_count = 0
    if stage.result_kind == "residual":
        report = _residual_report(matrix, projection)
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(stdout_path, _json_bytes(report))
        _atomic_write(stderr_path, b"")
    elif stage.result_kind == "runtime-snapshot":
        snapshot = _capture_runtime_coordinate_snapshot()
        report = {
            "schema_version": "redagent.autonomous-planner-runtime-coordinate-stage/v1",
            "passed_check_count": 1,
            "snapshot_sha256": snapshot["snapshot_sha256"],
            "unapproved_assessment_contacts": 0,
        }
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(stdout_path, _json_bytes(report))
        _atomic_write(stderr_path, b"")
    else:
        completed_count, launch_aborted = _run_processes(commands, stage, matrix)
        if stage.runner_id == "windows-full-gate" and not launch_aborted and completed_count == len(commands):
            if matrix.schema_version == MATRIX_SCHEMA_V4:
                _complete_v4_full_gate_transition(matrix, stdout_path)
            elif matrix.schema_version in (MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6):
                _complete_v5_full_gate_transition(matrix, stdout_path)
        if stage.result_kind == "cleanup" and not launch_aborted and completed_count == len(commands):
            removed_receipts = _remove_owned_zap_qualification_state()
            with stdout_path.open("ab") as stdout:
                stdout.write(
                    (
                        json.dumps(
                            {
                                "ok": True,
                                "removed_qualification_receipts": removed_receipts,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("utf-8")
                )
                stdout.flush()
                os.fsync(stdout.fileno())
            _remove_item_runtime_paths(matrix)
        if stage.runner_id == "pytest-offline-lineage" and not launch_aborted and completed_count == len(commands):
            # IMPORTANT: post-cleanup verification gets its own contained temp/home writers; remove
            # those recreated paths before the terminal residual stage proves item ownership empty.
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
    if stage.result_kind == "runtime-snapshot" and RUNTIME_COORDINATE_SNAPSHOT.is_file():
        artifacts["runtime-coordinate-snapshot.json"] = file_sha256(RUNTIME_COORDINATE_SNAPSHOT)
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
        RUNTIME_COORDINATE_SNAPSHOT,
    )
    if any(path.exists() for path in formal_outputs):
        raise QualificationError("formal attempt output already exists; retries are forbidden")
    _assert_formal_start_ready(matrix)
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
            except Exception:  # noqa: BLE001 - formal ordinary failures must become denial evidence
                # CRITICAL: after formal start, any ordinary controller defect is denial evidence,
                # not an unrecorded crash. Never broaden this to BaseException or turn it into pass.
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
            except Exception:  # noqa: BLE001 - drift observation defects must fail closed
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
    events = build_event_chain(
        event_inputs,
        expected_stage_ids=[stage.stage_id for stage in matrix.stages],
    )
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
