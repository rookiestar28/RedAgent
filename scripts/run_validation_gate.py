from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time
from typing import Sequence

# CRITICAL: keep the repository bootstrap before package imports; both supported
# wrappers execute this file directly, which otherwise exposes only scripts/.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.validation import (
    ChangeRequest,
    GateDecision,
    ReceiptVerificationError,
    StageResult,
    StageRunner,
    ValidationConfigError,
    build_default_registry,
    build_verification_receipt,
    classify_change,
    current_configuration_digests,
    decision_evidence_payload,
    verify_verification_receipt,
)
from redagent_platform.gate_lease import (
    ValidationLease,
    bind_authoritative_validation_platform,
    validated_authoritative_validation_lease_path,
)
from redagent_platform.gate_runtime import (
    EvidenceParentGuard,
    GateRuntimeError,
    attest_active_project_venv,
    prepare_authoritative_runtime as _prepare_gate_runtime,
    run_bounded_stdout,
)
from redagent_platform.gate_deadline import bounded_timeout, budget_seconds


DEFAULT_RECEIPT = ROOT / ".tmp/validation/verification.json"
DEFAULT_DECISION_RECEIPT = ROOT / ".tmp/validation/decision.json"
ZERO_REVISION = "0" * 40
_FULL_REVISION = re.compile(r"^[0-9a-fA-F]{40}$")
_DIFF_STATUSES = {"A", "C", "D", "M", "R", "T", "U", "X", "B"}
_ARTIFACT_SPECS = {
    "secure_sdlc_sbom": (Path(".tmp/sbom/redagent-sbom.json"), 16 * 1024 * 1024),
    "frontend_index": (Path("frontend/dist/index.html"), 2 * 1024 * 1024),
    "frontend_cli": (Path("frontend/cli-dist/cli/redagent.js"), 16 * 1024 * 1024),
    "openapi_contract": (Path("frontend/openapi.json"), 16 * 1024 * 1024),
}
_MAX_ARTIFACT_TOTAL_BYTES = 32 * 1024 * 1024
_GIT_TIMEOUT_SECONDS = 30
_TOOL_PREFLIGHT_TIMEOUT_SECONDS = 30
_MAX_GIT_OUTPUT_BYTES = 2 * 1024 * 1024
_MAX_WORKTREE_DIAGNOSTIC_BYTES = 4096
_MAX_WORKTREE_DIAGNOSTIC_ENTRIES = 20
DEFAULT_VERIFY_EXECUTION_SECONDS = 600
_MIN_VERIFY_EXECUTION_SECONDS = 60
_MAX_VERIFY_EXECUTION_SECONDS = 7_200
_GIT_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}
_GIT_ALLOWED_ENVIRONMENT = {
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE",
}
_GIT_COMMAND_CONFIG_OVERRIDES = (
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.untrackedCache=false",
    "maintenance.auto=false",
    "gc.auto=0",
    "credential.helper=",
)
_GIT_DIFF_COMMANDS = frozenset({"diff", "log", "show", "diff-tree", "diff-index", "diff-files"})
_SELECTIVE_DEPENDENCY_MODULES = ("pre_commit", "pytest")


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in _GIT_ALLOWED_ENVIRONMENT
    }
    environment.update(_GIT_ENVIRONMENT)
    return environment


def _isolated_git_command(arguments: Sequence[str]) -> tuple[str, ...]:
    """Build a read-only Git command with helper-dispatch features disabled."""

    if not arguments:
        raise RuntimeError("Git source query requires a subcommand")
    command: list[str] = ["git", "--no-pager", "--no-replace-objects"]
    # CRITICAL: hosted runners may own the checkout through a service identity.
    # Trust only this code-owned authoritative root; global config remains disabled.
    command.extend(("-c", f"safe.directory={ROOT.absolute()}"))
    if os.name == "nt":
        # IMPORTANT: Actions materializes Windows checkouts with CRLF normalization
        # from global config; preserve that exact semantic after global config denial.
        command.extend(("-c", "core.autocrlf=true"))
    for setting in _GIT_COMMAND_CONFIG_OVERRIDES:
        command.extend(("-c", setting))
    command.append(arguments[0])
    if arguments[0] in _GIT_DIFF_COMMANDS:
        # CRITICAL: source-state diffs must not invoke repository-configured helpers.
        command.extend(("--no-ext-diff", "--no-textconv"))
    command.extend(arguments[1:])
    return tuple(command)


def _remaining_timeout(deadline: float | None, cap_seconds: int, phase: str) -> int:
    """Return a child timeout that cannot extend an enclosing absolute deadline."""

    if deadline is None:
        return cap_seconds
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise RuntimeError("authoritative verification deadline is invalid")
    timeout_seconds = bounded_timeout(float(deadline), cap_seconds)
    if timeout_seconds <= 0:
        raise RuntimeError(f"authoritative verification deadline exhausted before {phase}")
    return timeout_seconds


def _assert_deadline_remaining(deadline: float | None, phase: str) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise RuntimeError(f"authoritative verification deadline exhausted {phase}")


def _validated_verify_execution_budget(value: object) -> int:
    """Keep public receipt replay bounded even when invoked outside CI."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError("verification execution budget must be an integer")
    if not _MIN_VERIFY_EXECUTION_SECONDS <= value <= _MAX_VERIFY_EXECUTION_SECONDS:
        raise RuntimeError(
            "verification execution budget must be between "
            f"{_MIN_VERIFY_EXECUTION_SECONDS} and {_MAX_VERIFY_EXECUTION_SECONDS} seconds"
        )
    return value


def _verify_execution_budget_argument(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("verification execution budget must be an integer") from exc
    try:
        return _validated_verify_execution_budget(parsed)
    except RuntimeError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _git(*arguments: str, deadline: float | None = None):
    """Run a small source-state query with bounded, non-interactive Git state."""

    try:
        return run_bounded_stdout(
            _isolated_git_command(arguments),
            cwd=ROOT,
            environment=_git_environment(),
            timeout_seconds=_remaining_timeout(deadline, _GIT_TIMEOUT_SECONDS, "Git source query"),
            max_output_bytes=_MAX_GIT_OUTPUT_BYTES,
        )
    except GateRuntimeError:
        return None


def _revision(
    value: str | None,
    fallback: str | None = None,
    *,
    allow_zero: bool = False,
    deadline: float | None = None,
) -> str | None:
    candidate = value.strip() if value else (fallback or "HEAD")
    if candidate == ZERO_REVISION and allow_zero:
        return ZERO_REVISION
    # CRITICAL: never pass unvalidated caller text to Git; option-looking values
    # can otherwise become Git options even when shell=False.
    if value and not re.fullmatch(r"[0-9a-fA-F]{7,64}", candidate):
        return None
    completed = _git("rev-parse", "--verify", f"{candidate}^{{commit}}", deadline=deadline)
    if completed is None or completed.returncode != 0:
        return None
    try:
        resolved = completed.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        return None
    return resolved if _FULL_REVISION.fullmatch(resolved) else None


def _changed_paths(base: str | None, head: str, *, deadline: float | None = None) -> tuple[str, ...]:
    if (
        not base
        or base == ZERO_REVISION
        or not _FULL_REVISION.fullmatch(base)
        or not _FULL_REVISION.fullmatch(head)
    ):
        return ()
    completed = _git(
        "diff",
        "--name-status",
        "-z",
        "--no-renames",
        "--diff-filter=ACDMRTUXB",
        f"{base}..{head}",
        "--",
        deadline=deadline,
    )
    if completed is None or completed.returncode != 0:
        return ()
    tokens = completed.stdout.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    if len(tokens) % 2:
        return ()
    paths: list[str] = []
    try:
        for index in range(0, len(tokens), 2):
            status = tokens[index].decode("ascii")
            if len(status) != 1 or status not in _DIFF_STATUSES:
                return ()
            paths.append(tokens[index + 1].decode("utf-8", errors="strict"))
    except UnicodeDecodeError:
        return ()
    return tuple(paths)


@dataclass(frozen=True, slots=True)
class WorktreeState:
    kind: str
    entries: tuple[str, ...] = ()


def _worktree_state(*, deadline: float | None = None) -> WorktreeState:
    completed = _git("status", "--porcelain=v1", "-z", "--untracked-files=normal", deadline=deadline)
    if completed is None or completed.returncode != 0:
        return WorktreeState(kind="query_failed")
    if completed.stdout == b"":
        return WorktreeState(kind="clean")
    entries = tuple(
        raw.decode("utf-8", errors="backslashreplace")
        for raw in completed.stdout.split(b"\0")
        if raw
    )
    return WorktreeState(kind="dirty", entries=entries)


def _worktree_failure_summary(state: WorktreeState) -> str:
    if state.kind == "query_failed":
        return "git_source_state_query_failed"
    if state.kind == "clean":
        return "worktree_clean"
    prefix = f"worktree_dirty total={len(state.entries)} entries="
    encoded_entries: list[str] = []
    for entry in state.entries[:_MAX_WORKTREE_DIAGNOSTIC_ENTRIES]:
        candidate = json.dumps(entry, ensure_ascii=True)
        proposed = prefix + "[" + ",".join((*encoded_entries, candidate)) + "]"
        if len(proposed.encode("utf-8")) > _MAX_WORKTREE_DIAGNOSTIC_BYTES:
            break
        encoded_entries.append(candidate)
    return prefix + "[" + ",".join(encoded_entries) + "]"


def _worktree_is_clean(*, deadline: float | None = None) -> bool:
    return _worktree_state(deadline=deadline).kind == "clean"


def _request(
    args: argparse.Namespace,
    *,
    authoritative: bool = False,
    deadline: float | None = None,
) -> ChangeRequest:
    current_head = _revision(None, "HEAD", deadline=deadline)
    supplied_head = _revision(args.head, deadline=deadline) if args.head is not None else current_head
    if authoritative and (not current_head or supplied_head != current_head):
        raise RuntimeError("claimed head must resolve to the checked-out HEAD")
    head = supplied_head or (args.head.strip() if args.head else ZERO_REVISION)
    if args.base is not None and args.base.strip():
        resolved_base = _revision(args.base, allow_zero=True, deadline=deadline)
        if authoritative and resolved_base is None:
            raise RuntimeError("base revision must resolve before validation")
        base = resolved_base or args.base.strip()
    elif args.base is not None:
        # IMPORTANT: an explicitly empty CI base is a missing-base G2 claim;
        # resolving it as HEAD makes the producer disagree with `verify ... none`.
        base = None
    else:
        base = _revision(None, "HEAD^", deadline=deadline)
    paths = _changed_paths(base, head, deadline=deadline)
    asserted_paths = tuple(path.replace("\\", "/") for path in (args.changed_path or ()))
    if asserted_paths:
        trusted_revisions_available = bool(supplied_head and base)
        if trusted_revisions_available and tuple(sorted(asserted_paths, key=str.casefold)) != tuple(
            sorted(paths, key=str.casefold)
        ):
            raise RuntimeError("asserted changed paths do not match the trusted Git diff")
        if not trusted_revisions_available:
            asserted_paths = ()
    return ChangeRequest(
        base_revision=base,
        head_revision=head,
        changed_paths=paths,
        force_full=bool(args.force_full or getattr(args, "legacy_full", False)),
        ci_context=os.environ.get("GITHUB_EVENT_NAME") or "local",
    )


def _write_json(
    path: Path,
    payload: object,
    *,
    evidence_parent: EvidenceParentGuard | None = None,
) -> None:
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if evidence_parent is not None:
        if path.parent.absolute() != evidence_parent.parent.absolute():
            raise RuntimeError("authoritative receipt leaves the pinned evidence parent")
        evidence_parent.atomic_replace(path.name, encoded)
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        descriptor = None
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validated_authoritative_receipt_path(value: str, *, deadline: float | None = None) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    expected_parent = (ROOT / ".tmp/validation").absolute()
    target = candidate.absolute()
    if target.parent != expected_parent or target.suffix.casefold() != ".json":
        raise RuntimeError("authoritative receipt must be an immediate .tmp/validation JSON file")
    current = ROOT.absolute()
    for part in expected_parent.relative_to(current).parts:
        current = current / part
        if current.exists() or current.is_symlink():
            metadata = current.lstat()
            if current.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & 0x00000400):
                raise RuntimeError("authoritative receipt path contains a symlink or reparse point")
        else:
            current.mkdir()
    if target.exists() or target.is_symlink():
        metadata = target.lstat()
        if target.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("authoritative receipt target is not a regular file")
    ignored = _git(
        "check-ignore",
        "--quiet",
        "--",
        str(target.relative_to(ROOT)),
        deadline=deadline,
    )
    if ignored is None or ignored.returncode != 0:
        raise RuntimeError("authoritative receipt path must be ignored by Git")
    return target


def _validated_decision_receipt_path(value: str) -> Path:
    """Keep decision-only classifier output away from authoritative receipt names."""

    target = _validated_authoritative_receipt_path(value)
    name = target.name.casefold()
    if name != "decision.json" and not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}-decision\.json", name):
        raise RuntimeError("decision receipt must use the dedicated *-decision.json namespace")
    return target


def _validation_lease_path() -> Path:
    """Return the contained, ignored lock shared by authoritative full gates."""

    return validated_authoritative_validation_lease_path(ROOT)


def _prepare_authoritative_runtime(lease_capability: object, *, deadline: float | None = None) -> None:
    """Prepare canonical ignored scratch paths only while the writer lease is live."""

    try:
        _assert_deadline_remaining(deadline, "before runtime preparation")
        os.environ.update(_prepare_gate_runtime(ROOT, lease_capability=lease_capability))
        _assert_deadline_remaining(deadline, "during runtime preparation")
    except GateRuntimeError as exc:
        raise RuntimeError("authoritative validation runtime is unsafe") from exc


def _attest_active_project_venv() -> None:
    """Reject a direct host-Python launch before it can create validation state."""

    try:
        attest_active_project_venv(ROOT)
    except GateRuntimeError as exc:
        raise RuntimeError("authoritative validation requires the active project virtual environment") from exc


def _open_authoritative_evidence_parent(lease_capability: object) -> EvidenceParentGuard:
    """Pin the receipt parent for the complete leased stage/publication lifetime."""

    return EvidenceParentGuard.create(ROOT, lease_capability=lease_capability)


def _assert_selective_dependencies_ready() -> None:
    """Fail fast instead of silently consuming a G0/G1 feedback budget installing packages."""

    try:
        missing = tuple(module for module in _SELECTIVE_DEPENDENCY_MODULES if importlib.util.find_spec(module) is None)
    except (AttributeError, ImportError, ValueError) as exc:
        raise RuntimeError(
            "project_venv_dependencies_unavailable; run the explicit dependency provisioning command "
            "or G2 before G0/G1"
        ) from exc
    if missing:
        raise RuntimeError(
            "project_venv_dependencies_unavailable; run the explicit dependency provisioning command "
            "or G2 before G0/G1 "
            f"(missing: {', '.join(missing)})"
        )


def _bootstrap_validation_dependencies(
    lease_capability: object,
    timeout_seconds: int,
    deadline_monotonic: float | None = None,
) -> None:
    """Refresh locked Python dependencies only while an authoritative runner owns the lease."""

    from scripts.install_validation_dependencies import (
        DependencyInstallError,
        LOCKED_REQUIREMENTS,
        install_locked_dependencies,
    )

    try:
        install_locked_dependencies(
            LOCKED_REQUIREMENTS,
            lease_capability=lease_capability,
            timeout_seconds=timeout_seconds,
            deadline_monotonic=deadline_monotonic,
        )
    except DependencyInstallError as exc:
        raise RuntimeError("bounded locked dependency bootstrap failed") from exc


def _assert_reference_docs_only() -> None:
    reference = ROOT / "reference"
    if not reference.exists():
        return
    unexpected = sorted(entry.name for entry in reference.iterdir() if entry.name != "docs")
    if unexpected:
        raise RuntimeError(f"unexpected external reference entries: {', '.join(unexpected)}")


def _node_version(
    timeout_seconds: int = _TOOL_PREFLIGHT_TIMEOUT_SECONDS,
    *,
    deadline: float | None = None,
) -> str:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise RuntimeError("Node.js preflight has no remaining validation budget")
    timeout_seconds = _remaining_timeout(deadline, timeout_seconds, "Node.js preflight")
    try:
        completed = subprocess.run(
            ("node", "-v"),
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Node.js 18+ is required; install it before G1/G2 validation") from exc
    version = completed.stdout.strip()
    try:
        major = int(version.removeprefix("v").split(".", maxsplit=1)[0])
    except ValueError as exc:
        raise RuntimeError(f"cannot parse Node.js version: {version}") from exc
    if major < 18:
        raise RuntimeError(f"Node.js 18+ is required; found {version}")
    return version


def _environment(node_version: str | None) -> dict[str, str]:
    values = {
        "python": platform.python_version(),
        "platform": f"{platform.system().casefold()}-{platform.machine().casefold()}",
    }
    if node_version:
        values["node"] = node_version
    return values


def collect_artifact_digests(
    repository_root: Path,
    gate: str,
    *,
    succeeded: bool,
    deadline: float | None = None,
) -> dict[str, str]:
    if not succeeded or gate != "G2":
        return {}
    root = repository_root.resolve()
    total = 0
    digests: dict[str, str] = {}
    for name, (relative_path, maximum) in _ARTIFACT_SPECS.items():
        _assert_deadline_remaining(deadline, f"before artifact {name}")
        path = root / relative_path
        candidate = path
        while candidate != root:
            if candidate.is_symlink():
                raise RuntimeError(f"validation artifact is symlinked: {name}")
            if candidate.parent == candidate:
                raise RuntimeError(f"validation artifact escapes its approved root: {name}")
            candidate = candidate.parent
        try:
            pre_open = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError(f"required validation artifact is missing: {name}") from exc
        if (
            root not in resolved.parents
            or not stat.S_ISREG(pre_open.st_mode)
            or resolved != path.absolute()
        ):
            raise RuntimeError(f"validation artifact escapes its approved root: {name}")
        digest = hashlib.sha256()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise RuntimeError(f"validation artifact cannot be opened safely: {name}") from exc
        consumed = 0
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (pre_open.st_dev, pre_open.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_size > maximum
            ):
                raise RuntimeError(f"validation artifact changed or exceeds its size limit: {name}")
            # SECURITY: two descriptor-bound passes detect same-size in-place rewrites
            # even on filesystems whose timestamp granularity cannot expose the race.
            first_pass = hashlib.sha256()
            first_consumed = 0
            while True:
                _assert_deadline_remaining(deadline, f"while hashing artifact {name}")
                chunk = os.read(descriptor, min(1024 * 1024, maximum - first_consumed + 1))
                if not chunk:
                    break
                first_consumed += len(chunk)
                if first_consumed > maximum:
                    raise RuntimeError(f"validation artifact exceeds its size limit: {name}")
                first_pass.update(chunk)
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                while True:
                    _assert_deadline_remaining(deadline, f"while hashing artifact {name}")
                    chunk = handle.read(min(1024 * 1024, maximum - consumed + 1))
                    if not chunk:
                        break
                    consumed += len(chunk)
                    total += len(chunk)
                    if consumed > maximum:
                        raise RuntimeError(f"validation artifact exceeds its size limit: {name}")
                    if total > _MAX_ARTIFACT_TOTAL_BYTES:
                        raise RuntimeError("validation artifacts exceed the total size limit")
                    digest.update(chunk)
            post_read = os.fstat(descriptor)
            if (
                (opened.st_dev, opened.st_ino) != (post_read.st_dev, post_read.st_ino)
                or first_consumed != consumed
                or first_pass.digest() != digest.digest()
                or post_read.st_size != consumed
                or (opened.st_mtime_ns, opened.st_ctime_ns) != (post_read.st_mtime_ns, post_read.st_ctime_ns)
            ):
                raise RuntimeError(f"validation artifact changed while hashing: {name}")
        finally:
            os.close(descriptor)
        _assert_deadline_remaining(deadline, f"after artifact {name}")
        digests[name] = digest.hexdigest()
    return digests


def _github_output(path: str | None, gate: str, digest: str) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(f"gate={gate}\n")
        handle.write(f"decision_digest={digest}\n")


def classify_command(args: argparse.Namespace) -> int:
    decision_path = _validated_decision_receipt_path(args.receipt)
    # IMPORTANT: classification is a decision-only child process used by G2 tests.
    # Only full-gate writers take the workspace lease; otherwise G2 self-deadlocks.
    request = _request(args)
    decision = classify_change(request)
    evidence = decision_evidence_payload(decision)
    payload = {
        "schema_version": "2",
        "base_revision": request.base_revision,
        "source_revision": request.head_revision,
        "selected_gate": decision.selected_gate,
        "decision_digest": decision.decision_digest,
        "decision": {
            "planes": decision.planes,
            "reasons": decision.reasons,
            "changed_path_count": evidence["changed_path_count"],
            "changed_path_digest": evidence["changed_path_digest"],
        },
    }
    _write_json(decision_path, payload)
    _validated_decision_receipt_path(args.receipt)
    _github_output(args.github_output, decision.selected_gate, decision.decision_digest)
    print(decision.selected_gate)
    return 0


def _authoritative_selection(
    args: argparse.Namespace,
    *,
    deadline: float | None = None,
) -> tuple[ChangeRequest, GateDecision, str]:
    request = _request(args, authoritative=True, deadline=deadline)
    decision = classify_change(request)
    selected_gate = args.gate or decision.selected_gate
    if args.gate and args.gate != decision.selected_gate and not args.force_full:
        raise RuntimeError(
            f"requested gate {args.gate} does not match classifier decision {decision.selected_gate}"
        )
    if args.force_full:
        selected_gate = "G2"
        decision = classify_change(replace(request, force_full=True))

    return request, decision, selected_gate


def _run_command_locked(
    args: argparse.Namespace,
    receipt_path: Path,
    *,
    request: ChangeRequest | None = None,
    decision: GateDecision | None = None,
    selected_gate: str | None = None,
    node_version: str | None = None,
    deadline: float | None = None,
    evidence_parent: EvidenceParentGuard | None = None,
) -> int:
    if request is None or decision is None or selected_gate is None:
        request, decision, selected_gate = _authoritative_selection(args, deadline=deadline)

    if selected_gate in {"G1", "G2"} and node_version is None:
        node_version = _node_version(deadline=deadline)
    stages = build_default_registry(ROOT).plan_ids(decision.required_stage_ids)
    if selected_gate in {"G0", "G1"}:
        if not decision.normalized_paths:
            raise RuntimeError("selective validation requires classifier-normalized changed paths")
        stages = tuple(
            replace(stage, argv=(*stage.argv, *decision.normalized_paths))
            if stage.id == "changed-file-hooks"
            else stage
            for stage in stages
        )

    inherited_environment = dict(os.environ)
    results: list[StageResult] = []
    failed = False
    for stage in stages:
        if failed:
            skipped_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            results.append(
                StageResult(stage.id, "skipped", None, 0, stage.argv, skipped_at, skipped_at)
            )
            continue
        executable_stage = stage
        if deadline is not None:
            timeout_seconds = bounded_timeout(deadline, stage.timeout_seconds)
            if timeout_seconds <= 0:
                timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                results.append(
                    StageResult(stage.id, "timed_out", None, 0, stage.argv, timestamp, timestamp)
                )
                if evidence_parent is not None:
                    evidence_parent.assert_intact()
                print(f"[timed_out] {stage.id} (authoritative deadline exhausted)", flush=True)
                failed = True
                continue
            executable_stage = replace(stage, timeout_seconds=timeout_seconds)
        print(
            f"[started] {executable_stage.id} (timeout {executable_stage.timeout_seconds}s)",
            flush=True,
        )
        runner = StageRunner(
            ROOT,
            inherited_environment=inherited_environment,
            fixed_environment=_GIT_ENVIRONMENT,
        )
        # CRITICAL: clipping the declared stage timeout alone leaves process
        # startup, descendant cleanup, and stream draining outside the gate's
        # absolute deadline.  StageRunner owns those operations, so it must
        # receive the same deadline rather than a derived timeout only.
        result = (
            runner.run(executable_stage)
            if deadline is None
            else runner.run(executable_stage, deadline_monotonic=deadline)
        )
        results.append(result)
        if evidence_parent is not None:
            evidence_parent.assert_intact()
        if stage.id == "local-stack" and result.status == "passed":
            database_url_file = ROOT / ".local/redagent/runtime/database-url"
            if not database_url_file.is_file():
                result = replace(result, status="failed", exit_code=None)
                results[-1] = result
            else:
                inherited_environment["REDAGENT_DATABASE_URL_FILE"] = str(database_url_file)
        print(f"[{result.status}] {stage.id} ({result.duration_ms} ms)", flush=True)
        failed = result.status != "passed"

    # CRITICAL: a stage that changes executable source invalidates every result
    # bound to the pre-run commit, even when the stage itself exits zero.
    if not _worktree_is_clean(deadline=deadline) or _revision(
        None,
        "HEAD",
        deadline=deadline,
    ) != request.head_revision:
        raise RuntimeError("authoritative source changed during validation")

    receipt = build_verification_receipt(
        decision=decision,
        base_revision=request.base_revision,
        source_revision=request.head_revision,
        force_full=request.force_full,
        stage_results=results,
        environment=_environment(node_version),
        artifact_digests=collect_artifact_digests(
            ROOT,
            selected_gate,
            succeeded=not failed,
            deadline=deadline,
        ),
        # CRITICAL: receipt construction must not renew the authoritative gate
        # budget through an unbounded configuration-source hash.
        configuration_digests=current_configuration_digests(deadline_monotonic=deadline),
        ci_context=request.ci_context or "local",
        validation_mode=(
            "legacy_full" if getattr(args, "legacy_full", False) else "risk_proportional"
        ),
    )
    if evidence_parent is not None:
        evidence_parent.assert_intact()
    receipt_path = _validated_authoritative_receipt_path(args.receipt, deadline=deadline)
    _write_json(receipt_path, receipt, evidence_parent=evidence_parent)
    receipt_path = _validated_authoritative_receipt_path(args.receipt, deadline=deadline)
    if evidence_parent is not None:
        evidence_parent.assert_intact()
    if not _worktree_is_clean(deadline=deadline) or _revision(
        None,
        "HEAD",
        deadline=deadline,
    ) != request.head_revision:
        raise RuntimeError("authoritative source changed after receipt publication")
    return 1 if failed else 0


def run_command(args: argparse.Namespace) -> int:
    _assert_reference_docs_only()
    if not _worktree_is_clean():
        detail = _worktree_failure_summary(_worktree_state())
        raise RuntimeError(
            "authoritative validation requires a clean worktree, including non-ignored "
            f"untracked files; {detail}"
        )
    with ValidationLease(_validation_lease_path()) as lease:
        # CRITICAL: another writer can finish after the first preflight; never plan stages on that changed source.
        capability = lease.capability()
        # Start with the closed G2 ceiling before source selection.  The final
        # selected-gate ceiling is anchored to this same instant below, so Git
        # classification cannot create an unbounded prefix or renew the budget.
        gate_started = time.monotonic()
        deadline = gate_started + budget_seconds("G2")
        _attest_active_project_venv()
        bind_authoritative_validation_platform(ROOT, capability)
        if not _worktree_is_clean(deadline=deadline):
            detail = _worktree_failure_summary(_worktree_state(deadline=deadline))
            raise RuntimeError(
                "authoritative validation requires a clean worktree, including non-ignored "
                f"untracked files; {detail}"
            )
        request, decision, selected_gate = _authoritative_selection(args, deadline=deadline)
        deadline = min(deadline, gate_started + budget_seconds(selected_gate))
        _assert_deadline_remaining(deadline, "after source selection")
        # Fail invalid Node installations before any mutable runtime/bootstrap action.
        node_timeout = bounded_timeout(deadline, _TOOL_PREFLIGHT_TIMEOUT_SECONDS)
        node_version = (
            _node_version(node_timeout, deadline=deadline)
            if selected_gate in {"G1", "G2"}
            else None
        )
        if selected_gate in {"G0", "G1"}:
            _assert_selective_dependencies_ready()
        with _open_authoritative_evidence_parent(capability) as evidence_parent:
            _prepare_authoritative_runtime(capability, deadline=deadline)
            if not _worktree_is_clean(deadline=deadline) or _revision(
                None,
                "HEAD",
                deadline=deadline,
            ) != request.head_revision:
                raise RuntimeError("authoritative source changed during runtime preparation")
            needs_bootstrap = selected_gate == "G2"
            if needs_bootstrap:
                bootstrap_timeout = bounded_timeout(deadline, 900)
                if bootstrap_timeout <= 0:
                    raise RuntimeError("authoritative validation deadline exhausted before dependency bootstrap")
                _bootstrap_validation_dependencies(capability, bootstrap_timeout, deadline)
            receipt_path = _validated_authoritative_receipt_path(args.receipt, deadline=deadline)
            # CRITICAL: mutable runtime preparation and G2 bootstrap cannot inherit a changed source.
            if not _worktree_is_clean(deadline=deadline) or _revision(
                None,
                "HEAD",
                deadline=deadline,
            ) != request.head_revision:
                phase = "dependency bootstrap" if needs_bootstrap else "runtime preparation"
                raise RuntimeError(f"authoritative source changed during {phase}")
            return _run_command_locked(
                args,
                receipt_path,
                request=request,
                decision=decision,
                selected_gate=selected_gate,
                node_version=node_version,
                deadline=deadline,
                evidence_parent=evidence_parent,
            )


def provision_command(_args: argparse.Namespace) -> int:
    """Explicitly prepare project dependencies; this is not validation or evidence."""

    _assert_reference_docs_only()
    if not _worktree_is_clean():
        raise RuntimeError("validation provisioning requires a clean worktree")
    with ValidationLease(_validation_lease_path()) as lease:
        capability = lease.capability()
        _attest_active_project_venv()
        bind_authoritative_validation_platform(ROOT, capability)
        if not _worktree_is_clean():
            raise RuntimeError("validation provisioning requires a clean worktree")
        with _open_authoritative_evidence_parent(capability):
            _prepare_authoritative_runtime(capability)
            if not _worktree_is_clean():
                raise RuntimeError("validation source changed during runtime preparation")
            _bootstrap_validation_dependencies(capability, 900)
        if not _worktree_is_clean():
            raise RuntimeError("validation source changed during dependency provisioning")
    print("validation dependencies provisioned; no validation receipt was issued", flush=True)
    return 0


def aggregate_command(args: argparse.Namespace) -> int:
    selected = args.selected.casefold()
    results = {
        "g0": args.g0_result.casefold(),
        "g1": args.g1_result.casefold(),
        "g2": args.g2_result.casefold(),
    }
    if args.classify_result.casefold() != "success":
        return 1
    if results.get(selected) != "success":
        return 1
    return 0 if all(
        result == ("success" if gate == selected else "skipped")
        for gate, result in results.items()
    ) else 1


def benchmark_command(args: argparse.Namespace) -> int:
    """Run a selective timing fixture without producing acceptance evidence."""

    if args.gate == "G2":
        raise RuntimeError("G2 must use the authoritative run command")
    if not _worktree_is_clean():
        raise RuntimeError("benchmark requires a clean worktree")
    source_revision = _revision(None, "HEAD")
    if not source_revision:
        raise RuntimeError("benchmark source revision cannot be resolved")
    request = ChangeRequest(
        base_revision=source_revision,
        head_revision=source_revision,
        changed_paths=tuple(args.changed_path),
        force_full=False,
        ci_context="benchmark",
    )
    decision = classify_change(request)
    if decision.selected_gate != args.gate:
        raise RuntimeError(
            f"benchmark fixture selects {decision.selected_gate}, not requested {args.gate}"
        )
    node_version = _node_version() if args.gate == "G1" else None
    del node_version
    stages = build_default_registry(ROOT).plan_ids(decision.required_stage_ids)
    stages = tuple(
        replace(stage, argv=(*stage.argv, *decision.normalized_paths))
        if stage.id == "changed-file-hooks"
        else stage
        for stage in stages
    )
    started = datetime.now(timezone.utc)
    for stage in stages:
        result = StageRunner(ROOT, inherited_environment=dict(os.environ)).run(stage)
        print(f"[{result.status}] {stage.id} ({result.duration_ms} ms)", flush=True)
        if result.status != "passed":
            return 1
    if not _worktree_is_clean() or _revision(None, "HEAD") != source_revision:
        raise RuntimeError("benchmark source changed during execution")
    duration_ms = round((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    print(
        "NON_AUTHORITATIVE_BENCHMARK "
        f"gate={args.gate} source={source_revision} duration_ms={duration_ms} "
        f"stages={','.join(stage.id for stage in stages)}"
    )
    return 0


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"verification receipt contains duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise RuntimeError(f"verification receipt contains non-standard JSON value: {value}")


def _load_bounded_json(path: Path, *, deadline: float | None = None) -> object:
    _assert_deadline_remaining(deadline, "before receipt read")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("verification receipt cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size > 1024 * 1024
        ):
            raise RuntimeError("verification receipt size or identity is invalid")
        content = bytearray()
        while True:
            _assert_deadline_remaining(deadline, "while reading receipt")
            chunk = os.read(descriptor, min(65536, 1024 * 1024 - len(content) + 1))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > 1024 * 1024:
                raise RuntimeError("verification receipt size exceeds the 1 MiB limit")
        after = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
            != (after.st_dev, after.st_ino, len(content), after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise RuntimeError("verification receipt changed while reading")
    finally:
        os.close(descriptor)
    try:
        decoded = json.loads(
            bytes(content).decode("utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("verification receipt is not valid UTF-8 JSON") from exc
    _assert_deadline_remaining(deadline, "after receipt read")
    return decoded


def verify_command(args: argparse.Namespace) -> int:
    execution_budget = _validated_verify_execution_budget(
        getattr(args, "max_execution_seconds", DEFAULT_VERIFY_EXECUTION_SECONDS)
    )
    deadline = time.monotonic() + execution_budget
    _assert_deadline_remaining(deadline, "before public receipt verification")
    receipt_path = Path(args.receipt)
    payload = _load_bounded_json(receipt_path, deadline=deadline)
    if not isinstance(payload, dict):
        raise RuntimeError("verification receipt root must be an object")
    _assert_deadline_remaining(deadline, "after receipt read")
    if not _worktree_is_clean(deadline=deadline):
        raise RuntimeError("authoritative verification requires a clean worktree")
    resolved_source = _revision(args.source_revision, deadline=deadline)
    resolved_base = (
        None
        if args.base_revision.casefold() == "none"
        else _revision(args.base_revision, allow_zero=True, deadline=deadline)
    )
    current_head = _revision(None, "HEAD", deadline=deadline)
    if not resolved_source or (
        resolved_base is None and args.base_revision.casefold() != "none"
    ):
        raise RuntimeError("trusted source/base revisions must resolve or use zero/none")
    if current_head != resolved_source:
        raise RuntimeError("trusted source revision must equal the clean checked-out HEAD")
    expected_force_full = args.expected_force_full == "true"
    succeeded = payload.get("aggregate_result") == "passed"
    expected_artifacts = collect_artifact_digests(
        ROOT,
        args.expected_gate,
        succeeded=succeeded,
        deadline=deadline,
    )
    _assert_deadline_remaining(deadline, "before receipt verification")
    verify_verification_receipt(
        payload,
        expected_source_revision=resolved_source,
        expected_base_revision=resolved_base,
        expected_configuration_digests=current_configuration_digests(deadline_monotonic=deadline),
        expected_artifact_digests=expected_artifacts,
        expected_changed_paths=_changed_paths(resolved_base, resolved_source, deadline=deadline),
        expected_force_full=expected_force_full,
        expected_gate=args.expected_gate,
        expected_ci_context=args.expected_ci_context,
        expected_validation_mode=args.expected_mode,
        expected_environment=_environment(
            _node_version(deadline=deadline) if args.expected_gate in {"G1", "G2"} else None
        ),
    )
    # CRITICAL: the pure receipt verifier is bounded by the 1 MiB receipt cap,
    # but its return boundary must still not permit another Git preflight after expiry.
    _assert_deadline_remaining(deadline, "after receipt verification")
    if not _worktree_is_clean(deadline=deadline) or _revision(None, "HEAD", deadline=deadline) != resolved_source:
        raise RuntimeError("authoritative source changed during verification")
    print("authoritative verification receipt accepted")
    return 0


def _change_arguments(
    parser: argparse.ArgumentParser,
    *,
    receipt_default: Path = DEFAULT_RECEIPT,
) -> None:
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--changed-path", action="append")
    parser.add_argument("--force-full", action="store_true")
    parser.add_argument("--receipt", default=str(receipt_default))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic R118 repository validation")
    commands = parser.add_subparsers(dest="command", required=True)
    classify_parser = commands.add_parser("classify")
    _change_arguments(classify_parser, receipt_default=DEFAULT_DECISION_RECEIPT)
    classify_parser.add_argument("--github-output")
    classify_parser.set_defaults(handler=classify_command)

    run_parser = commands.add_parser("run")
    _change_arguments(run_parser)
    run_parser.add_argument("--gate", choices=("G0", "G1", "G2"))
    run_parser.add_argument("--legacy-full", action="store_true")
    run_parser.set_defaults(handler=run_command)

    provision_parser = commands.add_parser("provision")
    provision_parser.set_defaults(handler=provision_command)

    aggregate_parser = commands.add_parser("aggregate")
    aggregate_parser.add_argument("--selected", choices=("G0", "G1", "G2"), required=True)
    aggregate_parser.add_argument("--classify-result", required=True)
    aggregate_parser.add_argument("--g0-result", required=True)
    aggregate_parser.add_argument("--g1-result", required=True)
    aggregate_parser.add_argument("--g2-result", required=True)
    aggregate_parser.set_defaults(handler=aggregate_command)

    benchmark_parser = commands.add_parser("benchmark")
    benchmark_parser.add_argument("--gate", choices=("G0", "G1"), required=True)
    benchmark_parser.add_argument("--changed-path", action="append", required=True)
    benchmark_parser.set_defaults(handler=benchmark_command)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--receipt", required=True)
    verify_parser.add_argument("--source-revision", required=True)
    verify_parser.add_argument("--base-revision", required=True)
    verify_parser.add_argument("--expected-gate", choices=("G0", "G1", "G2"), required=True)
    verify_parser.add_argument("--expected-force-full", choices=("true", "false"), required=True)
    verify_parser.add_argument("--expected-ci-context", required=True)
    verify_parser.add_argument(
        "--expected-mode",
        choices=("risk_proportional", "legacy_full"),
        required=True,
    )
    verify_parser.add_argument(
        "--max-execution-seconds",
        default=DEFAULT_VERIFY_EXECUTION_SECONDS,
        type=_verify_execution_budget_argument,
        help=(
            "maximum total public receipt-verification time "
            f"({_MIN_VERIFY_EXECUTION_SECONDS}-{_MAX_VERIFY_EXECUTION_SECONDS} seconds)"
        ),
    )
    verify_parser.set_defaults(handler=verify_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (ReceiptVerificationError, RuntimeError, ValidationConfigError) as exc:
        print(f"validation gate failed closed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
