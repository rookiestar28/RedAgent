from __future__ import annotations

from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Mapping, Sequence

from redagent_platform.validation.classifier import (
    ChangeRequest,
    GateDecision,
    classify_change,
    decision_evidence_payload,
)
from redagent_platform.validation.stages import (
    DEFAULT_STAGE_CONTRACT,
    STAGE_REGISTRY_REVISION,
    StageResult,
)


# IMPORTANT: v2 removes raw changed paths from retained evidence and binds them
# by count and digest instead; do not accept v1 receipts under this contract.
SCHEMA_VERSION = "2"
MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_CONFIGURATION_SOURCE_BYTES = 1024 * 1024
_CONFIGURATION_READ_CHUNK_BYTES = 64 * 1024
_REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL = {"passed", "failed", "timed_out", "skipped"}
_FORBIDDEN_KEY_PARTS = ("secret", "token", "cookie", "credential", "password", "database_url")
_RECEIPT_KEYS = {
    "schema_version",
    "base_revision",
    "source_revision",
    "force_full",
    "ci_context",
    "validation_mode",
    "stage_registry_revision",
    "decision",
    "environment",
    "stages",
    "artifact_digests",
    "configuration_digests",
    "aggregate_result",
    "receipt_digest",
}
_DECISION_KEYS = {
    "classifier_revision",
    "selected_gate",
    "planes",
    "changed_path_count",
    "reasons",
    "required_stage_ids",
    "skipped_stage_ids",
    "changed_path_digest",
    "decision_digest",
}
_ENVIRONMENT_KEYS = {"python", "platform", "node"}
_CONFIGURATION_KEYS = {
    "agent_skills_script",
    "classifier",
    "config_loader",
    "dependency_bootstrap_script",
    "dev_lock",
    "gate_deadline",
    "gate_workflow",
    "gate_runtime",
    "local_stack_script",
    "openbao_script",
    "opa_script",
    "package_lock",
    "package_manifest",
    "path_mapping",
    "pre_commit_config",
    "receipt_verifier",
    "runtime_lock",
    "secure_sdlc_script",
    "stage_registry",
    "stage_runner",
    "validation_lease",
    "validation_runner",
    "validation_workflow",
    "venv_boundary_script",
    "venv_preparation_script",
    "posix_venv_layout_script",
    "windows_wrapper",
    "linux_wrapper",
    "legacy_runner",
}
_ARTIFACT_KEYS = {"secure_sdlc_sbom", "frontend_index", "frontend_cli", "openapi_contract"}
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_PYTHON_VERSION = re.compile(r"^\d{1,2}\.\d{1,2}\.\d{1,3}(?:[a-z0-9.+-]{0,32})?$")
_NODE_VERSION = re.compile(r"^v?\d{1,3}\.\d{1,3}\.\d{1,3}(?:[a-z0-9.+-]{0,32})?$")
_PLATFORM = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_CONTEXT = re.compile(r"^[a-z0-9_-]{1,64}$")
_FORBIDDEN_VALUE = re.compile(
    r"(?i)(?:^|[/\\\s])(?:[a-z0-9]+[_-])*(?:secret[_-]?access[_-]?key|"
    r"access[_-]?key[_-]?id|api[_-]?(?:key|token)|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|session[_-]?id|authorization|token|"
    r"secret|password|credential|cookie|database[_-]?url)\s*[:=]"
)


class ReceiptVerificationError(ValueError):
    """Raised when verification evidence is malformed, unsafe, or inconsistent."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest_without_binding(receipt: Mapping[str, object]) -> str:
    content = dict(receipt)
    content.pop("receipt_digest", None)
    return hashlib.sha256(_canonical_bytes(content)).hexdigest()


def _contains_forbidden_key(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).casefold()
            if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
                return True
            if _contains_forbidden_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _contains_forbidden_value(value: object) -> bool:
    if isinstance(value, dict):
        return any(_contains_forbidden_value(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_forbidden_value(item) for item in value)
    return isinstance(value, str) and _FORBIDDEN_VALUE.search(value) is not None


def build_verification_receipt(
    *,
    decision: GateDecision,
    base_revision: str | None,
    source_revision: str,
    force_full: bool,
    stage_results: Sequence[StageResult],
    environment: Mapping[str, str],
    artifact_digests: Mapping[str, str],
    configuration_digests: Mapping[str, str] | None = None,
    ci_context: str = "local",
    validation_mode: str = "risk_proportional",
) -> dict[str, object]:
    if _contains_forbidden_key(dict(environment)) or _contains_forbidden_value(dict(environment)):
        raise ReceiptVerificationError("environment contains a forbidden field or value")
    stages = [
        {
            "stage_id": result.stage_id,
            "status": result.status,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "argv": list(result.argv),
            "started_at": result.started_at,
            "ended_at": result.ended_at,
        }
        for result in stage_results
    ]
    active_configuration = dict(configuration_digests or current_configuration_digests())
    active_artifacts = dict(artifact_digests)
    receipt: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "base_revision": base_revision,
        "source_revision": source_revision,
        "force_full": force_full,
        "ci_context": ci_context,
        "validation_mode": validation_mode,
        "stage_registry_revision": STAGE_REGISTRY_REVISION,
        "decision": decision_evidence_payload(decision),
        "environment": dict(sorted(environment.items())),
        "stages": stages,
        "artifact_digests": dict(sorted(active_artifacts.items())),
        "configuration_digests": dict(sorted(active_configuration.items())),
        "aggregate_result": "passed" if stages and all(stage["status"] == "passed" for stage in stages) else "failed",
    }
    receipt["receipt_digest"] = _digest_without_binding(receipt)
    verify_verification_receipt(
        receipt,
        expected_source_revision=source_revision,
        expected_base_revision=base_revision,
        expected_configuration_digests=active_configuration,
        expected_artifact_digests=active_artifacts,
        expected_changed_paths=decision.normalized_paths,
        expected_force_full=force_full,
        expected_gate=decision.selected_gate,
        expected_ci_context=ci_context,
        expected_validation_mode=validation_mode,
        expected_environment=environment,
    )
    return receipt


def verify_verification_receipt(
    receipt: Mapping[str, object],
    *,
    expected_source_revision: str,
    expected_base_revision: str | None,
    expected_configuration_digests: Mapping[str, str],
    expected_artifact_digests: Mapping[str, str],
    expected_changed_paths: Sequence[str],
    expected_force_full: bool,
    expected_gate: str,
    expected_ci_context: str,
    expected_validation_mode: str,
    expected_environment: Mapping[str, str],
) -> None:
    try:
        encoded = _canonical_bytes(receipt)
    except (TypeError, ValueError) as exc:
        raise ReceiptVerificationError("receipt is not canonical JSON") from exc
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ReceiptVerificationError("receipt size exceeds the 1 MiB limit")
    if _contains_forbidden_key(dict(receipt)):
        raise ReceiptVerificationError("receipt contains a forbidden field or value")
    if _contains_forbidden_value(receipt.get("environment")):
        raise ReceiptVerificationError("environment contains a forbidden value")
    if _contains_forbidden_value(dict(receipt)):
        raise ReceiptVerificationError("receipt contains a forbidden field or value")
    if set(receipt) != _RECEIPT_KEYS:
        raise ReceiptVerificationError("receipt has unknown or missing fields")
    if receipt.get("schema_version") != SCHEMA_VERSION:
        raise ReceiptVerificationError("receipt schema version is unsupported")
    base_revision = receipt.get("base_revision")
    if base_revision is not None and (
        not isinstance(base_revision, str) or not _REVISION.fullmatch(base_revision)
    ):
        raise ReceiptVerificationError("base revision is invalid")
    if base_revision != expected_base_revision:
        raise ReceiptVerificationError("base revision does not match expected base revision")
    if receipt.get("source_revision") != expected_source_revision:
        raise ReceiptVerificationError("source revision does not match expected source revision")
    if not _REVISION.fullmatch(expected_source_revision):
        raise ReceiptVerificationError("source revision is invalid")
    force_full = receipt.get("force_full")
    if not isinstance(force_full, bool):
        raise ReceiptVerificationError("force_full is invalid")
    if force_full is not expected_force_full:
        raise ReceiptVerificationError("force_full does not match expected validation context")
    ci_context = receipt.get("ci_context")
    validation_mode = receipt.get("validation_mode")
    if not isinstance(ci_context, str) or not _CONTEXT.fullmatch(ci_context):
        raise ReceiptVerificationError("CI context is invalid")
    if validation_mode not in {"risk_proportional", "legacy_full"}:
        raise ReceiptVerificationError("validation mode is invalid")
    if ci_context != expected_ci_context:
        raise ReceiptVerificationError("CI context does not match expected validation context")
    if validation_mode != expected_validation_mode:
        raise ReceiptVerificationError("validation mode does not match expected validation context")
    if receipt.get("stage_registry_revision") != STAGE_REGISTRY_REVISION:
        raise ReceiptVerificationError("stage registry revision is unsupported")
    supplied_digest = receipt.get("receipt_digest")
    if not isinstance(supplied_digest, str) or not _DIGEST.fullmatch(supplied_digest):
        raise ReceiptVerificationError("receipt digest is invalid")
    expected_digest = _digest_without_binding(receipt)
    if not hmac.compare_digest(supplied_digest, expected_digest):
        raise ReceiptVerificationError("receipt digest does not match content")

    decision = receipt.get("decision")
    if not isinstance(decision, dict) or set(decision) != _DECISION_KEYS:
        raise ReceiptVerificationError("decision is invalid")
    decision_digest = decision.get("decision_digest")
    decision_content = dict(decision)
    decision_content.pop("decision_digest", None)
    recomputed_decision = hashlib.sha256(_canonical_bytes(decision_content)).hexdigest()
    if not isinstance(decision_digest, str) or not hmac.compare_digest(decision_digest, recomputed_decision):
        raise ReceiptVerificationError("decision digest does not match decision content")
    changed_path_count = decision.get("changed_path_count")
    changed_path_digest = decision.get("changed_path_digest")
    if (
        not isinstance(changed_path_count, int)
        or isinstance(changed_path_count, bool)
        or not 0 <= changed_path_count <= 2**31 - 1
    ):
        raise ReceiptVerificationError("decision changed path count is invalid")
    expected_paths = tuple(sorted(expected_changed_paths, key=str.casefold))
    recomputed_paths = hashlib.sha256(_canonical_bytes(expected_paths)).hexdigest()
    if changed_path_count != len(expected_paths):
        raise ReceiptVerificationError("decision path count does not match trusted Git diff")
    if not isinstance(changed_path_digest, str) or not hmac.compare_digest(changed_path_digest, recomputed_paths):
        raise ReceiptVerificationError("changed path digest does not match trusted Git diff")
    for list_key in ("planes", "reasons", "required_stage_ids", "skipped_stage_ids"):
        value = decision.get(list_key)
        if (
            not isinstance(value, (list, tuple))
            or len(value) > 64
            or any(not isinstance(item, str) or not item or len(item) > 128 for item in value)
        ):
            raise ReceiptVerificationError(f"decision {list_key} is invalid")
    if decision.get("selected_gate") not in {"G0", "G1", "G2"}:
        raise ReceiptVerificationError("decision selected gate is invalid")
    if decision.get("selected_gate") != expected_gate:
        raise ReceiptVerificationError("decision gate does not match expected validation context")
    if validation_mode == "legacy_full" and (
        not force_full or decision.get("selected_gate") != "G2"
    ):
        raise ReceiptVerificationError("legacy_full evidence requires force_full G2 validation")
    if not isinstance(decision.get("classifier_revision"), str) or len(decision["classifier_revision"]) > 128:
        raise ReceiptVerificationError("classifier revision is invalid")

    semantic_decision = classify_change(
        ChangeRequest(
            base_revision=base_revision,
            head_revision=expected_source_revision,
            changed_paths=expected_paths,
            force_full=force_full,
        )
    )
    semantic_payload = decision_evidence_payload(semantic_decision)
    if _canonical_bytes(decision) != _canonical_bytes(semantic_payload):
        raise ReceiptVerificationError("decision does not match semantic classifier result")

    stages = receipt.get("stages")
    if not isinstance(stages, list) or not stages:
        raise ReceiptVerificationError("receipt must contain terminal stages")
    seen: set[str] = set()
    statuses: list[str] = []
    exact_commands = {stage.id: stage.argv for stage in DEFAULT_STAGE_CONTRACT}
    for stage in stages:
        if not isinstance(stage, dict) or set(stage) != {
            "stage_id",
            "status",
            "exit_code",
            "duration_ms",
            "argv",
            "started_at",
            "ended_at",
        }:
            raise ReceiptVerificationError("stage entry is invalid")
        stage_id = stage.get("stage_id")
        status = stage.get("status")
        if not isinstance(stage_id, str) or stage_id in seen:
            raise ReceiptVerificationError("stage IDs must be unique")
        if status not in _TERMINAL:
            raise ReceiptVerificationError("stage status must be terminal")
        exit_code = stage.get("exit_code")
        if exit_code is not None and (
            not isinstance(exit_code, int)
            or isinstance(exit_code, bool)
            or not -(2**31) <= exit_code <= 2**31 - 1
        ):
            raise ReceiptVerificationError("stage exit code is invalid")
        if (
            (status == "passed" and exit_code != 0)
            or (status == "failed" and exit_code == 0)
            or (status in {"timed_out", "skipped"} and exit_code is not None)
        ):
            raise ReceiptVerificationError("stage status and exit code are inconsistent")
        seen.add(stage_id)
        statuses.append(status)
        if (
            not isinstance(stage.get("started_at"), str)
            or not isinstance(stage.get("ended_at"), str)
            or not _UTC_TIMESTAMP.fullmatch(stage["started_at"])
            or not _UTC_TIMESTAMP.fullmatch(stage["ended_at"])
        ):
            raise ReceiptVerificationError("stage timing is invalid")
        try:
            started = datetime.fromisoformat(stage["started_at"].replace("Z", "+00:00"))
            ended = datetime.fromisoformat(stage["ended_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReceiptVerificationError("stage timing is invalid") from exc
        if ended < started:
            raise ReceiptVerificationError("stage timing is invalid")
        argv = stage.get("argv")
        if (
            not isinstance(argv, list)
            or len(argv) > 64
            or any(not isinstance(item, str) or not item or len(item) > 4096 for item in argv)
        ):
            raise ReceiptVerificationError("stage argv is invalid")
        expected_argv = exact_commands.get(stage_id)
        if stage_id == "changed-file-hooks" and expected_argv is not None:
            expected_argv = (*expected_argv, *semantic_decision.normalized_paths)
        if expected_argv is None or tuple(argv) != expected_argv:
            raise ReceiptVerificationError("stage argv does not match exact stage contract")
        duration = stage.get("duration_ms")
        if (
            not isinstance(duration, int)
            or isinstance(duration, bool)
            or duration < 0
            or duration > 86_400_000
            or abs((ended - started).total_seconds() * 1000 - duration) > 60_000
        ):
            raise ReceiptVerificationError("stage duration is invalid")

    required_stage_ids = decision.get("required_stage_ids")
    if (
        not isinstance(required_stage_ids, (list, tuple))
        or tuple(required_stage_ids) != tuple(stage["stage_id"] for stage in stages)
        or set(required_stage_ids) != seen
    ):
        raise ReceiptVerificationError("required stage terminal results are incomplete or unexpected")

    aggregate = receipt.get("aggregate_result")
    expected_aggregate = "passed" if all(status == "passed" for status in statuses) else "failed"
    if aggregate != expected_aggregate:
        raise ReceiptVerificationError("aggregate result is inconsistent")

    artifacts = receipt.get("artifact_digests")
    if (
        not isinstance(artifacts, dict)
        or not set(artifacts) <= _ARTIFACT_KEYS
        or any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in artifacts.values())
    ):
        raise ReceiptVerificationError("artifact digest is invalid")
    if dict(artifacts) != dict(expected_artifact_digests):
        raise ReceiptVerificationError("artifact digest does not match current artifacts")
    configuration = receipt.get("configuration_digests")
    if (
        not isinstance(configuration, dict)
        or set(configuration) != _CONFIGURATION_KEYS
    ):
        raise ReceiptVerificationError("configuration digests are incomplete")
    if any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in configuration.values()):
        raise ReceiptVerificationError("configuration digest is invalid")
    if dict(configuration) != dict(expected_configuration_digests):
        raise ReceiptVerificationError("configuration digest does not match current configuration")

    environment = receipt.get("environment")
    if (
        not isinstance(environment, dict)
        or not set(environment) <= _ENVIRONMENT_KEYS
        or not {"python", "platform"} <= set(environment)
        or any(not isinstance(value, str) or not value or len(value) > 256 for value in environment.values())
    ):
        raise ReceiptVerificationError("environment is invalid")
    environment_patterns = {
        "python": _PYTHON_VERSION,
        "platform": _PLATFORM,
        "node": _NODE_VERSION,
    }
    if any(
        environment_patterns[key].fullmatch(value) is None
        for key, value in environment.items()
    ):
        raise ReceiptVerificationError("environment value is invalid")
    if dict(environment) != dict(expected_environment):
        raise ReceiptVerificationError("environment does not match current trusted environment")


def _is_linklike(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT_ATTRIBUTE
    )


def _configuration_metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", 0)),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _lstat_configuration_path(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise ReceiptVerificationError("configuration source cannot be inspected") from exc


def _assert_real_configuration_directory(path: Path) -> os.stat_result:
    metadata = _lstat_configuration_path(path)
    if _is_linklike(metadata):
        raise ReceiptVerificationError("configuration source contains a link or reparse point")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReceiptVerificationError("configuration source parent is not a regular directory")
    return metadata


def _assert_bounded_regular_configuration_file(path: Path) -> os.stat_result:
    metadata = _lstat_configuration_path(path)
    if _is_linklike(metadata):
        raise ReceiptVerificationError("configuration source contains a link or reparse point")
    if not stat.S_ISREG(metadata.st_mode):
        raise ReceiptVerificationError("configuration source is not a regular file")
    if metadata.st_size < 0 or metadata.st_size > _MAX_CONFIGURATION_SOURCE_BYTES:
        raise ReceiptVerificationError("configuration source exceeds the per-file size limit")
    return metadata


def _configuration_source_path(
    root: Path,
    relative_path: Path,
) -> tuple[Path, tuple[tuple[Path, os.stat_result], ...], os.stat_result]:
    if relative_path.is_absolute() or not relative_path.parts or any(
        part in {"", ".", ".."} for part in relative_path.parts
    ):
        raise ReceiptVerificationError("configuration source path is unsafe")

    lexical_root = Path(os.path.abspath(root))
    source = Path(os.path.abspath(lexical_root / relative_path))
    try:
        contained_relative = source.relative_to(lexical_root)
    except ValueError as exc:
        raise ReceiptVerificationError("configuration source escaped the repository root") from exc

    directories: list[tuple[Path, os.stat_result]] = []
    current = lexical_root
    directories.append((current, _assert_real_configuration_directory(current)))
    for component in contained_relative.parts[:-1]:
        current /= component
        directories.append((current, _assert_real_configuration_directory(current)))
    return source, tuple(directories), _assert_bounded_regular_configuration_file(source)


def _assert_unchanged_configuration_source(
    source: Path,
    directories: Sequence[tuple[Path, os.stat_result]],
    expected_file: os.stat_result,
) -> None:
    for directory, expected_metadata in directories:
        current_metadata = _assert_real_configuration_directory(directory)
        if _configuration_metadata_identity(current_metadata) != _configuration_metadata_identity(
            expected_metadata
        ):
            raise ReceiptVerificationError("configuration source parent changed while hashing")
    current_file = _assert_bounded_regular_configuration_file(source)
    if _configuration_metadata_identity(current_file) != _configuration_metadata_identity(expected_file):
        raise ReceiptVerificationError("configuration source changed while hashing")


def _hash_configuration_source(
    root: Path,
    relative_path: Path,
    *,
    name: str,
    require_budget: Callable[[str], None],
) -> str:
    require_budget(f"before {name}")
    source, directories, expected_file = _configuration_source_path(root, relative_path)
    require_budget(f"before opening {name}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ReceiptVerificationError("configuration source cannot be opened") from exc
    try:
        try:
            opened_file = os.fstat(descriptor)
        except OSError as exc:
            raise ReceiptVerificationError("configuration source cannot be inspected") from exc
        if _is_linklike(opened_file) or not stat.S_ISREG(opened_file.st_mode):
            raise ReceiptVerificationError("configuration source is not a regular file")
        if opened_file.st_size < 0 or opened_file.st_size > _MAX_CONFIGURATION_SOURCE_BYTES:
            raise ReceiptVerificationError("configuration source exceeds the per-file size limit")
        if _configuration_metadata_identity(opened_file) != _configuration_metadata_identity(expected_file):
            raise ReceiptVerificationError("configuration source changed while opening")

        digest = hashlib.sha256()
        remaining = opened_file.st_size
        while remaining:
            require_budget(f"during {name}")
            try:
                chunk = os.read(descriptor, min(_CONFIGURATION_READ_CHUNK_BYTES, remaining))
            except OSError as exc:
                raise ReceiptVerificationError("configuration source cannot be read") from exc
            require_budget(f"during {name}")
            if not chunk or len(chunk) > remaining:
                raise ReceiptVerificationError("configuration source changed while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        try:
            final_file = os.fstat(descriptor)
        except OSError as exc:
            raise ReceiptVerificationError("configuration source cannot be inspected") from exc
        if _configuration_metadata_identity(final_file) != _configuration_metadata_identity(opened_file):
            raise ReceiptVerificationError("configuration source changed while hashing")
    finally:
        os.close(descriptor)

    _assert_unchanged_configuration_source(source, directories, expected_file)
    require_budget(f"after {name}")
    return digest.hexdigest()


def current_configuration_digests(*, deadline_monotonic: float | None = None) -> dict[str, str]:
    """Hash the closed, bounded configuration set without crossing a deadline."""

    def require_budget(phase: str) -> None:
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            raise ReceiptVerificationError(f"configuration hashing deadline exhausted {phase}")

    # IMPORTANT: keep these relative to the lexical checkout root. Resolving a
    # path before validation could silently follow a link or Windows reparse point.
    root = Path(__file__).absolute().parents[2]
    files = {
        "agent_skills_script": Path("scripts/validate_agent_skills.py"),
        "classifier": Path("redagent_platform/validation/classifier.py"),
        "config_loader": Path("redagent_platform/validation/config.py"),
        "dependency_bootstrap_script": Path("scripts/install_validation_dependencies.py"),
        "dev_lock": Path("requirements-dev.lock"),
        "gate_deadline": Path("redagent_platform/gate_deadline.py"),
        "gate_workflow": Path(".github/workflows/r118-validation-gate.yml"),
        "gate_runtime": Path("redagent_platform/gate_runtime.py"),
        "local_stack_script": Path("scripts/redagent_local_stack.py"),
        "openbao_script": Path("scripts/openbao_conformance.py"),
        "opa_script": Path("scripts/opa_conformance.py"),
        "package_lock": Path("package-lock.json"),
        "package_manifest": Path("package.json"),
        "path_mapping": Path("config/validation/r118-path-mapping.json"),
        "pre_commit_config": Path(".pre-commit-config.yaml"),
        "receipt_verifier": Path("redagent_platform/validation/receipt.py"),
        "runtime_lock": Path("requirements-runtime.lock"),
        "secure_sdlc_script": Path("scripts/validate_secure_sdlc.py"),
        "stage_registry": Path("config/validation/r118-stage-registry.json"),
        "stage_runner": Path("redagent_platform/validation/stages.py"),
        "validation_lease": Path("redagent_platform/gate_lease.py"),
        "validation_runner": Path("scripts/run_validation_gate.py"),
        "validation_workflow": Path(".github/workflows/r118-validation.yml"),
        "venv_boundary_script": Path("scripts/verify_venv_boundary.py"),
        "venv_preparation_script": Path("scripts/prepare_validation_venv.py"),
        "posix_venv_layout_script": Path("scripts/verify_posix_venv_layout.sh"),
        "windows_wrapper": Path("scripts/run_full_tests_windows.ps1"),
        "linux_wrapper": Path("scripts/run_full_tests_linux.sh"),
        "legacy_runner": Path("scripts/run_legacy_full_gate.py"),
    }
    return {
        name: _hash_configuration_source(root, relative_path, name=name, require_budget=require_budget)
        for name, relative_path in files.items()
    }
