"""Pure contracts and offline verification for bounded planner qualification."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping, Sequence


MATRIX_SCHEMA_V1 = "redagent.autonomous-planner-qualification-matrix/v1"
MATRIX_SCHEMA_V2 = "redagent.autonomous-planner-qualification-matrix/v2"
MATRIX_SCHEMA_V3 = "redagent.autonomous-planner-qualification-matrix/v3"
MATRIX_SCHEMA_V4 = "redagent.autonomous-planner-qualification-matrix/v4"
MATRIX_SCHEMA_V5 = "redagent.autonomous-planner-qualification-matrix/v5"
MATRIX_SCHEMA_V6 = "redagent.autonomous-planner-qualification-matrix/v6"
MATRIX_SCHEMA = MATRIX_SCHEMA_V1
SCORER_SCHEMA = "redagent.autonomous-planner-qualification-scorer/v1"
PROJECTION_SCHEMA_V1 = "redagent.autonomous-planner-qualification-projection/v1"
PROJECTION_SCHEMA_V2 = "redagent.autonomous-planner-qualification-projection/v2"
PROJECTION_SCHEMA_V3 = "redagent.autonomous-planner-qualification-projection/v3"
PROJECTION_SCHEMA_V4 = "redagent.autonomous-planner-qualification-projection/v4"
PROJECTION_SCHEMA_V5 = "redagent.autonomous-planner-qualification-projection/v5"
PROJECTION_SCHEMA_V6 = "redagent.autonomous-planner-qualification-projection/v6"
PROJECTION_SCHEMA = PROJECTION_SCHEMA_V1
PREFLIGHT_SCHEMA = "redagent.autonomous-planner-qualification-preflight/v1"
STAGE_RESULT_SCHEMA = "redagent.autonomous-planner-qualification-stage-result/v1"
EVENT_SCHEMA = "redagent.autonomous-planner-qualification-event/v1"
BUNDLE_SCHEMA = "redagent.autonomous-planner-qualification-bundle/v1"
PINS_SCHEMA = "redagent.autonomous-planner-qualification-pins/v1"
RESULT_SCHEMA = "redagent.autonomous-planner-qualification-result/v1"

AUTONOMOUS_PLANNER_QUALIFIED = "AUTONOMOUS_PLANNER_QUALIFIED"
CONDITIONALLY_QUALIFIED = "CONDITIONALLY_QUALIFIED"
NOT_QUALIFIED = "NOT_QUALIFIED"
ABORTED = "ABORTED"

MAX_MATRIX_BYTES = 512 * 1024
MAX_PROJECTION_BYTES = 512 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 16
EXPECTED_MATRIX_SHA256_V1 = "1ab6ef282abeda1dac450c2556a50369ab05211420d128e009a91c1ca6a2b524"
EXPECTED_MATRIX_SHA256_V2 = "236ca3a0c1422440c7e04a96186870dfa21735a21ccc6736de7d5784a7fa29b5"
EXPECTED_MATRIX_SHA256_V3 = "84d477f1864025b0857d6e7b623f32ca9c3ee61c5df39aeb3272983fbdfb6e5f"
EXPECTED_MATRIX_SHA256_V4 = "b2996b2d06ef0e041e08f0dd97e419aea7281a4294af8c425cfdd3d3319d777e"
EXPECTED_MATRIX_SHA256_V5 = "64ffe65c7b50060037418e872ad15625a50aa56868980a736b6d6a683626442c"
EXPECTED_MATRIX_SHA256_V6 = "864ea9c6faef2f68a0058a313f40d13ad7bee215d3d24af2316400ef31a18d72"


def _pinned_git_oid(*chunks: str) -> str:
    return "".join(chunks)


EXPECTED_PREDECESSORS = (
    (
        "campaign-authority-envelope-v2",
        _pinned_git_oid("cea19a04ff", "c0ddea7cef", "026657b337", "3a2bfc7bc4"),  # pragma: allowlist secret
    ),  # pragma: allowlist secret
    (
        "independent-plan-validator-v1",
        _pinned_git_oid("8cd82bee5b", "6550517c38", "b1bfca907f", "4359f781fb"),  # pragma: allowlist secret
    ),  # pragma: allowlist secret
    (
        "deterministic-dag-planner-v1",
        _pinned_git_oid("200df0dea5", "d9f522a80a", "b67fefbc12", "7e11bd4dd7"),  # pragma: allowlist secret
    ),  # pragma: allowlist secret
    (
        "plan-admission-budget-v1",
        _pinned_git_oid("63b1456fd4", "48471a55fc", "5cb6d6f414", "a0dd620fe9"),  # pragma: allowlist secret
    ),  # pragma: allowlist secret
    (
        "durable-dag-execution-v1",
        _pinned_git_oid("bf99bb242b", "e2d5b36960", "5c36a4c1e7", "83dc806d07"),  # pragma: allowlist secret
    ),  # pragma: allowlist secret
    (
        "trusted-bounded-replanning-v1",
        _pinned_git_oid("86644cac5d", "26902e92eb", "5a7dce2e10", "278fe81341"),  # pragma: allowlist secret
    ),  # pragma: allowlist secret
    (
        "planner-evidence-lineage-v1",
        _pinned_git_oid("a7e204c25e", "c7117ab95b", "5d18802f95", "fd59640942"),  # pragma: allowlist secret
    ),  # pragma: allowlist secret
    (
        "campaign-operations-v1",
        _pinned_git_oid("29ee076b11", "3d25e27af7", "ee3eba49ce", "7eeec5c7cc"),  # pragma: allowlist secret
    ),  # pragma: allowlist secret
)
EXPECTED_TARGET_HOSTS = ("127.0.0.1", "::1", "localhost")
EXPECTED_FORMAL_ENVIRONMENT = {
    "REDAGENT_ACTIVE_TARGET_ACCESS": "false",
    "REDAGENT_BIND_HOST": "127.0.0.1",
    "REDAGENT_COMPOSE_PROJECT_NAME": "redagent-planner-qualification",
    "REDAGENT_EXTERNAL_DELIVERY": "false",
    "REDAGENT_KEYCLOAK_PORT": "58090",
    "REDAGENT_OPA_HOST_PORT": "58191",
    "REDAGENT_POSTGRES_PORT": "55472",
    "REDAGENT_PRIVILEGED_RUNNERS": "false",
    "REDAGENT_PROFILE": "local",
    "REDAGENT_REAL_SCANNERS": "false",
    "REDAGENT_RUSTFS_PORT": "59010",
    "REDAGENT_STARTUP_TIMEOUT_SECONDS": "180",
    "REDAGENT_STATE_DIR": ".local/redagent",
    "REDAGENT_STOP_TIMEOUT_SECONDS": "30",
    "REDAGENT_TEMPORAL_PORT": "57273",
}
EXPECTED_STAGE_BINDINGS_V1 = (
    ("authority-to-terminal-python", "pytest-authority-to-terminal"),
    ("operations-component", "vitest-operations-component"),
    ("operations-e2e", "playwright-operations-e2e"),
    ("windows-full-gate", "windows-full-gate"),
    ("owned-runtime-cleanup", "owned-runtime-cleanup"),
    ("post-cleanup-offline-lineage", "pytest-offline-lineage"),
    ("residual-safety", "internal-residual-safety"),
)
EXPECTED_STAGE_BINDINGS_V2 = (
    ("authority-to-terminal-python", "pytest-authority-to-terminal"),
    ("operations-component", "vitest-operations-component"),
    ("operations-e2e", "playwright-operations-e2e"),
    ("windows-full-gate", "windows-full-gate"),
    ("runtime-coordinate-snapshot", "internal-runtime-coordinate-snapshot"),
    ("owned-runtime-cleanup", "owned-runtime-cleanup"),
    ("post-cleanup-offline-lineage", "pytest-offline-lineage"),
    ("residual-safety", "internal-residual-safety"),
)
EXPECTED_STAGE_BINDINGS_V3 = (
    ("authority-to-terminal-python", "pytest-authority-to-terminal"),
    ("operations-component", "vitest-operations-component"),
    ("operations-e2e", "playwright-operations-e2e"),
    ("windows-full-gate", "windows-full-gate"),
    ("owned-runtime-provision", "owned-runtime-provision"),
    ("runtime-coordinate-snapshot", "internal-runtime-coordinate-snapshot"),
    ("owned-runtime-cleanup", "owned-runtime-cleanup"),
    ("post-cleanup-offline-lineage", "pytest-offline-lineage"),
    ("residual-safety", "internal-residual-safety"),
)
EXPECTED_STAGE_BINDINGS_V4 = EXPECTED_STAGE_BINDINGS_V3
EXPECTED_STAGE_BINDINGS_V5 = EXPECTED_STAGE_BINDINGS_V3
EXPECTED_STAGE_BINDINGS_V6 = EXPECTED_STAGE_BINDINGS_V3
EXPECTED_STAGE_BINDINGS = EXPECTED_STAGE_BINDINGS_V1
EXPECTED_FORMAL_RUNTIME_PATHS_V2 = {
    "home": ".tmp/autonomous-planner-qualification-attempt-02/runtime/home",
    "pre_commit_home": ".tmp/autonomous-planner-qualification-attempt-02/runtime/cache/pre-commit",
    "temp": ".tmp/autonomous-planner-qualification-attempt-02/runtime/temp",
}
EXPECTED_FORMAL_RUNTIME_PATHS_V3 = {
    "home": ".tmp/autonomous-planner-qualification-attempt-03/runtime/home",
    "pre_commit_home": ".tmp/autonomous-planner-qualification-attempt-03/runtime/cache/pre-commit",
    "temp": ".tmp/autonomous-planner-qualification-attempt-03/runtime/temp",
}
EXPECTED_FORMAL_RUNTIME_PATHS_V4 = {
    "home": ".tmp/apq-04/runtime/h",
    "pre_commit_home": ".tmp/apq-04/runtime/p",
    "temp": ".tmp/apq-04/runtime/t",
}
EXPECTED_FORMAL_RUNTIME_PATHS_V5 = {
    "home": ".tmp/apq-05/runtime/h",
    "pre_commit_home": ".tmp/apq-05/runtime/p",
    "temp": ".tmp/apq-05/runtime/t",
}
EXPECTED_FORMAL_RUNTIME_PATHS_V6 = {
    "home": ".tmp/apq-06/runtime/h",
    "pre_commit_home": ".tmp/apq-06/runtime/p",
    "temp": ".tmp/apq-06/runtime/t",
}
EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V3 = {"REDAGENT_AUTONOMOUS_PLANNER_LIVE_QUALIFICATION": "owned-loopback-zap-v1"}
EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V4 = EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V3
EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V5 = EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V3
EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V6 = EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V3
RUNTIME_BOUND_MATRIX_SCHEMAS = frozenset(
    {MATRIX_SCHEMA_V2, MATRIX_SCHEMA_V3, MATRIX_SCHEMA_V4, MATRIX_SCHEMA_V5, MATRIX_SCHEMA_V6}
)

_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


class QualificationError(ValueError):
    """Raised when qualification input or offline evidence fails closed."""


@dataclass(frozen=True)
class StageSpec:
    stage_id: str
    runner_id: str
    timeout_seconds: int
    result_kind: str
    expected_pass_count: int | None
    allowed_skip_count: int
    expected_artifacts: tuple[str, ...]


@dataclass(frozen=True)
class QualificationMatrix:
    schema_version: str
    matrix_sha256: str
    accepted_predecessors: tuple[tuple[str, str], ...]
    candidate_parent_commit: str
    allowed_target_hosts: tuple[str, ...]
    formal_environment: Mapping[str, str]
    runner_environment: Mapping[str, Mapping[str, str]]
    formal_runtime_paths: Mapping[str, str]
    max_concurrency: int
    required_score_basis_points: int
    conditional_allowlist: tuple[str, ...]
    validation_dependency_runner_ids: tuple[str, ...]
    source_paths: tuple[str, ...]
    stages: tuple[StageSpec, ...]
    retained_artifacts: tuple[str, ...]
    cleanup_paths: tuple[str, ...]
    scorer_sha256: str


@dataclass(frozen=True)
class ExecutionProjection:
    attempt_id: str
    candidate_commit: str
    candidate_tree: str
    candidate_parent_commit: str
    matrix_sha256: str
    source_sha256: Mapping[str, str]
    platform: str
    architecture: str
    python_version: str
    node_version: str
    private_manifest_sha256: str
    operator_identity_sha256: str
    reviewer_identity_sha256: str
    trust_anchor_sha256: str
    runner_ids: tuple[str, ...]
    target_hosts: tuple[str, ...]
    formal_environment: Mapping[str, str]
    runner_environment: Mapping[str, Mapping[str, str]]
    formal_runtime_paths: Mapping[str, str]
    max_concurrency: int
    scorer_sha256: str
    retained_artifacts: tuple[str, ...]
    residual_ports: tuple[int, ...]
    residual_process_markers: tuple[str, ...]
    projection_sha256: str


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise QualificationError("value is not bounded canonical JSON") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _depth(value: object, *, current: int = 0) -> int:
    if current > MAX_JSON_DEPTH:
        raise QualificationError("JSON nesting exceeds the qualification bound")
    if isinstance(value, Mapping):
        return max((_depth(item, current=current + 1) for item in value.values()), default=current)
    if isinstance(value, list):
        return max((_depth(item, current=current + 1) for item in value), default=current)
    return current


def decode_json_bytes(payload: bytes, *, label: str, maximum_bytes: int) -> object:
    if not payload or len(payload) > maximum_bytes or payload.startswith(b"\xef\xbb\xbf"):
        raise QualificationError(f"{label} byte contract invalid")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError(f"{label} JSON invalid") from exc
    _depth(value)
    return value


def is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def load_json_file(path: Path, *, label: str, maximum_bytes: int) -> object:
    # CRITICAL: qualification inputs and retained evidence must never traverse a link or reparse
    # point; otherwise a fixed repository path could authenticate attacker-selected bytes.
    if is_link_or_reparse(path) or not path.is_file():
        raise QualificationError(f"{label} must be a regular non-link file")
    return decode_json_bytes(path.read_bytes(), label=label, maximum_bytes=maximum_bytes)


def _mapping(value: object, *, label: str, fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise QualificationError(f"{label} must be an object")
    if set(value) != fields:
        raise QualificationError(f"{label} fields invalid")
    return value


def _string(value: object, *, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\r" in value or "\n" in value:
        raise QualificationError(f"{label} invalid")
    if pattern is not None and not pattern.fullmatch(value):
        raise QualificationError(f"{label} invalid")
    return value


def _integer(value: object, *, label: str, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise QualificationError(f"{label} invalid")
    return value


def _boolean(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{label} invalid")
    return value


def _sorted_unique_strings(
    value: object,
    *,
    label: str,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise QualificationError(f"{label} invalid")
    result = tuple(_string(item, label=label, pattern=pattern) for item in value)
    if (not allow_empty and not result) or result != tuple(sorted(set(result))):
        raise QualificationError(f"{label} must be sorted and unique")
    return result


def _ordered_unique_strings(value: object, *, label: str, pattern: re.Pattern[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise QualificationError(f"{label} invalid")
    result = tuple(_string(item, label=label, pattern=pattern) for item in value)
    if not result or len(result) != len(set(result)):
        raise QualificationError(f"{label} must be unique")
    return result


def _sorted_unique_integers(
    value: object,
    *,
    label: str,
    minimum: int,
    maximum: int,
    allow_empty: bool = False,
) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise QualificationError(f"{label} invalid")
    result = tuple(_integer(item, label=label, minimum=minimum, maximum=maximum) for item in value)
    if (not allow_empty and not result) or result != tuple(sorted(set(result))):
        raise QualificationError(f"{label} must be sorted and unique")
    return result


def _sha(value: object, *, label: str) -> str:
    return _string(value, label=label, pattern=_SHA256)


def _git_oid(value: object, *, label: str) -> str:
    return _string(value, label=label, pattern=_GIT_OID)


def _safe_relative_path(value: object, *, label: str) -> str:
    result = _string(value, label=label)
    path = PurePosixPath(result)
    if (
        path.is_absolute()
        or "\\" in result
        or ":" in result
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise QualificationError(f"{label} invalid")
    return result


def _path_tuple(value: object, *, label: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise QualificationError(f"{label} invalid")
    result = tuple(_safe_relative_path(item, label=label) for item in value)
    if (not allow_empty and not result) or result != tuple(sorted(set(result))):
        raise QualificationError(f"{label} must be sorted and unique")
    return result


def _environment_mapping(value: object, *, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise QualificationError(f"{label} invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        name = _string(key, label=f"{label} key", pattern=_ENV_NAME)
        result[name] = _string(item, label=f"{label} value")
    if tuple(result) != tuple(sorted(result)):
        raise QualificationError(f"{label} must be sorted")
    return result


def _runner_environment_mapping(value: object) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise QualificationError("runner environment invalid")
    result = {
        _string(key, label="runner environment runner", pattern=_TOKEN): _environment_mapping(
            item, label="runner environment"
        )
        for key, item in value.items()
    }
    if tuple(result) != tuple(sorted(result)):
        raise QualificationError("runner environment must be sorted")
    return result


def _runtime_path_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise QualificationError("formal runtime paths invalid")
    result = {
        _string(key, label="formal runtime path key", pattern=_TOKEN): _safe_relative_path(
            item, label="formal runtime path"
        )
        for key, item in value.items()
    }
    if tuple(result) != tuple(sorted(result)):
        raise QualificationError("formal runtime paths must be sorted")
    return result


def _parse_stage(value: object) -> StageSpec:
    item = _mapping(
        value,
        label="stage",
        fields=frozenset(
            {
                "stage_id",
                "runner_id",
                "timeout_seconds",
                "result_kind",
                "expected_pass_count",
                "allowed_skip_count",
                "expected_artifacts",
            }
        ),
    )
    expected_pass_count_value = item["expected_pass_count"]
    expected_pass_count = (
        None
        if expected_pass_count_value is None
        else _integer(expected_pass_count_value, label="stage expected pass count", minimum=1)
    )
    result_kind = _string(item["result_kind"], label="stage result kind", pattern=_TOKEN)
    if result_kind not in {
        "pytest",
        "vitest",
        "playwright",
        "forced-g2",
        "provision",
        "runtime-snapshot",
        "cleanup",
        "residual",
    }:
        raise QualificationError("stage result kind invalid")
    return StageSpec(
        stage_id=_string(item["stage_id"], label="stage id", pattern=_TOKEN),
        runner_id=_string(item["runner_id"], label="runner id", pattern=_TOKEN),
        timeout_seconds=_integer(item["timeout_seconds"], label="stage timeout", minimum=1, maximum=7200),
        result_kind=result_kind,
        expected_pass_count=expected_pass_count,
        allowed_skip_count=_integer(item["allowed_skip_count"], label="stage skip count", maximum=10_000),
        expected_artifacts=_path_tuple(item["expected_artifacts"], label="stage artifact", allow_empty=True),
    )


def parse_matrix(payload: object) -> QualificationMatrix:
    if not isinstance(payload, Mapping):
        raise QualificationError("matrix must be an object")
    schema_version = payload.get("schema_version")
    common_fields = {
        "schema_version",
        "matrix_sha256",
        "accepted_predecessors",
        "source_base",
        "allowed_target_hosts",
        "max_concurrency",
        "scorer",
        "network_policy",
        "formal_environment",
        "required_source_paths",
        "stages",
        "retained_artifacts",
        "cleanup_paths",
    }
    if schema_version == MATRIX_SCHEMA_V1:
        matrix_fields = common_fields
    elif schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS:
        matrix_fields = common_fields | {"runner_environment", "formal_runtime_paths"}
    else:
        raise QualificationError("matrix schema invalid")
    item = _mapping(
        payload,
        label="matrix",
        fields=frozenset(matrix_fields),
    )
    supplied_digest = _sha(item["matrix_sha256"], label="matrix digest")
    body = {key: value for key, value in item.items() if key != "matrix_sha256"}
    computed_digest = canonical_sha256(body)
    # IMPORTANT: a coherently rehashed public matrix still needs the source-pinned trusted digest.
    if supplied_digest != computed_digest:
        raise QualificationError("matrix digest mismatch")
    expected_digest = {
        MATRIX_SCHEMA_V1: EXPECTED_MATRIX_SHA256_V1,
        MATRIX_SCHEMA_V2: EXPECTED_MATRIX_SHA256_V2,
        MATRIX_SCHEMA_V3: EXPECTED_MATRIX_SHA256_V3,
        MATRIX_SCHEMA_V4: EXPECTED_MATRIX_SHA256_V4,
        MATRIX_SCHEMA_V5: EXPECTED_MATRIX_SHA256_V5,
        MATRIX_SCHEMA_V6: EXPECTED_MATRIX_SHA256_V6,
    }[schema_version]
    if computed_digest != expected_digest:
        raise QualificationError("trusted matrix digest mismatch")

    predecessor_values = item["accepted_predecessors"]
    if not isinstance(predecessor_values, list):
        raise QualificationError("accepted predecessors invalid")
    predecessors: list[tuple[str, str]] = []
    for value in predecessor_values:
        predecessor = _mapping(
            value,
            label="accepted predecessor",
            fields=frozenset({"contract", "source_revision"}),
        )
        predecessors.append(
            (
                _string(predecessor["contract"], label="predecessor contract", pattern=_TOKEN),
                _git_oid(predecessor["source_revision"], label="predecessor commit"),
            )
        )
    if tuple(predecessors) != EXPECTED_PREDECESSORS:
        raise QualificationError("accepted predecessor chain invalid")

    target_hosts = _sorted_unique_strings(item["allowed_target_hosts"], label="target host")
    if target_hosts != EXPECTED_TARGET_HOSTS:
        raise QualificationError("target allowlist must be exact loopback hosts")
    max_concurrency = _integer(item["max_concurrency"], label="max concurrency", minimum=1)
    if max_concurrency != 1:
        raise QualificationError("qualification concurrency must be one")

    scorer = _mapping(
        item["scorer"],
        label="scorer",
        fields=frozenset({"schema_version", "required_score_basis_points", "conditional_allowlist"}),
    )
    if scorer["schema_version"] != SCORER_SCHEMA:
        raise QualificationError("scorer schema invalid")
    required_score = _integer(scorer["required_score_basis_points"], label="required score", minimum=1, maximum=10_000)
    if required_score != 10_000:
        raise QualificationError("qualification scorer must be all-or-nothing")
    conditional_allowlist = _sorted_unique_strings(
        scorer["conditional_allowlist"],
        label="conditional allowance",
        pattern=_TOKEN,
        allow_empty=True,
    )
    if conditional_allowlist:
        raise QualificationError("V1 conditional allowlist must be empty")
    scorer_sha256 = canonical_sha256(dict(scorer))

    network = _mapping(
        item["network_policy"],
        label="network policy",
        fields=frozenset(
            {
                "assessment_targets",
                "unapproved_assessment_contacts_max",
                "validation_dependency_runner_ids",
            }
        ),
    )
    if network["assessment_targets"] != "loopback_only":
        raise QualificationError("assessment target policy invalid")
    if (
        _integer(
            network["unapproved_assessment_contacts_max"],
            label="unapproved contact ceiling",
        )
        != 0
    ):
        raise QualificationError("unapproved assessment contact ceiling must be zero")
    dependency_runners = _sorted_unique_strings(
        network["validation_dependency_runner_ids"], label="dependency runner", pattern=_TOKEN
    )
    if dependency_runners != ("windows-full-gate",):
        raise QualificationError("validation dependency runner set invalid")

    formal_environment_value = item["formal_environment"]
    if (
        not isinstance(formal_environment_value, Mapping)
        or not all(isinstance(key, str) and isinstance(value, str) for key, value in formal_environment_value.items())
        or dict(formal_environment_value) != EXPECTED_FORMAL_ENVIRONMENT
    ):
        raise QualificationError("formal qualification environment invalid")
    formal_environment = dict(sorted(formal_environment_value.items()))
    if schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS:
        runner_environment = _runner_environment_mapping(item["runner_environment"])
        formal_runtime_paths = _runtime_path_mapping(item["formal_runtime_paths"])
        expected_runtime_paths = {
            MATRIX_SCHEMA_V2: EXPECTED_FORMAL_RUNTIME_PATHS_V2,
            MATRIX_SCHEMA_V3: EXPECTED_FORMAL_RUNTIME_PATHS_V3,
            MATRIX_SCHEMA_V4: EXPECTED_FORMAL_RUNTIME_PATHS_V4,
            MATRIX_SCHEMA_V5: EXPECTED_FORMAL_RUNTIME_PATHS_V5,
            MATRIX_SCHEMA_V6: EXPECTED_FORMAL_RUNTIME_PATHS_V6,
        }[schema_version]
        if formal_runtime_paths != expected_runtime_paths:
            raise QualificationError("formal runtime path binding invalid")
    else:
        runner_environment = {}
        formal_runtime_paths = {}

    source_paths = _path_tuple(item["required_source_paths"], label="required source path")
    stage_values = item["stages"]
    if not isinstance(stage_values, list):
        raise QualificationError("stages invalid")
    stages = tuple(_parse_stage(value) for value in stage_values)
    stage_bindings = tuple((stage.stage_id, stage.runner_id) for stage in stages)
    expected_stage_bindings = {
        MATRIX_SCHEMA_V1: EXPECTED_STAGE_BINDINGS_V1,
        MATRIX_SCHEMA_V2: EXPECTED_STAGE_BINDINGS_V2,
        MATRIX_SCHEMA_V3: EXPECTED_STAGE_BINDINGS_V3,
        MATRIX_SCHEMA_V4: EXPECTED_STAGE_BINDINGS_V4,
        MATRIX_SCHEMA_V5: EXPECTED_STAGE_BINDINGS_V5,
        MATRIX_SCHEMA_V6: EXPECTED_STAGE_BINDINGS_V6,
    }[schema_version]
    if stage_bindings != expected_stage_bindings:
        raise QualificationError("stage order or runner binding invalid")
    if schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS:
        runner_ids = tuple(sorted(stage.runner_id for stage in stages))
        if tuple(runner_environment) != runner_ids:
            raise QualificationError("runner environment inventory invalid")
        authority_environment = runner_environment["pytest-authority-to-terminal"]
        if len(authority_environment) != 1 or tuple(authority_environment.values()) != ("owned-loopback-zap-v1",):
            raise QualificationError("authority runner environment invalid")
        authority_name = next(iter(authority_environment))
        if not authority_name.startswith("REDAGENT_") or not authority_name.endswith("_LIVE_QUALIFICATION"):
            raise QualificationError("authority runner environment name invalid")
        if any(
            environment
            for runner_id, environment in runner_environment.items()
            if runner_id != "pytest-authority-to-terminal"
        ):
            raise QualificationError("runner environment exceeded authority stage")
        # IMPORTANT: V2 remains authenticated by its immutable trusted matrix digest; current V3-V6
        # authority surfaces are product-semantic and must never regress to a private item code.
        expected_authority_environment = {
            MATRIX_SCHEMA_V3: EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V3,
            MATRIX_SCHEMA_V4: EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V4,
            MATRIX_SCHEMA_V5: EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V5,
            MATRIX_SCHEMA_V6: EXPECTED_AUTHORITY_RUNNER_ENVIRONMENT_V6,
        }.get(schema_version)
        if expected_authority_environment is not None and authority_environment != expected_authority_environment:
            raise QualificationError("product authority runner environment invalid")

    retained_artifacts = _path_tuple(item["retained_artifacts"], label="retained artifact")
    expected_retained_artifacts = tuple(
        sorted(
            {
                "events.jsonl",
                "preflight.json",
                "stage-results.json",
                *(path for stage in stages for path in stage.expected_artifacts),
                *(f"stages/{stage.stage_id}.stderr.log" for stage in stages),
                *(f"stages/{stage.stage_id}.stdout.log" for stage in stages),
            }
        )
    )
    if retained_artifacts != expected_retained_artifacts:
        raise QualificationError("retained artifact inventory does not cover the fixed ceremony")
    cleanup_paths = _path_tuple(item["cleanup_paths"], label="cleanup path")
    cleanup_root = {
        MATRIX_SCHEMA_V1: ".tmp/autonomous-planner-qualification/runtime/",
        MATRIX_SCHEMA_V2: ".tmp/autonomous-planner-qualification-attempt-02/runtime/",
        MATRIX_SCHEMA_V3: ".tmp/autonomous-planner-qualification-attempt-03/runtime/",
        MATRIX_SCHEMA_V4: ".tmp/apq-04/runtime/",
        MATRIX_SCHEMA_V5: ".tmp/apq-05/runtime/",
        MATRIX_SCHEMA_V6: ".tmp/apq-06/runtime/",
    }[schema_version]
    if any(not path.startswith(cleanup_root) for path in cleanup_paths):
        raise QualificationError("cleanup path escaped the item-owned runtime root")
    # IMPORTANT: every formal writer must be owned by an exact declared cleanup root.
    if schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS and not all(
        any(path == cleanup_path or path.startswith(cleanup_path + "/") for cleanup_path in cleanup_paths)
        for path in formal_runtime_paths.values()
    ):
        raise QualificationError("formal runtime path lacks cleanup ownership")

    return QualificationMatrix(
        schema_version=str(schema_version),
        matrix_sha256=supplied_digest,
        accepted_predecessors=tuple(predecessors),
        candidate_parent_commit=_git_oid(item["source_base"], label="candidate parent"),
        allowed_target_hosts=target_hosts,
        formal_environment=formal_environment,
        runner_environment=runner_environment,
        formal_runtime_paths=formal_runtime_paths,
        max_concurrency=max_concurrency,
        required_score_basis_points=required_score,
        conditional_allowlist=conditional_allowlist,
        validation_dependency_runner_ids=dependency_runners,
        source_paths=source_paths,
        stages=stages,
        retained_artifacts=retained_artifacts,
        cleanup_paths=cleanup_paths,
        scorer_sha256=scorer_sha256,
    )


def load_matrix(path: Path) -> QualificationMatrix:
    return parse_matrix(load_json_file(path, label="qualification matrix", maximum_bytes=MAX_MATRIX_BYTES))


def parse_projection(payload: object, matrix: QualificationMatrix) -> ExecutionProjection:
    projection_schema = {
        MATRIX_SCHEMA_V1: PROJECTION_SCHEMA_V1,
        MATRIX_SCHEMA_V2: PROJECTION_SCHEMA_V2,
        MATRIX_SCHEMA_V3: PROJECTION_SCHEMA_V3,
        MATRIX_SCHEMA_V4: PROJECTION_SCHEMA_V4,
        MATRIX_SCHEMA_V5: PROJECTION_SCHEMA_V5,
        MATRIX_SCHEMA_V6: PROJECTION_SCHEMA_V6,
    }[matrix.schema_version]
    common_fields = {
        "schema_version",
        "attempt_id",
        "candidate_commit",
        "candidate_tree",
        "candidate_parent_commit",
        "matrix_sha256",
        "source_sha256",
        "environment",
        "private_manifest_sha256",
        "operator_identity_sha256",
        "reviewer_identity_sha256",
        "trust_anchor_sha256",
        "runner_ids",
        "target_hosts",
        "formal_environment",
        "max_concurrency",
        "scorer_sha256",
        "retained_artifacts",
        "residual_ports",
        "residual_process_markers",
        "projection_sha256",
    }
    projection_fields = (
        common_fields | {"runner_environment", "formal_runtime_paths"}
        if matrix.schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS
        else common_fields
    )
    item = _mapping(
        payload,
        label="execution projection",
        fields=frozenset(projection_fields),
    )
    if item["schema_version"] != projection_schema:
        raise QualificationError("projection schema invalid")
    supplied_digest = _sha(item["projection_sha256"], label="projection digest")
    body = {key: value for key, value in item.items() if key != "projection_sha256"}
    if canonical_sha256(body) != supplied_digest:
        raise QualificationError("projection digest mismatch")

    source_values = item["source_sha256"]
    if not isinstance(source_values, Mapping) or not all(isinstance(key, str) for key in source_values):
        raise QualificationError("projection source digests invalid")
    if tuple(sorted(source_values)) != matrix.source_paths:
        raise QualificationError("projection source inventory invalid")
    source_digests = {
        _safe_relative_path(key, label="projection source path"): _sha(value, label="source digest")
        for key, value in source_values.items()
    }

    environment = _mapping(
        item["environment"],
        label="projection environment",
        fields=frozenset({"platform", "architecture", "python_version", "node_version"}),
    )
    platform_name = _string(environment["platform"], label="platform", pattern=_TOKEN)
    if platform_name != "windows":
        raise QualificationError("qualification platform must be windows")

    runner_ids = _ordered_unique_strings(item["runner_ids"], label="projection runner", pattern=_TOKEN)
    if runner_ids != tuple(stage.runner_id for stage in matrix.stages):
        raise QualificationError("projection runner inventory invalid")
    target_hosts = _sorted_unique_strings(item["target_hosts"], label="projection target host")
    if target_hosts != matrix.allowed_target_hosts:
        raise QualificationError("projection target allowlist drift")
    formal_environment_value = item["formal_environment"]
    if not isinstance(formal_environment_value, Mapping) or dict(formal_environment_value) != dict(
        matrix.formal_environment
    ):
        raise QualificationError("projection formal environment drift")
    if matrix.schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS:
        runner_environment = _runner_environment_mapping(item["runner_environment"])
        if runner_environment != matrix.runner_environment:
            raise QualificationError("projection runner environment drift")
        formal_runtime_paths = _runtime_path_mapping(item["formal_runtime_paths"])
        if formal_runtime_paths != matrix.formal_runtime_paths:
            raise QualificationError("projection formal runtime path drift")
    else:
        runner_environment = {}
        formal_runtime_paths = {}
    retained_artifacts = _path_tuple(item["retained_artifacts"], label="projection artifact")
    if retained_artifacts != matrix.retained_artifacts:
        raise QualificationError("projection artifact inventory drift")
    residual_ports = _sorted_unique_integers(
        item["residual_ports"],
        label="residual port",
        minimum=1024,
        maximum=65535,
        allow_empty=matrix.schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS,
    )
    if matrix.schema_version == MATRIX_SCHEMA_V1 and not 4 <= len(residual_ports) <= 16:
        raise QualificationError("residual port inventory invalid")
    if matrix.schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS and residual_ports:
        raise QualificationError("runtime-bound residual ports must come from the retained runtime snapshot")
    residual_process_markers = _sorted_unique_strings(
        item["residual_process_markers"], label="residual process marker", pattern=_TOKEN
    )
    if len(residual_process_markers) < 3 or len(residual_process_markers) > 16:
        raise QualificationError("residual process marker inventory invalid")

    operator_digest = _sha(item["operator_identity_sha256"], label="operator identity digest")
    reviewer_digest = _sha(item["reviewer_identity_sha256"], label="reviewer identity digest")
    if operator_digest == reviewer_digest:
        raise QualificationError("operator and reviewer must be distinct")
    if item["matrix_sha256"] != matrix.matrix_sha256:
        raise QualificationError("projection matrix drift")
    if item["candidate_parent_commit"] != matrix.candidate_parent_commit:
        raise QualificationError("projection parent drift")
    if item["scorer_sha256"] != matrix.scorer_sha256:
        raise QualificationError("projection scorer drift")
    if _integer(item["max_concurrency"], label="projection concurrency", minimum=1) != 1:
        raise QualificationError("projection concurrency drift")

    return ExecutionProjection(
        attempt_id=_string(item["attempt_id"], label="attempt id", pattern=_TOKEN),
        candidate_commit=_git_oid(item["candidate_commit"], label="candidate commit"),
        candidate_tree=_git_oid(item["candidate_tree"], label="candidate tree"),
        candidate_parent_commit=_git_oid(item["candidate_parent_commit"], label="candidate parent"),
        matrix_sha256=matrix.matrix_sha256,
        source_sha256=source_digests,
        platform=platform_name,
        architecture=_string(environment["architecture"], label="architecture", pattern=_TOKEN),
        python_version=_string(environment["python_version"], label="Python version", pattern=_VERSION),
        node_version=_string(environment["node_version"], label="Node version", pattern=_VERSION),
        private_manifest_sha256=_sha(item["private_manifest_sha256"], label="private manifest digest"),
        operator_identity_sha256=operator_digest,
        reviewer_identity_sha256=reviewer_digest,
        trust_anchor_sha256=_sha(item["trust_anchor_sha256"], label="trust anchor digest"),
        runner_ids=runner_ids,
        target_hosts=target_hosts,
        formal_environment=dict(matrix.formal_environment),
        runner_environment=runner_environment,
        formal_runtime_paths=formal_runtime_paths,
        max_concurrency=1,
        scorer_sha256=matrix.scorer_sha256,
        retained_artifacts=retained_artifacts,
        residual_ports=residual_ports,
        residual_process_markers=residual_process_markers,
        projection_sha256=supplied_digest,
    )


def load_projection(path: Path, matrix: QualificationMatrix) -> ExecutionProjection:
    value = load_json_file(path, label="execution projection", maximum_bytes=MAX_PROJECTION_BYTES)
    return parse_projection(value, matrix)


def _formal_execution_binding(
    matrix: QualificationMatrix,
    projection: ExecutionProjection,
) -> dict[str, object]:
    binding: dict[str, object] = {"formal_environment": dict(projection.formal_environment)}
    if matrix.schema_version in RUNTIME_BOUND_MATRIX_SCHEMAS:
        binding["runner_environment"] = {key: dict(value) for key, value in projection.runner_environment.items()}
        binding["formal_runtime_paths"] = dict(projection.formal_runtime_paths)
    return binding


def verify_preflight(
    matrix: QualificationMatrix,
    projection: ExecutionProjection,
    *,
    observed_commit: str,
    observed_tree: str,
    observed_parent: str,
    observed_branch: str,
    worktree_clean: bool,
    observed_source_sha256: Mapping[str, str],
    observed_environment: Mapping[str, str],
) -> dict[str, object]:
    if (
        observed_commit != projection.candidate_commit
        or observed_tree != projection.candidate_tree
        or observed_parent != projection.candidate_parent_commit
        or observed_branch != "dev"
        or not worktree_clean
    ):
        raise QualificationError("exact clean candidate preflight failed")
    if projection.candidate_commit == matrix.candidate_parent_commit:
        raise QualificationError("qualification candidate must be a clean direct successor")
    if dict(observed_source_sha256) != dict(projection.source_sha256):
        raise QualificationError("qualification source digest drift")
    expected_environment = {
        "platform": projection.platform,
        "architecture": projection.architecture,
        "python_version": projection.python_version,
        "node_version": projection.node_version,
    }
    if dict(observed_environment) != expected_environment:
        raise QualificationError("qualification environment drift")
    body: dict[str, object] = {
        "schema_version": PREFLIGHT_SCHEMA,
        "attempt_id": projection.attempt_id,
        "candidate_commit": projection.candidate_commit,
        "candidate_tree": projection.candidate_tree,
        "candidate_parent_commit": projection.candidate_parent_commit,
        "matrix_sha256": matrix.matrix_sha256,
        "projection_sha256": projection.projection_sha256,
        "source_inventory_sha256": canonical_sha256(dict(sorted(observed_source_sha256.items()))),
        "environment_sha256": canonical_sha256(
            {**expected_environment, **_formal_execution_binding(matrix, projection)}
        ),
        "worktree_clean": True,
        "branch": "dev",
        "formal_run_authority": False,
        "remote_authority": False,
        "release_authority": False,
        "ga_authority": False,
    }
    return {**body, "preflight_sha256": canonical_sha256(body)}


def _verify_preflight_record(
    matrix: QualificationMatrix,
    projection: ExecutionProjection,
    value: object,
) -> Mapping[str, object]:
    item = _mapping(
        value,
        label="retained preflight",
        fields=frozenset(
            {
                "schema_version",
                "attempt_id",
                "candidate_commit",
                "candidate_tree",
                "candidate_parent_commit",
                "matrix_sha256",
                "projection_sha256",
                "source_inventory_sha256",
                "environment_sha256",
                "worktree_clean",
                "branch",
                "formal_run_authority",
                "remote_authority",
                "release_authority",
                "ga_authority",
                "preflight_sha256",
            }
        ),
    )
    body = {key: field for key, field in item.items() if key != "preflight_sha256"}
    if canonical_sha256(body) != _sha(item["preflight_sha256"], label="preflight digest"):
        raise QualificationError("retained preflight digest mismatch")
    expected = {
        "schema_version": PREFLIGHT_SCHEMA,
        "attempt_id": projection.attempt_id,
        "candidate_commit": projection.candidate_commit,
        "candidate_tree": projection.candidate_tree,
        "candidate_parent_commit": projection.candidate_parent_commit,
        "matrix_sha256": matrix.matrix_sha256,
        "projection_sha256": projection.projection_sha256,
        "source_inventory_sha256": canonical_sha256(dict(sorted(projection.source_sha256.items()))),
        "environment_sha256": canonical_sha256(
            {
                "platform": projection.platform,
                "architecture": projection.architecture,
                "python_version": projection.python_version,
                "node_version": projection.node_version,
                **_formal_execution_binding(matrix, projection),
            }
        ),
        "worktree_clean": True,
        "branch": "dev",
        "formal_run_authority": False,
        "remote_authority": False,
        "release_authority": False,
        "ga_authority": False,
    }
    if body != expected:
        raise QualificationError("retained preflight candidate or authority binding mismatch")
    return item


def create_stage_result(
    stage: StageSpec,
    *,
    status: str,
    exit_code: int | None,
    passed_count: int | None,
    skipped_count: int,
    stdout_sha256: str,
    stderr_sha256: str,
    artifact_sha256: Mapping[str, str],
    unapproved_assessment_contacts: int,
    cleanup_complete: bool,
    detail: str,
) -> dict[str, object]:
    if status not in {"passed", "failed", "aborted"}:
        raise QualificationError("stage status invalid")
    if exit_code is not None:
        _integer(exit_code, label="stage exit code", maximum=255)
    if passed_count is not None:
        _integer(passed_count, label="stage passed count", maximum=1_000_000)
    _integer(skipped_count, label="stage skipped count", maximum=1_000_000)
    artifacts = {
        _safe_relative_path(path, label="stage artifact path"): _sha(digest, label="stage artifact digest")
        for path, digest in artifact_sha256.items()
    }
    artifact_paths = tuple(sorted(artifacts))
    if status == "passed" and artifact_paths != stage.expected_artifacts:
        raise QualificationError("stage artifact inventory invalid")
    if status != "passed" and not set(artifact_paths).issubset(stage.expected_artifacts):
        raise QualificationError("stage artifact inventory invalid")
    body: dict[str, object] = {
        "schema_version": STAGE_RESULT_SCHEMA,
        "stage_id": stage.stage_id,
        "runner_id": stage.runner_id,
        "status": status,
        "exit_code": exit_code,
        "passed_count": passed_count,
        "skipped_count": skipped_count,
        "stdout_sha256": _sha(stdout_sha256, label="stdout digest"),
        "stderr_sha256": _sha(stderr_sha256, label="stderr digest"),
        "artifact_sha256": dict(sorted(artifacts.items())),
        "unapproved_assessment_contacts": _integer(
            unapproved_assessment_contacts, label="unapproved assessment contacts", maximum=1_000_000
        ),
        "cleanup_complete": _boolean(cleanup_complete, label="cleanup complete"),
        "detail": _string(detail, label="stage detail"),
    }
    return {**body, "stage_result_sha256": canonical_sha256(body)}


def _parse_stage_result(value: object, stage: StageSpec) -> Mapping[str, object]:
    item = _mapping(
        value,
        label="stage result",
        fields=frozenset(
            {
                "schema_version",
                "stage_id",
                "runner_id",
                "status",
                "exit_code",
                "passed_count",
                "skipped_count",
                "stdout_sha256",
                "stderr_sha256",
                "artifact_sha256",
                "unapproved_assessment_contacts",
                "cleanup_complete",
                "detail",
                "stage_result_sha256",
            }
        ),
    )
    supplied_digest = _sha(item["stage_result_sha256"], label="stage result digest")
    body = {key: value for key, value in item.items() if key != "stage_result_sha256"}
    if canonical_sha256(body) != supplied_digest:
        raise QualificationError("stage result digest mismatch")
    recreated = create_stage_result(
        stage,
        status=_string(item["status"], label="stage status"),
        exit_code=item["exit_code"]
        if item["exit_code"] is None
        else _integer(item["exit_code"], label="stage exit code", maximum=255),
        passed_count=item["passed_count"]
        if item["passed_count"] is None
        else _integer(item["passed_count"], label="stage passed count", maximum=1_000_000),
        skipped_count=_integer(item["skipped_count"], label="stage skipped count", maximum=1_000_000),
        stdout_sha256=_sha(item["stdout_sha256"], label="stdout digest"),
        stderr_sha256=_sha(item["stderr_sha256"], label="stderr digest"),
        artifact_sha256=item["artifact_sha256"] if isinstance(item["artifact_sha256"], Mapping) else {},
        unapproved_assessment_contacts=_integer(
            item["unapproved_assessment_contacts"], label="unapproved assessment contacts", maximum=1_000_000
        ),
        cleanup_complete=_boolean(item["cleanup_complete"], label="cleanup complete"),
        detail=_string(item["detail"], label="stage detail"),
    )
    if recreated != dict(item):
        raise QualificationError("stage result semantic mismatch")
    return item


def compute_disposition(
    matrix: QualificationMatrix,
    stage_results: Sequence[object],
    *,
    protocol_drift: bool,
    artifacts_complete: bool = True,
) -> dict[str, object]:
    parsed: list[Mapping[str, object]] = []
    if len(stage_results) == len(matrix.stages):
        for value, stage in zip(stage_results, matrix.stages, strict=True):
            parsed.append(_parse_stage_result(value, stage))
    elif not protocol_drift:
        body: dict[str, object] = {
            "schema_version": RESULT_SCHEMA,
            "disposition": NOT_QUALIFIED,
            "score_basis_points": 0,
            "stage_count": len(stage_results),
            "required_stage_count": len(matrix.stages),
            "protocol_drift": False,
            "artifact_inventory_complete": artifacts_complete,
            "reason": "mandatory_stage_result_missing_or_extra",
            "conditional_allowlist_used": [],
            "reviewer_approval_required": True,
            "execution_authority": False,
            "remote_authority": False,
            "release_authority": False,
            "go_authority": False,
            "ga_authority": False,
        }
        return {**body, "result_sha256": canonical_sha256(body)}

    if protocol_drift or any(result["status"] == "aborted" for result in parsed):
        disposition = ABORTED
        reason = "formal_protocol_or_environment_drift"
        score = 0
    else:
        all_passed = True
        for result, stage in zip(parsed, matrix.stages, strict=True):
            all_passed = all_passed and result["status"] == "passed"
            all_passed = all_passed and result["exit_code"] == 0
            all_passed = all_passed and result["cleanup_complete"] is True
            all_passed = all_passed and result["unapproved_assessment_contacts"] == 0
            all_passed = all_passed and result["skipped_count"] == stage.allowed_skip_count
            if stage.expected_pass_count is not None:
                all_passed = all_passed and result["passed_count"] == stage.expected_pass_count
        all_passed = all_passed and artifacts_complete
        disposition = AUTONOMOUS_PLANNER_QUALIFIED if all_passed else NOT_QUALIFIED
        reason = "all_mandatory_criteria_passed" if all_passed else "mandatory_criterion_failed"
        score = 10_000 if all_passed else 0

    body = {
        "schema_version": RESULT_SCHEMA,
        "disposition": disposition,
        "score_basis_points": score,
        "stage_count": len(parsed),
        "required_stage_count": len(matrix.stages),
        "protocol_drift": protocol_drift,
        "artifact_inventory_complete": artifacts_complete,
        "reason": reason,
        "conditional_allowlist_used": [],
        "reviewer_approval_required": True,
        "execution_authority": False,
        "remote_authority": False,
        "release_authority": False,
        "go_authority": False,
        "ga_authority": False,
    }
    return {**body, "result_sha256": canonical_sha256(body)}


def _expected_event_kinds(stage_count: int) -> tuple[str, ...]:
    return (
        "preflight_passed",
        "attempt_started",
        *("stage_completed" for _ in range(stage_count)),
        "attempt_terminal",
    )


def build_event_chain(
    events: Sequence[tuple[str, Mapping[str, object]]],
    *,
    expected_stage_ids: Sequence[str] | None = None,
) -> list[dict[str, object]]:
    stage_count = len(expected_stage_ids) if expected_stage_ids is not None else len(events) - 3
    if stage_count < 1 or tuple(kind for kind, _payload in events) != _expected_event_kinds(stage_count):
        raise QualificationError("formal event lifecycle invalid")
    if expected_stage_ids is not None:
        observed_stage_ids = tuple(payload.get("stage_id") for _kind, payload in events[2:-1])
        if observed_stage_ids != tuple(expected_stage_ids):
            raise QualificationError("formal event lifecycle invalid")
    previous = "0" * 64
    result: list[dict[str, object]] = []
    for sequence, (kind, payload) in enumerate(events, start=1):
        if not isinstance(payload, Mapping) or not all(isinstance(key, str) for key in payload):
            raise QualificationError("event payload invalid")
        body: dict[str, object] = {
            "schema_version": EVENT_SCHEMA,
            "sequence": sequence,
            "kind": kind,
            "previous_event_sha256": previous,
            "payload": dict(payload),
            "payload_sha256": canonical_sha256(payload),
        }
        event = {**body, "event_sha256": canonical_sha256(body)}
        result.append(event)
        previous = str(event["event_sha256"])
    return result


def _verify_event_chain(events: object, matrix: QualificationMatrix) -> list[Mapping[str, object]]:
    if not isinstance(events, list):
        raise QualificationError("event chain invalid")
    kinds: list[str] = []
    previous = "0" * 64
    verified: list[Mapping[str, object]] = []
    for expected_sequence, value in enumerate(events, start=1):
        item = _mapping(
            value,
            label="event",
            fields=frozenset(
                {
                    "schema_version",
                    "sequence",
                    "kind",
                    "previous_event_sha256",
                    "payload",
                    "payload_sha256",
                    "event_sha256",
                }
            ),
        )
        if item["schema_version"] != EVENT_SCHEMA or item["sequence"] != expected_sequence:
            raise QualificationError("event sequence invalid")
        if item["previous_event_sha256"] != previous:
            raise QualificationError("event chain link invalid")
        payload = item["payload"]
        if not isinstance(payload, Mapping) or canonical_sha256(payload) != item["payload_sha256"]:
            raise QualificationError("event payload digest invalid")
        body = {key: value for key, value in item.items() if key != "event_sha256"}
        if canonical_sha256(body) != item["event_sha256"]:
            raise QualificationError("event digest invalid")
        kinds.append(_string(item["kind"], label="event kind", pattern=_TOKEN))
        previous = _sha(item["event_sha256"], label="event digest")
        verified.append(item)
    if tuple(kinds) != _expected_event_kinds(len(matrix.stages)):
        raise QualificationError("formal event lifecycle invalid")
    return verified


def _expected_event_payloads(
    preflight: Mapping[str, object],
    projection: ExecutionProjection,
    matrix: QualificationMatrix,
    stage_results: Sequence[Mapping[str, object]],
    result: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    payloads: list[Mapping[str, object]] = [
        {"preflight_sha256": preflight["preflight_sha256"]},
        {"attempt_id": projection.attempt_id},
    ]
    payloads.extend(
        {
            "stage_id": stage.stage_id,
            "stage_result_sha256": stage_result["stage_result_sha256"],
        }
        for stage, stage_result in zip(matrix.stages, stage_results, strict=True)
    )
    payloads.append({"result_sha256": result["result_sha256"]})
    return tuple(payloads)


def _verify_ceremony_cross_bindings(
    matrix: QualificationMatrix,
    projection: ExecutionProjection,
    preflight: object,
    stage_results: object,
    artifacts: Mapping[str, str],
    events: Sequence[Mapping[str, object]],
    result: Mapping[str, object],
) -> tuple[Mapping[str, object], tuple[Mapping[str, object], ...]]:
    # CRITICAL: independent valid hashes are insufficient; every retained file must bind to the
    # same preflight, ordered stage results, event lifecycle, and terminal result.
    verified_preflight = _verify_preflight_record(matrix, projection, preflight)
    if not isinstance(stage_results, list) or len(stage_results) != len(matrix.stages):
        raise QualificationError("qualification stage result lifecycle incomplete")
    verified_stage_results = tuple(
        _parse_stage_result(value, stage) for value, stage in zip(stage_results, matrix.stages, strict=True)
    )
    expected_payloads = _expected_event_payloads(
        verified_preflight,
        projection,
        matrix,
        verified_stage_results,
        result,
    )
    if len(events) != len(expected_payloads):
        raise QualificationError("qualification event lifecycle binding incomplete")
    for event, expected_payload in zip(events, expected_payloads, strict=True):
        if event["payload"] != expected_payload:
            raise QualificationError("qualification event payload binding mismatch")

    canonical_records = {
        "preflight.json": canonical_bytes(verified_preflight) + b"\n",
        "stage-results.json": canonical_bytes(list(verified_stage_results)) + b"\n",
        "events.jsonl": b"".join(canonical_bytes(event) + b"\n" for event in events),
    }
    for path, payload in canonical_records.items():
        if artifacts.get(path) != hashlib.sha256(payload).hexdigest():
            raise QualificationError(f"qualification canonical record binding mismatch: {path}")

    for stage, stage_result in zip(matrix.stages, verified_stage_results, strict=True):
        stdout_path = f"stages/{stage.stage_id}.stdout.log"
        stderr_path = f"stages/{stage.stage_id}.stderr.log"
        if artifacts.get(stdout_path) != stage_result["stdout_sha256"]:
            raise QualificationError(f"qualification stage stdout binding mismatch: {stage.stage_id}")
        if artifacts.get(stderr_path) != stage_result["stderr_sha256"]:
            raise QualificationError(f"qualification stage stderr binding mismatch: {stage.stage_id}")
        stage_artifacts = stage_result["artifact_sha256"]
        if not isinstance(stage_artifacts, Mapping):
            raise QualificationError("qualification stage artifact binding invalid")
        for path in stage.expected_artifacts:
            if stage_artifacts.get(path) != artifacts.get(path):
                raise QualificationError(f"qualification stage artifact binding mismatch: {stage.stage_id}")
    return verified_preflight, verified_stage_results


def build_bundle(
    matrix: QualificationMatrix,
    projection: ExecutionProjection,
    preflight: Mapping[str, object],
    stage_results: Sequence[object],
    artifact_sha256: Mapping[str, str],
    events: Sequence[Mapping[str, object]],
    *,
    protocol_drift: bool,
) -> dict[str, object]:
    artifacts = {
        _safe_relative_path(path, label="retained artifact path"): _sha(digest, label="retained artifact digest")
        for path, digest in artifact_sha256.items()
    }
    artifact_inventory_complete = tuple(sorted(artifacts)) == matrix.retained_artifacts
    if not set(artifacts).issubset(matrix.retained_artifacts):
        raise QualificationError("retained artifact inventory invalid")
    verified_events = _verify_event_chain(list(events), matrix)
    result = compute_disposition(
        matrix,
        stage_results,
        protocol_drift=protocol_drift,
        artifacts_complete=artifact_inventory_complete,
    )
    verified_preflight, verified_stage_results = _verify_ceremony_cross_bindings(
        matrix,
        projection,
        preflight,
        list(stage_results),
        artifacts,
        verified_events,
        result,
    )
    body: dict[str, object] = {
        "schema_version": BUNDLE_SCHEMA,
        "attempt_id": projection.attempt_id,
        "candidate_commit": projection.candidate_commit,
        "candidate_tree": projection.candidate_tree,
        "candidate_parent_commit": projection.candidate_parent_commit,
        "matrix_sha256": matrix.matrix_sha256,
        "projection_sha256": projection.projection_sha256,
        "private_manifest_sha256": projection.private_manifest_sha256,
        "trust_anchor_sha256": projection.trust_anchor_sha256,
        "preflight": dict(verified_preflight),
        "stage_results": [dict(stage_result) for stage_result in verified_stage_results],
        "artifact_sha256": dict(sorted(artifacts.items())),
        "events": [dict(event) for event in verified_events],
        "result": result,
        "formal_result_only": True,
        "execution_authority": False,
        "remote_authority": False,
        "release_authority": False,
        "go_authority": False,
        "ga_authority": False,
    }
    return {**body, "bundle_sha256": canonical_sha256(body)}


def parse_pins(payload: object) -> Mapping[str, object]:
    item = _mapping(
        payload,
        label="verification pins",
        fields=frozenset(
            {
                "schema_version",
                "matrix_sha256",
                "projection_sha256",
                "candidate_commit",
                "candidate_tree",
                "private_manifest_sha256",
                "trust_anchor_sha256",
                "pins_sha256",
            }
        ),
    )
    if item["schema_version"] != PINS_SCHEMA:
        raise QualificationError("verification pins schema invalid")
    body = {key: value for key, value in item.items() if key != "pins_sha256"}
    if canonical_sha256(body) != _sha(item["pins_sha256"], label="pins digest"):
        raise QualificationError("verification pins digest mismatch")
    _sha(item["matrix_sha256"], label="pinned matrix digest")
    _sha(item["projection_sha256"], label="pinned projection digest")
    _git_oid(item["candidate_commit"], label="pinned candidate commit")
    _git_oid(item["candidate_tree"], label="pinned candidate tree")
    _sha(item["private_manifest_sha256"], label="pinned private manifest digest")
    _sha(item["trust_anchor_sha256"], label="pinned trust anchor digest")
    return item


def verify_bundle(
    matrix: QualificationMatrix,
    projection: ExecutionProjection,
    bundle: object,
    pins: object,
    artifact_payloads: Mapping[str, bytes],
) -> dict[str, object]:
    item = _mapping(
        bundle,
        label="qualification bundle",
        fields=frozenset(
            {
                "schema_version",
                "attempt_id",
                "candidate_commit",
                "candidate_tree",
                "candidate_parent_commit",
                "matrix_sha256",
                "projection_sha256",
                "private_manifest_sha256",
                "trust_anchor_sha256",
                "preflight",
                "stage_results",
                "artifact_sha256",
                "events",
                "result",
                "formal_result_only",
                "execution_authority",
                "remote_authority",
                "release_authority",
                "go_authority",
                "ga_authority",
                "bundle_sha256",
            }
        ),
    )
    if item["schema_version"] != BUNDLE_SCHEMA:
        raise QualificationError("qualification bundle schema invalid")
    body = {key: value for key, value in item.items() if key != "bundle_sha256"}
    supplied_bundle_digest = _sha(item["bundle_sha256"], label="bundle digest")
    if canonical_sha256(body) != supplied_bundle_digest:
        raise QualificationError("qualification bundle digest mismatch")
    pin_values = parse_pins(pins)
    expected_bindings = {
        "matrix_sha256": matrix.matrix_sha256,
        "projection_sha256": projection.projection_sha256,
        "candidate_commit": projection.candidate_commit,
        "candidate_tree": projection.candidate_tree,
        "private_manifest_sha256": projection.private_manifest_sha256,
        "trust_anchor_sha256": projection.trust_anchor_sha256,
    }
    for key, expected in expected_bindings.items():
        if item[key] != expected or pin_values[key] != expected:
            raise QualificationError(f"qualification {key} binding mismatch")
    if (
        item["attempt_id"] != projection.attempt_id
        or item["candidate_parent_commit"] != projection.candidate_parent_commit
    ):
        raise QualificationError("qualification candidate lineage mismatch")

    stage_values = item["stage_results"]
    if not isinstance(stage_values, list):
        raise QualificationError("qualification stage results invalid")
    recomputed_result = compute_disposition(
        matrix,
        stage_values,
        protocol_drift=bool(item["result"].get("protocol_drift")) if isinstance(item["result"], Mapping) else True,
        artifacts_complete=(
            isinstance(item["artifact_sha256"], Mapping)
            and tuple(sorted(item["artifact_sha256"])) == matrix.retained_artifacts
        ),
    )
    if recomputed_result != item["result"]:
        raise QualificationError("qualification result mismatch")
    verified_events = _verify_event_chain(item["events"], matrix)

    artifact_values = item["artifact_sha256"]
    if not isinstance(artifact_values, Mapping) or not set(artifact_values).issubset(matrix.retained_artifacts):
        raise QualificationError("qualification artifact inventory invalid")
    if tuple(sorted(artifact_payloads)) != tuple(sorted(artifact_values)):
        raise QualificationError("offline artifact payload inventory invalid")
    for path in sorted(artifact_values):
        expected_digest = _sha(artifact_values[path], label="bundle artifact digest")
        if hashlib.sha256(artifact_payloads[path]).hexdigest() != expected_digest:
            raise QualificationError(f"offline artifact digest mismatch: {path}")

    _verify_ceremony_cross_bindings(
        matrix,
        projection,
        item["preflight"],
        stage_values,
        artifact_values,
        verified_events,
        recomputed_result,
    )
    canonical_payloads = {
        "preflight.json": canonical_bytes(item["preflight"]) + b"\n",
        "stage-results.json": canonical_bytes(stage_values) + b"\n",
        "events.jsonl": b"".join(canonical_bytes(event) + b"\n" for event in verified_events),
    }
    for path, expected_payload in canonical_payloads.items():
        if artifact_payloads.get(path) != expected_payload:
            raise QualificationError(f"offline canonical record mismatch: {path}")

    for authority_field in (
        "formal_result_only",
        "execution_authority",
        "remote_authority",
        "release_authority",
        "go_authority",
        "ga_authority",
    ):
        expected_authority_value = authority_field == "formal_result_only"
        if item[authority_field] is not expected_authority_value:
            raise QualificationError("qualification authority boundary invalid")

    return {
        "verified": True,
        "attempt_id": projection.attempt_id,
        "candidate_commit": projection.candidate_commit,
        "candidate_tree": projection.candidate_tree,
        "disposition": recomputed_result["disposition"],
        "bundle_sha256": supplied_bundle_digest,
        "execution_authority": False,
        "remote_authority": False,
        "release_authority": False,
        "go_authority": False,
        "ga_authority": False,
    }
