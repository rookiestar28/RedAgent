from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Iterable

from redagent_platform.validation.config import PathMappingConfig, load_path_mapping
from redagent_platform.validation.stages import (
    ValidationConfigError,
    stage_ids_for_gate,
)


DEFAULT_PATH_MAPPING = Path(__file__).resolve().parents[2] / "config/validation/r118-path-mapping.json"
_REVISION = re.compile(r"^[0-9a-fA-F]{7,64}$")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:/")
_HIGH_RISK_PLANES = {
    "public_api",
    "database",
    "identity_policy_security",
    "workflow",
    "runner_execution",
    "infrastructure_release",
    "validator_test",
}
_PROTECTED_EXACT_PATHS = {
    ".pre-commit-config.yaml",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "scripts/run_full_tests_linux.sh",
    "scripts/run_full_tests_windows.ps1",
    "scripts/run_validation_gate.py",
    "scripts/validate_secure_sdlc.py",
    "redagent_platform/gate_lease.py",
}
_FALLBACK_CLASSIFIER_REVISION = "r118-classifier-fallback-v1"
_MAX_SELECTIVE_PATHS = 50
_MAX_SELECTIVE_PATH_BYTES = 24_000
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[/\\\s])(?:[a-z0-9]+[_-])*(?:secret[_-]?access[_-]?key|"
    r"access[_-]?key[_-]?id|api[_-]?(?:key|token)|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|session[_-]?id|authorization|token|"
    r"secret|password|credential|cookie|database[_-]?url)\s*[:=]"
)
_AUTHORITY_STEMS = {"promotion", "qualification", "release", "provenance", "secret_scan"}


def _protected_plane(path: str) -> str | None:
    lowered = path.casefold()
    if lowered.startswith("redagent_platform/") and PurePosixPath(lowered).stem in _AUTHORITY_STEMS:
        return "infrastructure_release"
    if lowered.startswith((".github/workflows/", "config/validation/")):
        return "workflow"
    if lowered.startswith((
        "redagent_platform/artifact_pipeline/",
        "redagent_platform/ga_qualification/",
    )):
        return "infrastructure_release"
    if lowered in _PROTECTED_EXACT_PATHS or lowered.startswith(
        ("redagent_platform/validation/", "tests/")
    ):
        return "validator_test"
    # CRITICAL: root modules are cross-cutting authority/runtime boundaries in
    # this repository. Conservatively route present and future root Python
    # modules to G2 instead of relying on an inevitably incomplete name list.
    if lowered.startswith("redagent_platform/") and lowered.endswith(".py") and lowered.count("/") == 1:
        return "runner_execution"
    return None


@dataclass(frozen=True, slots=True)
class ChangeRequest:
    base_revision: str | None
    head_revision: str
    changed_paths: tuple[str, ...]
    force_full: bool = False
    ci_context: str | None = None


@dataclass(frozen=True, slots=True)
class GateDecision:
    classifier_revision: str
    selected_gate: str
    planes: tuple[str, ...]
    normalized_paths: tuple[str, ...]
    reasons: tuple[str, ...]
    required_stage_ids: tuple[str, ...]
    skipped_stage_ids: tuple[str, ...]
    changed_path_count: int
    changed_path_digest: str
    decision_digest: str


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _normalize_paths(paths: Iterable[str]) -> tuple[tuple[str, ...], str | None]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_path in paths:
        if not isinstance(raw_path, str) or not raw_path or any(ord(char) < 32 for char in raw_path):
            return (), "invalid_path"
        candidate = raw_path.replace("\\", "/")
        if candidate.startswith("/") or _WINDOWS_ABSOLUTE.match(candidate):
            return (), "invalid_path"
        parts = PurePosixPath(candidate).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            return (), "invalid_path"
        clean = "/".join(parts)
        folded = clean.casefold()
        if folded in seen:
            return (), "duplicate_normalized_path"
        seen.add(folded)
        normalized.append(clean)
    return tuple(sorted(normalized, key=str.casefold)), None


def _classify_path(path: str, mapping: PathMappingConfig) -> str | None:
    lowered = path.casefold()
    name = PurePosixPath(lowered).name
    for rule in mapping.rules:
        if lowered in rule.exact_paths:
            return rule.plane
        if any(lowered.startswith(prefix) for prefix in rule.prefixes):
            return rule.plane
        if any(name.startswith(prefix) for prefix in rule.name_prefixes):
            return rule.plane
        if any(fragment in lowered for fragment in rule.contains):
            return rule.plane
    return None


@lru_cache(maxsize=1)
def _default_mapping() -> PathMappingConfig:
    return load_path_mapping(DEFAULT_PATH_MAPPING)


def _stage_ids(
    gate: str,
    planes: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return stage_ids_for_gate(gate, planes)


def _decision(
    *,
    gate: str,
    planes: tuple[str, ...],
    paths: tuple[str, ...],
    reasons: tuple[str, ...],
    classifier_revision: str,
) -> GateDecision:
    required, skipped = _stage_ids(gate, planes)
    evidence = {
        "classifier_revision": classifier_revision,
        "selected_gate": gate,
        "planes": planes,
        "reasons": reasons,
        "required_stage_ids": required,
        "skipped_stage_ids": skipped,
        "changed_path_count": len(paths),
        "changed_path_digest": _canonical_digest(paths),
    }
    return GateDecision(
        normalized_paths=paths,
        **evidence,
        decision_digest=_canonical_digest(evidence),
    )


def decision_evidence_payload(decision: GateDecision) -> dict[str, object]:
    """Return the minimized, secret-free decision fields allowed in retained evidence."""

    return {
        "classifier_revision": decision.classifier_revision,
        "selected_gate": decision.selected_gate,
        "planes": decision.planes,
        "reasons": decision.reasons,
        "required_stage_ids": decision.required_stage_ids,
        "skipped_stage_ids": decision.skipped_stage_ids,
        "changed_path_count": decision.changed_path_count,
        "changed_path_digest": decision.changed_path_digest,
        "decision_digest": decision.decision_digest,
    }


def classify_change(
    request: ChangeRequest,
    *,
    mapping: PathMappingConfig | None = None,
) -> GateDecision:
    """Classify repository changes; every ambiguity deterministically selects G2."""

    try:
        active_mapping = mapping or _default_mapping()
    except ValidationConfigError:
        return _decision(
            gate="G2",
            planes=(),
            paths=(),
            reasons=("classifier_config_error",),
            classifier_revision=_FALLBACK_CLASSIFIER_REVISION,
        )

    def decide(
        gate: str,
        planes: tuple[str, ...] = (),
        paths: tuple[str, ...] = (),
        reasons: tuple[str, ...] = (),
    ) -> GateDecision:
        return _decision(
            gate=gate,
            planes=planes,
            paths=paths,
            reasons=reasons,
            classifier_revision=active_mapping.classifier_revision,
        )

    paths, path_error = _normalize_paths(request.changed_paths)
    if path_error:
        return decide("G2", reasons=(path_error,))
    if len(paths) > active_mapping.max_changed_paths:
        return decide("G2", paths=paths, reasons=("changed_path_limit_exceeded",))
    if any(_SECRET_ASSIGNMENT.search(path) for path in paths):
        return decide("G2", paths=paths, reasons=("secret_like_path",))
    if (
        len(paths) > _MAX_SELECTIVE_PATHS
        or sum(len(path.encode("utf-8")) + 1 for path in paths) > _MAX_SELECTIVE_PATH_BYTES
    ):
        return decide("G2", paths=paths, reasons=("selective_command_budget_exceeded",))
    if request.force_full:
        return decide("G2", paths=paths, reasons=("force_full",))
    if request.base_revision is None:
        return decide("G2", paths=paths, reasons=("missing_base_revision",))
    if not _REVISION.fullmatch(request.base_revision) or not _REVISION.fullmatch(request.head_revision):
        return decide("G2", paths=paths, reasons=("invalid_revision",))
    if not paths:
        return decide("G2", reasons=("ambiguous_empty_diff",))
    protected_planes = tuple(sorted({_protected_plane(path) for path in paths} - {None}))
    if protected_planes:
        return decide("G2", protected_planes, paths, ("protected_validation_change",))

    mapped = tuple(_classify_path(path, active_mapping) for path in paths)
    if any(plane is None for plane in mapped):
        known = tuple(sorted({plane for plane in mapped if plane is not None}))
        return decide("G2", known, paths, ("unknown_path",))
    planes = tuple(sorted(set(mapped)))  # type: ignore[arg-type]
    if any(plane in _HIGH_RISK_PLANES for plane in planes):
        return decide("G2", planes, paths, ("high_risk_plane",))
    if planes == ("documentation",):
        return decide("G0", planes, paths, ("isolated_low_risk",))
    return decide("G1", planes, paths, ("mapped_plane_suite",))
