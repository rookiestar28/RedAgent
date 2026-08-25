from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from redagent_platform.validation.stages import ValidationConfigError


_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:/")
_PLANES = {
    "documentation",
    "governance",
    "backend",
    "public_api",
    "database",
    "identity_policy_security",
    "workflow",
    "runner_execution",
    "evidence_reporting",
    "connector_integration",
    "frontend",
    "infrastructure_release",
    "validator_test",
}


@dataclass(frozen=True, slots=True)
class PathRule:
    plane: str
    prefixes: tuple[str, ...] = ()
    exact_paths: tuple[str, ...] = ()
    name_prefixes: tuple[str, ...] = ()
    contains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PathMappingConfig:
    schema_version: str
    classifier_revision: str
    max_changed_paths: int
    rules: tuple[PathRule, ...]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationConfigError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_strict_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except ValidationConfigError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationConfigError(f"invalid JSON configuration: {path.name}") from exc
    if not isinstance(payload, dict):
        raise ValidationConfigError("configuration root must be an object")
    return payload


def _closed_keys(payload: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(payload) - allowed
    missing = allowed - set(payload)
    if unknown:
        raise ValidationConfigError(f"unknown {context} keys: {sorted(unknown)}")
    if missing:
        raise ValidationConfigError(f"missing {context} keys: {sorted(missing)}")


def _safe_pattern(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ValidationConfigError(f"invalid {context} pattern")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or _WINDOWS_ABSOLUTE.match(normalized):
        raise ValidationConfigError(f"unsafe {context} path")
    if ".." in PurePosixPath(normalized).parts:
        raise ValidationConfigError(f"unsafe {context} path")
    return normalized.casefold()


def _string_tuple(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValidationConfigError(f"{context} must be a list")
    values = tuple(_safe_pattern(item, context) for item in value)
    if len(values) != len(set(values)):
        raise ValidationConfigError(f"duplicate {context} pattern")
    return values


def load_path_mapping(path: Path) -> PathMappingConfig:
    payload = load_strict_json(path)
    _closed_keys(
        payload,
        {"schema_version", "classifier_revision", "max_changed_paths", "rules"},
        "path-mapping",
    )
    if payload["schema_version"] != "1":
        raise ValidationConfigError("unsupported path-mapping schema version")
    if not isinstance(payload["classifier_revision"], str) or not payload["classifier_revision"]:
        raise ValidationConfigError("classifier revision is invalid")
    limit = payload["max_changed_paths"]
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 5000:
        raise ValidationConfigError("max_changed_paths is invalid")
    raw_rules = payload["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValidationConfigError("path mapping rules must be a non-empty list")
    rules: list[PathRule] = []
    allowed_rule_keys = {"plane", "prefixes", "exact_paths", "name_prefixes", "contains"}
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            raise ValidationConfigError("path mapping rule must be an object")
        unknown = set(raw_rule) - allowed_rule_keys
        if unknown:
            raise ValidationConfigError(f"unknown path-rule keys: {sorted(unknown)}")
        if "plane" not in raw_rule:
            raise ValidationConfigError("path mapping rule plane is required")
        plane = raw_rule["plane"]
        if plane not in _PLANES:
            raise ValidationConfigError("path mapping plane is invalid")
        rule = PathRule(
            plane=plane,
            prefixes=_string_tuple(raw_rule.get("prefixes", []), "prefix"),
            exact_paths=_string_tuple(raw_rule.get("exact_paths", []), "exact-path"),
            name_prefixes=_string_tuple(raw_rule.get("name_prefixes", []), "name-prefix"),
            contains=_string_tuple(raw_rule.get("contains", []), "contains"),
        )
        if not (rule.prefixes or rule.exact_paths or rule.name_prefixes or rule.contains):
            raise ValidationConfigError("path mapping rule has no matcher")
        rules.append(rule)
    return PathMappingConfig(
        schema_version="1",
        classifier_revision=payload["classifier_revision"],
        max_changed_paths=limit,
        rules=tuple(rules),
    )
