"""Deterministic, data-only compat_108 IaC/image/filesystem evaluation engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Mapping


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class OfflineCheckKind(str, Enum):
    IAC = "iac"
    IMAGE = "image"
    FILESYSTEM = "filesystem"


@dataclass(frozen=True, kw_only=True)
class OfflineArtifactBinding:
    engine_id: str
    engine_sha256: str
    policy_pack_id: str
    policy_sha256: str
    database_id: str
    database_sha256: str
    network_allowed: bool
    subprocess_allowed: bool
    repository_config_allowed: bool
    external_modules_allowed: bool
    max_files: int
    max_bytes: int
    max_results: int

    def __post_init__(self) -> None:
        for value in (self.engine_id, self.policy_pack_id, self.database_id):
            _identifier(value)
        for value in (self.engine_sha256, self.policy_sha256, self.database_sha256):
            _sha(value)
        # CRITICAL: offline inputs and rule bundles are untrusted data and must never gain code or network execution.
        if (
            self.network_allowed
            or self.subprocess_allowed
            or self.repository_config_allowed
            or self.external_modules_allowed
        ):
            raise ValueError("offline_sandbox_not_closed")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 1
            for value in (self.max_files, self.max_bytes, self.max_results)
        ):
            raise ValueError("offline_budget_invalid")


@dataclass(frozen=True, kw_only=True)
class OfflineInput:
    input_id: str
    kind: OfflineCheckKind
    input_sha256: str
    files: tuple[Mapping[str, object], ...]

    def __post_init__(self) -> None:
        _identifier(self.input_id)
        _sha(self.input_sha256)
        if not self.files:
            raise ValueError("offline_input_required")
        for item in self.files:
            raw_path = item.get("path")
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise ValueError("offline_path_invalid")
            path = PurePosixPath(raw_path)
            if path.is_absolute() or ".." in path.parts or "\\" in raw_path:
                raise ValueError("offline_path_escape_denied")
            if item.get("symlink") is True:
                raise ValueError("offline_symlink_denied")


@dataclass(frozen=True, kw_only=True)
class OfflineCheck:
    check_id: str
    kind: OfflineCheckKind
    attribute: str
    expected: object
    severity: str

    def __post_init__(self) -> None:
        _identifier(self.check_id)
        if not self.attribute.strip() or self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("offline_check_invalid")


@dataclass(frozen=True, kw_only=True)
class OfflineCheckResult:
    check_id: str
    resource_id: str
    path: str
    passed: bool
    severity: str


@dataclass(frozen=True, kw_only=True)
class OfflineEvaluation:
    input_id: str
    input_sha256: str
    engine_sha256: str
    policy_sha256: str
    database_sha256: str
    evaluated_at: datetime
    results: tuple[OfflineCheckResult, ...]
    result_sha256: str


def offline_input_digest(*, kind: OfflineCheckKind, files: tuple[Mapping[str, object], ...]) -> str:
    material = {"kind": kind.value, "files": _canonical_files(files)}
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def evaluate_offline(
    *,
    binding: OfflineArtifactBinding,
    input_data: OfflineInput,
    checks: tuple[OfflineCheck, ...],
    evaluated_at: datetime,
) -> OfflineEvaluation:
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("offline_time_invalid")
    if len(input_data.files) > binding.max_files:
        raise ValueError("offline_input_limit_exceeded")
    total_bytes = 0
    for item in input_data.files:
        size = item.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("offline_input_size_invalid")
        total_bytes += size
    if total_bytes > binding.max_bytes:
        raise ValueError("offline_input_limit_exceeded")
    if any(check.kind is not input_data.kind for check in checks):
        raise ValueError("offline_check_kind_mismatch")
    if offline_input_digest(kind=input_data.kind, files=input_data.files) != input_data.input_sha256:
        raise ValueError("offline_input_digest_mismatch")

    rows: list[OfflineCheckResult] = []
    for item in input_data.files:
        path = str(item["path"])
        resources = item.get("resources", ())
        if not isinstance(resources, (list, tuple)):
            raise ValueError("offline_resource_contract_invalid")
        for resource in resources:
            if not isinstance(resource, dict):
                raise ValueError("offline_resource_contract_invalid")
            resource_id = resource.get("resource_id")
            if not isinstance(resource_id, str) or not resource_id.strip():
                raise ValueError("offline_resource_identity_required")
            for check in checks:
                rows.append(
                    OfflineCheckResult(
                        check_id=check.check_id,
                        resource_id=resource_id.strip(),
                        path=path,
                        passed=resource.get(check.attribute) == check.expected,
                        severity=check.severity,
                    )
                )
                if len(rows) > binding.max_results:
                    raise ValueError("offline_result_limit_exceeded")
    results = tuple(sorted(rows, key=lambda row: (row.resource_id, row.check_id, row.path)))
    material = {
        "schema": "redagent.r108-offline-result/v1",
        "input_sha256": input_data.input_sha256,
        "engine_sha256": binding.engine_sha256,
        "policy_sha256": binding.policy_sha256,
        "database_sha256": binding.database_sha256,
        "evaluated_at": evaluated_at.isoformat(),
        "results": [
            [row.check_id, row.resource_id, row.path, row.passed, row.severity] for row in results
        ],
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return OfflineEvaluation(
        input_id=input_data.input_id,
        input_sha256=input_data.input_sha256,
        engine_sha256=binding.engine_sha256,
        policy_sha256=binding.policy_sha256,
        database_sha256=binding.database_sha256,
        evaluated_at=evaluated_at,
        results=results,
        result_sha256=digest,
    )


def _canonical_files(files: tuple[Mapping[str, object], ...]) -> list[dict[str, object]]:
    return [dict(sorted(item.items())) for item in sorted(files, key=lambda value: str(value.get("path", "")))]


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("offline_identifier_invalid")


def _sha(value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("offline_sha256_invalid")
