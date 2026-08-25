"""Qualified in-memory Schemathesis adapter with no transport authority."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

import schemathesis
from schemathesis.core import NOT_SET

from redagent_platform.api_differential_service.compiler import CompiledDifferentialCase
from redagent_platform.api_differential_service.contracts import SCHEMATHESIS_VERSION
from redagent_platform.api_differential_service.specification import (
    OpenApiSnapshot,
    validate_and_snapshot_spec,
)


_MAX_PUBLIC_CASE_BYTES = 4_096


@dataclass(frozen=True, kw_only=True)
class GeneratedPublicCase:
    operation_id: str
    method: str
    path_parameters: tuple[tuple[str, object], ...]
    query: tuple[tuple[str, object], ...]
    body: object | None
    headers: tuple[tuple[str, str], ...]
    cookies: tuple[tuple[str, str], ...]
    serialized_size_bytes: int


def load_certified_generator_schema(snapshot: OpenApiSnapshot):
    if schemathesis.__version__ != SCHEMATHESIS_VERSION:
        raise ValueError("api_generator_version_drift")
    document = json.loads(snapshot.canonical_bytes)
    verified = validate_and_snapshot_spec(document)
    if verified.spec_sha256 != snapshot.spec_sha256:
        raise ValueError("api_generator_spec_drift")
    # CRITICAL: generator schemas contain no security material; the compat_106 gateway alone resolves opaque identity handles.
    document.pop("security", None)
    components = document.get("components")
    if isinstance(components, dict):
        components.pop("securitySchemes", None)
    paths = document.get("paths", {})
    if isinstance(paths, dict):
        for path_item in paths.values():
            if isinstance(path_item, dict):
                for operation in path_item.values():
                    if isinstance(operation, dict):
                        operation.pop("security", None)
    return schemathesis.openapi.from_dict(document)


def strategy_for_operation(schema: Any, compiled: CompiledDifferentialCase, *, negative: bool):
    try:
        operation = schema[compiled.path_template][compiled.method]
    except (KeyError, TypeError) as exc:
        raise ValueError("api_generator_operation_missing") from exc
    raw = operation.definition.raw
    if not isinstance(raw, dict) or raw.get("operationId") != compiled.operation_id:
        raise ValueError("api_generator_operation_mismatch")
    mode = schemathesis.GenerationMode.NEGATIVE if negative else schemathesis.GenerationMode.POSITIVE
    return operation.as_strategy(generation_mode=mode)


def generated_public_case(case: schemathesis.Case, compiled: CompiledDifferentialCase) -> GeneratedPublicCase:
    raw = case.operation.definition.raw
    if (
        not isinstance(raw, dict) or raw.get("operationId") != compiled.operation_id
        or case.method != compiled.method or case.path != compiled.path_template
    ):
        raise ValueError("api_generated_operation_mismatch")
    if case.headers or case.cookies:
        raise ValueError("api_generated_transport_material_forbidden")
    body = None if case.body is NOT_SET else case.body
    payload = {
        "operation_id": compiled.operation_id,
        "method": compiled.method,
        "path_parameters": case.path_parameters or {},
        "query": case.query or {},
        "body": body,
    }
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("api_generated_case_not_serializable") from exc
    if len(encoded) > _MAX_PUBLIC_CASE_BYTES:
        raise ValueError("api_generated_case_too_large")
    return GeneratedPublicCase(
        operation_id=compiled.operation_id,
        method=compiled.method,
        path_parameters=tuple(sorted((case.path_parameters or {}).items())),
        query=tuple(sorted((case.query or {}).items())),
        body=body,
        headers=(),
        cookies=(),
        serialized_size_bytes=len(encoded),
    )
