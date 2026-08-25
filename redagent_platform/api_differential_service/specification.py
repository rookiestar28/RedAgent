"""Bounded, no-network OpenAPI intake for R106."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping

from redagent_platform.api_differential_service.contracts import GATEWAY_ORIGIN, OperationRisk


_MAX_CANONICAL_BYTES = 256 * 1024
_MAX_NODES = 5_000
_MAX_DEPTH = 32
_MAX_STRING = 8_192
_ALLOWED_ROOT_KEYS = frozenset({"openapi", "info", "servers", "components", "security", "paths"})
_CERTIFIED_OPERATIONS = {
    "getDocument": ("GET", "/documents/{documentId}", OperationRisk.READ),
    "getAudit": ("GET", "/admin/audit", OperationRisk.ADMIN_READ),
    "getProfile": ("GET", "/profiles/{profileId}", OperationRisk.READ),
    "createDocument": ("POST", "/documents", OperationRisk.CREATE_OWNED),
    "transferDocument": ("POST", "/documents/{documentId}/transfer", OperationRisk.UPDATE_OWNED),
    "deleteDocument": ("DELETE", "/documents/{documentId}", OperationRisk.DELETE_OWNED),
}


@dataclass(frozen=True, kw_only=True)
class OperationSnapshot:
    operation_id: str
    method: str
    path_template: str
    risk: OperationRisk


@dataclass(frozen=True, kw_only=True)
class OpenApiSnapshot:
    spec_sha256: str
    canonical_bytes: bytes
    dialect: str
    server: str
    operation_ids: tuple[str, ...]
    operations: tuple[OperationSnapshot, ...]


def validate_and_snapshot_spec(spec: Mapping[str, object]) -> OpenApiSnapshot:
    if not isinstance(spec, Mapping):
        raise ValueError("api_spec_mapping_required")
    if set(spec) - _ALLOWED_ROOT_KEYS:
        if "webhooks" in spec or "callbacks" in spec:
            raise ValueError("api_spec_callback_forbidden")
        raise ValueError("api_spec_root_field_forbidden")
    dialect = spec.get("openapi")
    if not isinstance(dialect, str) or not (dialect.startswith("3.0.") or dialect.startswith("3.1.")):
        raise ValueError("api_spec_dialect_not_certified")
    servers = spec.get("servers")
    if servers != [{"url": GATEWAY_ORIGIN}]:
        raise ValueError("api_spec_server_forbidden")
    _bounded_walk(spec)
    paths = spec.get("paths")
    if not isinstance(paths, Mapping) or not paths:
        raise ValueError("api_spec_paths_required")
    operations: list[OperationSnapshot] = []
    seen: set[str] = set()
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, Mapping):
            raise ValueError("api_spec_path_invalid")
        for method, operation in path_item.items():
            if str(method).lower() not in {"get", "post", "delete", "parameters"}:
                raise ValueError("api_spec_method_forbidden")
            if str(method).lower() == "parameters":
                continue
            if not isinstance(operation, Mapping):
                raise ValueError("api_spec_operation_invalid")
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or operation_id in seen:
                raise ValueError("api_spec_operation_id_invalid")
            expected = _CERTIFIED_OPERATIONS.get(operation_id)
            if expected is None or expected[:2] != (str(method).upper(), path):
                raise ValueError("api_spec_operation_not_promoted")
            if "callbacks" in operation:
                raise ValueError("api_spec_callback_forbidden")
            seen.add(operation_id)
            operations.append(OperationSnapshot(
                operation_id=operation_id, method=expected[0], path_template=path, risk=expected[2],
            ))
    if seen != set(_CERTIFIED_OPERATIONS):
        raise ValueError("api_spec_operation_inventory_mismatch")
    canonical = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(canonical) > _MAX_CANONICAL_BYTES:
        raise ValueError("api_spec_too_large")
    ordered = tuple(sorted(operations, key=lambda item: item.operation_id))
    return OpenApiSnapshot(
        spec_sha256=hashlib.sha256(canonical).hexdigest(),
        canonical_bytes=canonical,
        dialect=dialect,
        server=GATEWAY_ORIGIN,
        operation_ids=tuple(item.operation_id for item in ordered),
        operations=ordered,
    )


def _bounded_walk(value: object, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > _MAX_NODES or depth > _MAX_DEPTH:
        raise ValueError("api_spec_complexity_exceeded")
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            raise ValueError("api_spec_string_too_large")
        return
    if isinstance(value, Mapping):
        if "callbacks" in value or "webhooks" in value:
            raise ValueError("api_spec_callback_forbidden")
        reference = value.get("$ref")
        if reference is not None and (not isinstance(reference, str) or not reference.startswith("#/")):
            raise ValueError("api_spec_external_reference_forbidden")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > _MAX_STRING:
                raise ValueError("api_spec_key_invalid")
            _bounded_walk(item, depth=depth + 1, counter=counter)
    elif isinstance(value, list):
        for item in value:
            _bounded_walk(item, depth=depth + 1, counter=counter)
    elif value is not None and not isinstance(value, bool | int | float):
        raise ValueError("api_spec_value_invalid")
