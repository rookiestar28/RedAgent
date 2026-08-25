"""Monotonic compat_100 capability projection into narrow compat_113 model-facing tools."""

from __future__ import annotations

from dataclasses import asdict
from enum import Enum
import hashlib
import json
from typing import Mapping

from redagent_platform.agent_kernel.contracts import ModelBudget, ProjectedTool, ToolKind
from redagent_platform.runner_service.contracts import ExecutionCapabilityManifest, canonical_capability_sha256


_FORBIDDEN = frozenset({
    "command", "argv", "shell", "script", "code", "url", "http", "browser", "credential",
    "secret", "token", "password", "policy", "approval", "evidence_export", "runner", "dispatch",
    "plugin", "template", "flags", "image", "mounts", "environment",
})


def project_capability(
    capability: ExecutionCapabilityManifest,
    *,
    input_schema: Mapping[str, object],
    output_schema: Mapping[str, object],
    description: str,
    approval_tier: str,
    budget: ModelBudget,
) -> ProjectedTool:
    # CRITICAL: model-facing projection may narrow an compat_100 manifest but must never add authority.
    if capability.status != "certified":
        raise ValueError("capability_not_certified")
    _validate_strict_schema(input_schema)
    _validate_strict_schema(output_schema)
    _reject_forbidden_fields(input_schema)
    _reject_forbidden_fields(output_schema)
    if capability.network_mode.value == "host":
        raise ValueError("capability_network_broadened")
    return ProjectedTool(
        fully_qualified_name=f"redagent.{capability.capability_id}.propose.v1",
        tool_kind=ToolKind.PROPOSAL,
        description=description,
        description_sha256=_sha256_text(description),
        input_schema=dict(input_schema),
        input_schema_sha256=_schema_sha256(input_schema),
        output_schema_sha256=_schema_sha256(output_schema),
        source_capability_id=capability.capability_id,
        source_capability_revision=capability.revision,
        source_capability_sha256=canonical_capability_sha256(capability),
        adapter_id=capability.adapter_id,
        adapter_version=capability.adapter_version,
        network_mode=capability.network_mode.value,
        credential_class=capability.credential_class.value,
        approval_tier=approval_tier,
        budget=budget,
        unsupported_features=capability.unsupported_features,
    )


def canonical_projected_tool_sha256(tool: ProjectedTool) -> str:
    """Hash one compat_113 projection without changing its model-facing contract."""
    if not isinstance(tool, ProjectedTool):
        raise ValueError("tool_projection_type_invalid")
    encoded = json.dumps(
        _normalize(asdict(tool)), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_strict_schema(schema: Mapping[str, object]) -> None:
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise ValueError("tool_schema_not_strict")
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, Mapping) or not isinstance(required, list) or set(required) != set(properties):
        raise ValueError("tool_schema_not_strict")
    for value in properties.values():
        if isinstance(value, Mapping) and value.get("type") == "object":
            _validate_strict_schema(value)


def _reject_forbidden_fields(value: object) -> None:
    # CRITICAL: schema fields are an authorization surface, not harmless model metadata.
    if isinstance(value, Mapping):
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            for field in properties:
                if str(field).lower() in _FORBIDDEN:
                    raise ValueError("tool_schema_forbidden_field")
        for nested in value.values():
            _reject_forbidden_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_forbidden_fields(nested)


def _schema_sha256(schema: Mapping[str, object]) -> str:
    return hashlib.sha256(json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value
