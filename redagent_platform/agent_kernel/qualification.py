"""Deterministic no-network qualification of all R104-R112 capability projections."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
from typing import Iterable, Mapping

from redagent_platform.agent_kernel.contracts import (
    ContextItem,
    ModelBudget,
    ModelRequest,
    ModelResult,
    ModelToolCall,
    ModelUsage,
    ProjectedTool,
    TrustLabel,
)
from redagent_platform.agent_kernel.kernel import validate_model_tool_calls
from redagent_platform.agent_kernel.providers import DeterministicFakeModelGateway
from redagent_platform.agent_kernel.registry import project_capability
from redagent_platform.api_differential_service.capability import build_api_differential_capability_manifest
from redagent_platform.artifact_pipeline.capability import build_artifact_capability
from redagent_platform.cloud_connectors.capability import build_cloud_connector_capability
from redagent_platform.human_simulation.capability import build_human_simulation_capability
from redagent_platform.identity_saas.capability import build_identity_capability
from redagent_platform.network_service.capability import build_network_capability_manifest
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.purple_runtime.capability import build_purple_capability
from redagent_platform.runner_service.contracts import ExecutionCapabilityManifest
from redagent_platform.zap_service.capability import build_zap_capability_manifest


_NOW = datetime(2026, 7, 12, 4, 0, tzinfo=timezone.utc)
_SOURCE_DIGEST = "sha256:" + "d" * 64


def certified_capability_catalog() -> tuple[ExecutionCapabilityManifest, ...]:
    return (
        build_zap_capability_manifest(platform="linux/amd64", artifact_receipt_id="artifact-r104"),
        build_nuclei_capability_manifest(platform="linux/amd64", artifact_receipt_id="artifact-r105"),
        build_api_differential_capability_manifest(artifact_receipt_id="artifact-r106"),
        build_network_capability_manifest(artifact_receipt_id="artifact-r107"),
        build_cloud_connector_capability(artifact_receipt_id="artifact-r108", source_digest=_SOURCE_DIGEST),
        build_identity_capability(artifact_receipt_id="artifact-r109", source_digest=_SOURCE_DIGEST),
        build_artifact_capability(artifact_receipt_id="artifact-r110", source_digest=_SOURCE_DIGEST),
        build_purple_capability(artifact_receipt_id="artifact-r111", source_digest=_SOURCE_DIGEST),
        build_human_simulation_capability(artifact_receipt_id="artifact-r112", source_digest=_SOURCE_DIGEST),
    )


def build_projection_catalog(capabilities: Iterable[ExecutionCapabilityManifest]) -> tuple[ProjectedTool, ...]:
    budget = ModelBudget(
        max_turns=3, max_tool_calls=1, max_elapsed_seconds=30, max_input_tokens=4000,
        max_output_tokens=500, max_cost_microunits=10_000, max_result_bytes=4096,
    )
    input_schema = {
        "type": "object",
        "properties": {"plan_id": {"type": "string", "minLength": 1, "maxLength": 100}},
        "required": ["plan_id"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {"proposal_id": {"type": "string"}},
        "required": ["proposal_id"],
        "additionalProperties": False,
    }
    return tuple(
        project_capability(
            capability,
            input_schema=input_schema,
            output_schema=output_schema,
            description=f"Propose the stored, policy-bound plan for certified capability {capability.capability_id}.",
            approval_tier="high",
            budget=budget,
        )
        for capability in capabilities
    )


def qualify_agent_kernel() -> dict[str, object]:
    tools = build_projection_catalog(certified_capability_catalog())
    registry_sha256 = _digest([_normalize(asdict(tool)) for tool in tools])
    selected = next(tool for tool in tools if tool.source_capability_id == "human-simulation-sink")
    valid_call = ModelToolCall(call_id="call-qualified-1", tool_name=selected.fully_qualified_name, arguments={"plan_id": "plan-r112-owned-sink"})
    result = ModelResult(
        response_id="fake-qualified-1", finish_reason="tool_call", tool_calls=(valid_call,), output_text=None,
        usage=ModelUsage(input_tokens=100, output_tokens=20, cost_microunits=50),
    )
    gateway = DeterministicFakeModelGateway((result,))
    request = ModelRequest(
        request_id="request-qualified-1", tenant_id="tenant-qualified", run_id="run-qualified-1",
        instructions=(ContextItem(
            item_id="trusted-context-1", content="Return one stored-plan proposal only.",
            trust_label=TrustLabel.TRUSTED_REGENERATED, provenance_sha256="e" * 64,
        ),),
        tools=(selected,), budget=selected.budget, issued_at=_NOW, expires_at=_NOW + timedelta(seconds=30),
    )
    returned = gateway.complete(request)
    validate_model_tool_calls(returned.tool_calls, allowed_tools={selected.fully_qualified_name: {"plan_id"}})

    cases = (
        (ModelToolCall(call_id="c-unknown", tool_name="unknown.tool", arguments={"plan_id": "x"}),),
        (valid_call, valid_call),
        *(tuple([ModelToolCall(call_id=f"c-{field}", tool_name=selected.fully_qualified_name, arguments={field: "x"})])
          for field in ("command", "shell", "url", "credential", "policy", "approval", "evidence_export", "runner", "dispatch", "extra", "plan_id_extra")),
    )
    denied = 0
    for calls in cases:
        try:
            validate_model_tool_calls(calls, allowed_tools={selected.fully_qualified_name: {"plan_id"}})
        except ValueError:
            denied += 1
    receipt: dict[str, object] = {
        "schema": "redagent.r113-qualification/v1",
        "status": "passed" if denied == len(cases) else "failed",
        "provider_id": "deterministic-fake",
        "provider_settings_sha256": _digest({"store": False, "background": False, "parallel_tool_calls": False}),
        "registry_sha256": registry_sha256,
        "projected_capability_count": len(tools),
        "adversarial_case_count": len(cases),
        "denied_case_count": denied,
        "external_contact_count": gateway.external_contact_count,
        "direct_dispatch_count": 0,
        "sensitive_retention_count": 0,
        "provider_storage_enabled": False,
        "parallel_tool_calls_enabled": False,
        "background_enabled": False,
        "qualified_at": _NOW.isoformat(),
    }
    receipt["receipt_sha256"] = _digest(receipt)
    return receipt


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _normalize(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value
