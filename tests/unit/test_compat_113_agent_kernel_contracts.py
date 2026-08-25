from __future__ import annotations

import importlib.util
import importlib
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.runner_service.contracts import (
    CredentialClass,
    ExecutionCapabilityManifest,
    NetworkMode,
    ResourceLimits,
)


def test_r113_agent_kernel_package_exists_before_contract_implementation() -> None:
    assert importlib.util.find_spec("redagent_platform.agent_kernel") is not None, (
        "compat_113 RED: the provider-neutral agent kernel package does not exist"
    )


NOW = datetime(2026, 7, 12, 1, 0, tzinfo=timezone.utc)


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.agent_kernel.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_113 RED: agent kernel module {name!r} is not implemented")


def _capability(**overrides: object) -> ExecutionCapabilityManifest:
    values: dict[str, object] = {
        "schema_version": "1.0",
        "capability_id": "human-simulation-sink",
        "revision": 1,
        "adapter_id": "r112-owned-sink",
        "adapter_version": "1.0.0",
        "image_digest": "sha256:" + "a" * 64,
        "input_schema_id": "redagent.r112-campaign-plan.v1",
        "supported_modes": ("owned-sink",),
        "phases": ("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        "sandbox_profile_id": "r112-in-process-sink",
        "network_mode": NetworkMode.NONE,
        "credential_class": CredentialClass.NONE,
        "evidence_schema": ("r112-qualification-v1",),
        "unsupported_features": (
            "arbitrary_command",
            "native_template",
            "plugin_loading",
            "human_delivery",
            "external_delivery",
        ),
        "limits": ResourceLimits(
            cpu_millis=100,
            memory_mib=64,
            pids=4,
            timeout_seconds=10,
            evidence_bytes=4096,
        ),
        "artifact_receipt_id": "r112-promotion-receipt",
        "reviewed_by": "reviewer-r112",
        "status": "certified",
    }
    values.update(overrides)
    return ExecutionCapabilityManifest(**values)  # type: ignore[arg-type]


def _budget():
    contracts = _module("contracts")
    return contracts.ModelBudget(
        max_turns=3,
        max_tool_calls=1,
        max_elapsed_seconds=30,
        max_input_tokens=2000,
        max_output_tokens=500,
        max_cost_microunits=5000,
        max_result_bytes=4096,
    )


def test_model_budget_is_finite_and_rejects_unbounded_or_boolean_values() -> None:
    contracts = _module("contracts")
    budget = _budget()
    assert budget.max_turns == 3 and budget.max_tool_calls == 1
    with pytest.raises(ValueError, match="budget_max_turns_invalid"):
        contracts.ModelBudget(
            max_turns=0,
            max_tool_calls=1,
            max_elapsed_seconds=30,
            max_input_tokens=2000,
            max_output_tokens=500,
            max_cost_microunits=5000,
            max_result_bytes=4096,
        )


def test_r100_projection_is_strict_digest_bound_and_never_broadens_capability() -> None:
    registry = _module("registry")
    tool = registry.project_capability(
        _capability(),
        input_schema={
            "type": "object",
            "properties": {"campaign_id": {"type": "string", "const": "r112-sink-email-canary-v1"}},
            "required": ["campaign_id"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"proposal_id": {"type": "string"}},
            "required": ["proposal_id"],
            "additionalProperties": False,
        },
        description="Propose the one certified owned synthetic sink campaign.",
        approval_tier="high",
        budget=_budget(),
    )
    assert tool.fully_qualified_name == "redagent.human-simulation-sink.propose.v1"
    assert tool.source_capability_sha256 and tool.input_schema_sha256
    assert tool.network_mode == "none" and tool.credential_class == "none"
    assert tool.tool_kind.value == "proposal"
    assert "human_delivery" in tool.unsupported_features


@pytest.mark.parametrize(
    "field",
    ["command", "argv", "shell", "url", "browser", "credential", "policy", "approval", "evidence_export"],
)
def test_projection_rejects_generic_or_authority_changing_schema_fields(field: str) -> None:
    registry = _module("registry")
    with pytest.raises(ValueError, match="tool_schema_forbidden_field"):
        registry.project_capability(
            _capability(),
            input_schema={
                "type": "object",
                "properties": {field: {"type": "string"}},
                "required": [field],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"proposal_id": {"type": "string"}},
                "required": ["proposal_id"],
                "additionalProperties": False,
            },
            description="Closed proposal.",
            approval_tier="high",
            budget=_budget(),
        )


def test_projection_rejects_non_strict_schema_unknown_status_or_host_network() -> None:
    registry = _module("registry")
    with pytest.raises(ValueError, match="tool_schema_not_strict"):
        registry.project_capability(
            _capability(),
            input_schema={"type": "object", "properties": {}, "required": []},
            output_schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
            description="Closed proposal.",
            approval_tier="high",
            budget=_budget(),
        )


def test_deterministic_fake_provider_is_provider_neutral_and_never_contacts_network() -> None:
    contracts = _module("contracts")
    providers = _module("providers")
    result = contracts.ModelResult(
        response_id="fake-response-1",
        finish_reason="tool_call",
        tool_calls=(
            contracts.ModelToolCall(
                call_id="call-1",
                tool_name="redagent.human-simulation-sink.propose.v1",
                arguments={"campaign_id": "r112-sink-email-canary-v1"},
            ),
        ),
        output_text=None,
        usage=contracts.ModelUsage(input_tokens=50, output_tokens=10, cost_microunits=25),
    )
    fake = providers.DeterministicFakeModelGateway((result,))
    request = contracts.ModelRequest(
        request_id="request-1",
        tenant_id="tenant-a",
        run_id="run-1",
        instructions=(
            contracts.ContextItem(
                item_id="instruction-1",
                content="Select only a certified proposal tool.",
                trust_label=contracts.TrustLabel.TRUSTED_REGENERATED,
                provenance_sha256="1" * 64,
            ),
        ),
        tools=(),
        budget=_budget(),
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    returned = fake.complete(request)
    assert returned == result and fake.external_contact_count == 0 and fake.request_count == 1
