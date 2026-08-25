from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib

import pytest


NOW = datetime(2026, 7, 12, 2, 30, tzinfo=timezone.utc)


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.agent_kernel.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_113 RED: agent kernel module {name!r} is not implemented")


def _budget():
    contracts = _module("contracts")
    return contracts.ModelBudget(
        max_turns=2,
        max_tool_calls=1,
        max_elapsed_seconds=20,
        max_input_tokens=1000,
        max_output_tokens=250,
        max_cost_microunits=1000,
        max_result_bytes=1024,
    )


def _tool():
    contracts = _module("contracts")
    return contracts.ProjectedTool(
        fully_qualified_name="redagent.human-simulation-sink.propose.v1",
        tool_kind=contracts.ToolKind.PROPOSAL,
        description="Propose the certified owned sink campaign.",
        description_sha256="1" * 64,
        input_schema={
            "type": "object",
            "properties": {"campaign_id": {"type": "string", "const": "r112-sink-email-canary-v1"}},
            "required": ["campaign_id"],
            "additionalProperties": False,
        },
        input_schema_sha256="2" * 64,
        output_schema_sha256="3" * 64,
        source_capability_id="human-simulation-sink",
        source_capability_revision=1,
        source_capability_sha256="4" * 64,
        adapter_id="r112-owned-sink",
        adapter_version="1.0.0",
        network_mode="none",
        credential_class="none",
        approval_tier="high",
        budget=_budget(),
        unsupported_features=("arbitrary_command", "native_template", "plugin_loading", "human_delivery"),
    )


def _request():
    contracts = _module("contracts")
    return contracts.ModelRequest(
        request_id="request-1",
        tenant_id="tenant-a",
        run_id="run-1",
        instructions=(
            contracts.ContextItem(
                item_id="instruction-1",
                content="Return at most one strict proposal call.",
                trust_label=contracts.TrustLabel.TRUSTED_REGENERATED,
                provenance_sha256="5" * 64,
            ),
        ),
        tools=(_tool(),),
        budget=_budget(),
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=20),
    )


def test_openai_payload_is_strict_single_call_store_off_and_has_no_hosted_tools() -> None:
    adapter = _module("openai_responses")
    payload = adapter.OpenAIResponsesAdapter(model="approved-model-snapshot", transport=None).build_payload(_request())
    assert payload["store"] is False
    assert payload["background"] is False
    assert payload["parallel_tool_calls"] is False
    assert payload["max_output_tokens"] == 250
    assert len(payload["tools"]) == 1
    tool = payload["tools"][0]
    assert tool["type"] == "function" and tool["strict"] is True
    assert tool["parameters"]["additionalProperties"] is False
    rendered = repr(payload).lower()
    for forbidden in ("web_search", "file_search", "computer", "shell", "mcp", "code_interpreter", "credential"):
        assert forbidden not in rendered


def test_openai_adapter_rejects_mutable_model_alias_bad_schema_and_missing_transport_for_call() -> None:
    adapter = _module("openai_responses")
    with pytest.raises(ValueError, match="openai_model_snapshot_required"):
        adapter.OpenAIResponsesAdapter(model="latest", transport=None)
    request = _request()
    request.tools[0].input_schema["additionalProperties"] = True
    with pytest.raises(ValueError, match="openai_tool_schema_not_strict"):
        adapter.OpenAIResponsesAdapter(model="approved-model-snapshot", transport=None).build_payload(request)
    with pytest.raises(ValueError, match="openai_transport_required"):
        adapter.OpenAIResponsesAdapter(model="approved-model-snapshot", transport=None).complete(_request())
