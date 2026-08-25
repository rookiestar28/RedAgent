from __future__ import annotations

import importlib

import pytest


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.mcp_broker.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_114 RED: MCP broker module {name!r} is not implemented")


def test_deterministic_fixture_has_zero_network_process_credentials_and_direct_dispatch() -> None:
    fixture = _module("fixture").DeterministicMcpFixture()
    inventory = fixture.list_inventory()
    result = fixture.read_resource("campaign.read", {"campaign_id": "campaign-r114"})
    assert len(inventory) == 2 and result.trust_label == "untrusted_external"
    assert fixture.network_contact_count == 0
    assert fixture.process_launch_count == 0
    assert fixture.credential_access_count == 0
    assert fixture.direct_dispatch_count == 0


def test_fixture_rejects_unknown_items_arbitrary_arguments_and_side_effect_calls() -> None:
    fixture = _module("fixture").DeterministicMcpFixture()
    with pytest.raises(ValueError, match="mcp_fixture_item_not_allowed"):
        fixture.read_resource("unknown", {"campaign_id": "campaign-r114"})
    with pytest.raises(ValueError, match="mcp_fixture_arguments_invalid"):
        fixture.read_resource("campaign.read", {"url": "https://example.invalid"})
    with pytest.raises(ValueError, match="mcp_fixture_proposal_only"):
        fixture.call_tool("campaign.propose", {"plan_id": "plan-r114"})


def test_bridge_requires_exact_inventory_and_keeps_r113_proposal_authoritative() -> None:
    bridge = _module("bridge")
    fixture = _module("fixture").DeterministicMcpFixture()
    projection = bridge.project_fixture_tool(fixture, item_name="campaign.propose")
    assert projection.tool.tool_kind.value == "proposal"
    assert projection.tool.fully_qualified_name == "redagent.r114-mcp-fixture.propose.v1"
    assert projection.transport_enabled is False
    assert projection.direct_dispatch_enabled is False
    with pytest.raises(ValueError, match="mcp_inventory_digest_mismatch"):
        bridge.project_fixture_tool(fixture, item_name="campaign.propose", expected_inventory_sha256="f" * 64)
