from __future__ import annotations

import importlib

import pytest


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.mcp_broker.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_114 RED: MCP broker module {name!r} is not implemented")


def _item(**overrides: object):
    contracts = _module("contracts")
    values = {
        "name": "campaign.propose",
        "item_kind": contracts.InventoryItemKind.TOOL,
        "description": "Create a bounded proposal from one stored campaign draft.",
        "description_sha256": "a" * 64,
        "input_schema_sha256": "b" * 64,
        "output_schema_sha256": "c" * 64,
        "risk_class": "high",
        "data_class": "internal",
        "tool_mode": "proposal_only",
    }
    values.update(overrides)
    return contracts.InventoryItem(**values)


def test_inventory_digest_is_order_stable_and_pins_every_security_relevant_field() -> None:
    inventory = _module("inventory")
    read = _item(name="campaign.read", item_kind=_module("contracts").InventoryItemKind.RESOURCE,
                 tool_mode="read_only", description_sha256="d" * 64)
    proposal = _item()
    first = inventory.inventory_sha256((proposal, read))
    assert first == inventory.inventory_sha256((read, proposal))
    assert first != inventory.inventory_sha256((_item(description_sha256="e" * 64), read))


@pytest.mark.parametrize("field", ["name", "description_sha256", "input_schema_sha256", "risk_class", "data_class", "tool_mode"])
def test_any_inventory_drift_freezes_server_and_invalidates_dependent_approval(field: str) -> None:
    inventory = _module("inventory")
    original = _item()
    value = {
        "name": "campaign.propose.alias",
        "description_sha256": "9" * 64,
        "input_schema_sha256": "8" * 64,
        "risk_class": "critical",
        "data_class": "restricted",
        "tool_mode": "read_only",
    }[field]
    changed = _item(**{field: value})
    freeze = inventory.compare_inventory(server_id="redagent-fixture", expected=(original,), observed=(changed,),
                                         dependent_approval_ids=("approval-r114",))
    assert freeze.frozen and freeze.reason_code == "mcp_inventory_drift"
    assert freeze.invalidated_approval_ids == ("approval-r114",)


def test_confusable_alias_and_unexpected_list_change_fail_closed() -> None:
    inventory = _module("inventory")
    with pytest.raises(ValueError, match="mcp_inventory_name_confusable"):
        inventory.validate_inventory((_item(name="campaign.propose"), _item(name="campaign-propose")))
    freeze = inventory.freeze_on_list_changed(server_id="redagent-fixture", inventory_sha256="a" * 64)
    assert freeze.frozen and freeze.reason_code == "mcp_tools_list_changed"
