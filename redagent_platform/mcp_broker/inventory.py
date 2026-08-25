"""Deterministic compat_114 inventory digesting and fail-closed drift freezes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re

from redagent_platform.mcp_broker.contracts import InventoryItem


@dataclass(frozen=True, kw_only=True)
class ServerFreeze:
    server_id: str
    frozen: bool
    reason_code: str
    expected_inventory_sha256: str | None
    observed_inventory_sha256: str | None
    invalidated_approval_ids: tuple[str, ...]


def inventory_sha256(items: tuple[InventoryItem, ...]) -> str:
    validate_inventory(items)
    values = [asdict(item) for item in sorted(items, key=lambda item: item.name)]
    for value in values:
        value["item_kind"] = value["item_kind"].value
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_inventory(items: tuple[InventoryItem, ...]) -> None:
    if not items or len(items) > 64:
        raise ValueError("mcp_inventory_size_invalid")
    normalized: set[str] = set()
    for item in items:
        key = re.sub(r"[^a-z0-9]", "", item.name.lower())
        if key in normalized:
            raise ValueError("mcp_inventory_name_confusable")
        normalized.add(key)


def compare_inventory(*, server_id: str, expected: tuple[InventoryItem, ...], observed: tuple[InventoryItem, ...],
                      dependent_approval_ids: tuple[str, ...]) -> ServerFreeze:
    expected_sha = inventory_sha256(expected)
    observed_sha = inventory_sha256(observed)
    return ServerFreeze(server_id=server_id, frozen=expected_sha != observed_sha,
                        reason_code="mcp_inventory_drift" if expected_sha != observed_sha else "mcp_inventory_current",
                        expected_inventory_sha256=expected_sha, observed_inventory_sha256=observed_sha,
                        invalidated_approval_ids=dependent_approval_ids if expected_sha != observed_sha else ())


def freeze_on_list_changed(*, server_id: str, inventory_sha256: str) -> ServerFreeze:
    return ServerFreeze(server_id=server_id, frozen=True, reason_code="mcp_tools_list_changed",
                        expected_inventory_sha256=inventory_sha256, observed_inventory_sha256=None,
                        invalidated_approval_ids=())
