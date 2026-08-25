"""In-process no-I/O MCP fixture used for all initial compat_114 qualification."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from redagent_platform.mcp_broker.contracts import InventoryItem, InventoryItemKind


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True, kw_only=True)
class FixtureResult:
    item_name: str
    summary: str
    trust_label: str
    provenance_sha256: str


class DeterministicMcpFixture:
    def __init__(self) -> None:
        self.network_contact_count = 0
        self.process_launch_count = 0
        self.credential_access_count = 0
        self.direct_dispatch_count = 0

    def list_inventory(self) -> tuple[InventoryItem, ...]:
        return (
            InventoryItem(name="campaign.read", item_kind=InventoryItemKind.RESOURCE,
                          description="Read one minimized stored campaign summary.", description_sha256=_sha("read-description"),
                          input_schema_sha256=_sha("read-input"), output_schema_sha256=_sha("read-output"),
                          risk_class="low", data_class="internal", tool_mode="read_only"),
            InventoryItem(name="campaign.propose", item_kind=InventoryItemKind.TOOL,
                          description="Create a bounded proposal from one stored campaign plan.",
                          description_sha256=_sha("proposal-description"), input_schema_sha256=_sha("proposal-input"),
                          output_schema_sha256=_sha("proposal-output"), risk_class="high", data_class="internal",
                          tool_mode="proposal_only"),
        )

    def read_resource(self, item_name: str, arguments: dict[str, object]) -> FixtureResult:
        if item_name != "campaign.read":
            raise ValueError("mcp_fixture_item_not_allowed")
        if set(arguments) != {"campaign_id"} or not isinstance(arguments["campaign_id"], str):
            raise ValueError("mcp_fixture_arguments_invalid")
        campaign_id = arguments["campaign_id"]
        return FixtureResult(item_name=item_name, summary="Stored campaign is awaiting bounded review.",
                             trust_label="untrusted_external", provenance_sha256=_sha(campaign_id))

    def call_tool(self, item_name: str, arguments: dict[str, object]) -> None:
        if item_name != "campaign.propose":
            raise ValueError("mcp_fixture_item_not_allowed")
        del arguments
        raise ValueError("mcp_fixture_proposal_only")
