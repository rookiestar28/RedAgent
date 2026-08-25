"""Monotonic bridge from attested MCP fixture inventory into compat_113 proposals."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from redagent_platform.agent_kernel.contracts import ModelBudget, ProjectedTool, ToolKind
from redagent_platform.mcp_broker.fixture import DeterministicMcpFixture
from redagent_platform.mcp_broker.inventory import inventory_sha256


@dataclass(frozen=True, kw_only=True)
class BrokerProjection:
    server_id: str
    inventory_sha256: str
    tool: ProjectedTool
    transport_enabled: bool
    direct_dispatch_enabled: bool


def project_fixture_tool(fixture: DeterministicMcpFixture, *, item_name: str,
                         expected_inventory_sha256: str | None = None) -> BrokerProjection:
    items = fixture.list_inventory()
    digest = inventory_sha256(items)
    if expected_inventory_sha256 is not None and expected_inventory_sha256 != digest:
        raise ValueError("mcp_inventory_digest_mismatch")
    item = next((candidate for candidate in items if candidate.name == item_name), None)
    if item is None or item.tool_mode != "proposal_only":
        raise ValueError("mcp_projection_item_invalid")
    schema = {"type": "object", "properties": {"plan_id": {"type": "string"}},
              "required": ["plan_id"], "additionalProperties": False}
    tool = ProjectedTool(
        fully_qualified_name="redagent.r114-mcp-fixture.propose.v1", tool_kind=ToolKind.PROPOSAL,
        description=item.description, description_sha256=item.description_sha256,
        input_schema=schema, input_schema_sha256=_schema_sha(schema), output_schema_sha256=item.output_schema_sha256,
        source_capability_id="r114-mcp-fixture", source_capability_revision=1,
        source_capability_sha256=digest, adapter_id="r114-in-process-mcp", adapter_version="1.0.0",
        network_mode="none", credential_class="none", approval_tier="high",
        budget=ModelBudget(max_turns=3, max_tool_calls=1, max_elapsed_seconds=30, max_input_tokens=4000,
                           max_output_tokens=500, max_cost_microunits=10000, max_result_bytes=4096),
        unsupported_features=("remote_http", "stdio", "provider_mcp", "direct_dispatch", "arbitrary_arguments"),
    )
    return BrokerProjection(server_id="redagent-fixture", inventory_sha256=digest, tool=tool,
                            transport_enabled=False, direct_dispatch_enabled=False)


def _schema_sha(value: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
