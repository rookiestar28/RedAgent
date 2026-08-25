"""Deterministic zero-network, zero-process compat_114 broker/workbench qualification."""

from __future__ import annotations

import hashlib
import json

from redagent_platform.mcp_broker.contracts import RemoteTransportAttestation, StdioTransportAttestation
from redagent_platform.mcp_broker.fixture import DeterministicMcpFixture
from redagent_platform.mcp_broker.inventory import compare_inventory, freeze_on_list_changed, inventory_sha256
from redagent_platform.workbench.contracts import WorkbenchProposal


def qualify_mcp_workbench() -> dict[str, object]:
    fixture = DeterministicMcpFixture()
    items = fixture.list_inventory()
    inventory_digest = inventory_sha256(items)
    denied = 0
    cases = 0

    def expect_denied(action) -> None:
        nonlocal denied, cases
        cases += 1
        try:
            action()
        except ValueError:
            denied += 1

    expect_denied(lambda: fixture.read_resource("unknown", {"campaign_id": "campaign-r114"}))
    expect_denied(lambda: fixture.read_resource("campaign.read", {"url": "https://example.invalid"}))
    expect_denied(lambda: fixture.call_tool("campaign.propose", {"plan_id": "plan-r114"}))
    remote = _remote_values()
    for field, value in (("origin", "http://example.com"), ("origin", "https://127.0.0.1"),
                         ("pkce_methods", ("plain",)), ("token_passthrough", True),
                         ("network_call_enabled", True)):
        expect_denied(lambda field=field, value=value: RemoteTransportAttestation(**{**remote, field: value}))
    stdio = _stdio_values()
    for field, value in (("shell_enabled", True), ("ambient_environment_inherited", True),
                         ("network_mode", "host"), ("process_launch_enabled", True)):
        expect_denied(lambda field=field, value=value: StdioTransportAttestation(**{**stdio, field: value}))
    for field, value in (("name", "campaign.propose.alias"), ("description_sha256", "9" * 64),
                         ("input_schema_sha256", "8" * 64), ("risk_class", "critical"),
                         ("data_class", "restricted"), ("tool_mode", "read_only")):
        observed = tuple(item if item.name != "campaign.propose" else _replace_item(item, field, value) for item in items)
        cases += 1
        if compare_inventory(server_id="redagent-fixture", expected=items, observed=observed,
                             dependent_approval_ids=("approval-r114",)).frozen:
            denied += 1
    cases += 1
    if freeze_on_list_changed(server_id="redagent-fixture", inventory_sha256=inventory_digest).frozen:
        denied += 1
    expect_denied(lambda: WorkbenchProposal(**_forbidden_proposal_values()))

    receipt: dict[str, object] = {
        "schema": "redagent.r114-qualification/v1", "status": "passed" if denied == cases else "failed",
        "protocol_version": "2025-11-25", "inventory_sha256": inventory_digest,
        "fixture_inventory_count": len(items), "adversarial_case_count": cases, "denied_case_count": denied,
        "network_contact_count": fixture.network_contact_count, "process_launch_count": fixture.process_launch_count,
        "credential_access_count": fixture.credential_access_count, "direct_dispatch_count": fixture.direct_dispatch_count,
        "sensitive_retention_count": 0, "remote_http_enabled": False, "stdio_enabled": False,
        "provider_mcp_enabled": False, "qualified_at": "2026-07-12T08:30:00+00:00",
    }
    receipt["receipt_sha256"] = _digest(receipt)
    return receipt


def _replace_item(item, field: str, value: object):
    from dataclasses import replace
    return replace(item, **{field: value})


def _remote_values() -> dict[str, object]:
    return {"origin": "https://mcp.fixture.invalid", "resource": "https://mcp.fixture.invalid/mcp",
            "authorization_server": "https://auth.fixture.invalid",
            "redirect_uri": "https://redagent.fixture.invalid/oauth/callback",
            "token_audience": "https://mcp.fixture.invalid/mcp",
            "downstream_credential_reference": "secret-ref-r114-fixture", "pkce_methods": ("S256",),
            "origin_validation": True, "ssrf_policy_enforced": True, "exact_redirect_validation": True,
            "state_binding": True, "token_passthrough": False, "egress_allowlisted": True,
            "revocation_supported": True, "network_call_enabled": False}


def _stdio_values() -> dict[str, object]:
    return {"artifact_sha256": "a" * 64, "executable_sha256": "b" * 64, "arguments_sha256": "c" * 64,
            "sandbox_profile_id": "r114-no-exec-fixture", "secret_reference_ids": (), "direct_launch": True,
            "shell_enabled": False, "ambient_environment_inherited": False,
            "filesystem_mode": "read_only_explicit_roots", "network_mode": "none",
            "resource_limits_enforced": True, "kill_supported": True, "cleanup_required": True,
            "process_launch_enabled": False}


def _forbidden_proposal_values() -> dict[str, object]:
    from datetime import datetime, timedelta, timezone
    now = datetime(2026, 7, 12, 8, 0, tzinfo=timezone.utc)
    return {"proposal_id": "proposal-r114", "campaign_id": "campaign-r114", "revision": 1,
            "predecessor_proposal_id": None, "server_id": "redagent-fixture",
            "server_inventory_sha256": "1" * 64, "tool_fqn": "redagent.fixture.propose.v1",
            "tool_schema_sha256": "2" * 64, "sanitized_arguments": {"token": "forbidden"},
            "target_ids": ("target-r114",), "roe_version_id": "roe-r114", "policy_revision": "r099-v1",
            "policy_decision_id": "decision-r114", "credential_class": "none", "egress_class": "none",
            "side_effects": ("proposal_only",), "disclosure_fields": ("stored_plan_id",),
            "budget_sha256": "3" * 64, "approval_id": None, "issued_at": now,
            "expires_at": now + timedelta(minutes=2)}


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
