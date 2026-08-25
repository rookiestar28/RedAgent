from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib

import pytest


NOW = datetime(2026, 7, 12, 8, 0, tzinfo=timezone.utc)
SHA = "a" * 64


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.mcp_broker.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_114 RED: MCP broker module {name!r} is not implemented")


def _registration(**overrides: object):
    contracts = _module("contracts")
    values = {
        "registration_id": "registration-r114-fixture",
        "tenant_id": "tenant-r114",
        "server_id": "redagent-fixture",
        "protocol_version": "2025-11-25",
        "transport": contracts.TransportKind.IN_PROCESS,
        "transport_identity_sha256": "1" * 64,
        "inventory_sha256": "2" * 64,
        "risk_class": "high",
        "data_class": "internal",
        "allowed_item_names": ("campaign.read", "campaign.propose"),
        "registered_by": "admin-r114",
        "reviewed_by": "reviewer-r114",
        "signature_sha256": "3" * 64,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=10),
    }
    values.update(overrides)
    return contracts.ServerRegistration(**values)


def test_registration_is_exact_reviewed_and_protocol_pinned() -> None:
    registration = _registration()
    assert registration.protocol_version == "2025-11-25"
    assert registration.registered_by != registration.reviewed_by
    with pytest.raises(ValueError, match="mcp_protocol_version_unsupported"):
        _registration(protocol_version="latest")
    with pytest.raises(ValueError, match="mcp_registration_separation_required"):
        _registration(reviewed_by="admin-r114")


def test_remote_attestation_requires_https_origin_ssrf_pkce_resource_audience_and_no_passthrough() -> None:
    contracts = _module("contracts")
    attestation = contracts.RemoteTransportAttestation(
        origin="https://mcp.fixture.invalid",
        resource="https://mcp.fixture.invalid/mcp",
        authorization_server="https://auth.fixture.invalid",
        redirect_uri="https://redagent.fixture.invalid/oauth/callback",
        token_audience="https://mcp.fixture.invalid/mcp",
        downstream_credential_reference="secret-ref-r114-fixture",
        pkce_methods=("S256",),
        origin_validation=True,
        ssrf_policy_enforced=True,
        exact_redirect_validation=True,
        state_binding=True,
        token_passthrough=False,
        egress_allowlisted=True,
        revocation_supported=True,
        network_call_enabled=False,
    )
    assert attestation.network_call_enabled is False
    for field, value, reason in (
        ("origin", "http://example.com", "mcp_remote_https_required"),
        ("origin", "https://127.0.0.1", "mcp_remote_destination_forbidden"),
        ("pkce_methods", ("plain",), "mcp_remote_pkce_s256_required"),
        ("token_passthrough", True, "mcp_token_passthrough_forbidden"),
        ("network_call_enabled", True, "mcp_remote_transport_not_qualified"),
    ):
        values = dict(attestation.__dict__); values[field] = value
        with pytest.raises(ValueError, match=reason):
            contracts.RemoteTransportAttestation(**values)


def test_stdio_attestation_requires_signed_non_shell_sandbox_without_ambient_environment_or_launch() -> None:
    contracts = _module("contracts")
    attestation = contracts.StdioTransportAttestation(
        artifact_sha256=SHA,
        executable_sha256="b" * 64,
        arguments_sha256="c" * 64,
        sandbox_profile_id="r114-no-exec-fixture",
        secret_reference_ids=("secret-ref-r114-fixture",),
        direct_launch=True,
        shell_enabled=False,
        ambient_environment_inherited=False,
        filesystem_mode="read_only_explicit_roots",
        network_mode="none",
        resource_limits_enforced=True,
        kill_supported=True,
        cleanup_required=True,
        process_launch_enabled=False,
    )
    assert attestation.process_launch_enabled is False
    for field, value, reason in (
        ("shell_enabled", True, "mcp_stdio_shell_forbidden"),
        ("ambient_environment_inherited", True, "mcp_stdio_ambient_environment_forbidden"),
        ("network_mode", "host", "mcp_stdio_network_forbidden"),
        ("process_launch_enabled", True, "mcp_stdio_transport_not_qualified"),
    ):
        values = dict(attestation.__dict__); values[field] = value
        with pytest.raises(ValueError, match=reason):
            contracts.StdioTransportAttestation(**values)


def test_registration_rejects_raw_transport_authority_fields() -> None:
    contracts = _module("contracts")
    field_names = set(contracts.ServerRegistration.__dataclass_fields__)
    assert not field_names.intersection({"command", "args", "environment", "token", "credential", "headers", "url"})
