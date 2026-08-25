"""Closed compat_114 MCP registration, transport-attestation, and inventory contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import ipaddress
import re
from urllib.parse import urlsplit


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_ITEM_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TransportKind(str, Enum):
    IN_PROCESS = "in_process"
    REMOTE_HTTP = "remote_http"
    STDIO = "stdio"


class InventoryItemKind(str, Enum):
    RESOURCE = "resource"
    PROMPT = "prompt"
    TOOL = "tool"


@dataclass(frozen=True, kw_only=True)
class ServerRegistration:
    registration_id: str
    tenant_id: str
    server_id: str
    protocol_version: str
    transport: TransportKind
    transport_identity_sha256: str
    inventory_sha256: str
    risk_class: str
    data_class: str
    allowed_item_names: tuple[str, ...]
    registered_by: str
    reviewed_by: str
    signature_sha256: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.registration_id, self.tenant_id, self.server_id, self.registered_by, self.reviewed_by):
            _identifier(value)
        if self.protocol_version != "2025-11-25":
            raise ValueError("mcp_protocol_version_unsupported")
        if not isinstance(self.transport, TransportKind):
            raise ValueError("mcp_transport_invalid")
        for value in (self.transport_identity_sha256, self.inventory_sha256, self.signature_sha256):
            _sha256(value)
        if self.registered_by == self.reviewed_by:
            raise ValueError("mcp_registration_separation_required")
        if self.risk_class not in {"low", "medium", "high", "critical"}:
            raise ValueError("mcp_risk_class_invalid")
        if self.data_class not in {"public", "internal", "confidential", "restricted"}:
            raise ValueError("mcp_data_class_invalid")
        if not self.allowed_item_names or len(self.allowed_item_names) > 64:
            raise ValueError("mcp_allowed_inventory_invalid")
        for name in self.allowed_item_names:
            _item_name(name)
        _window(self.issued_at, self.expires_at, timedelta(days=1))


@dataclass(frozen=True, kw_only=True)
class RemoteTransportAttestation:
    origin: str
    resource: str
    authorization_server: str
    redirect_uri: str
    token_audience: str
    downstream_credential_reference: str
    pkce_methods: tuple[str, ...]
    origin_validation: bool
    ssrf_policy_enforced: bool
    exact_redirect_validation: bool
    state_binding: bool
    token_passthrough: bool
    egress_allowlisted: bool
    revocation_supported: bool
    network_call_enabled: bool

    def __post_init__(self) -> None:
        for value in (self.origin, self.resource, self.authorization_server, self.redirect_uri, self.token_audience):
            _safe_https(value)
        _identifier(self.downstream_credential_reference)
        if "S256" not in self.pkce_methods:
            raise ValueError("mcp_remote_pkce_s256_required")
        if self.token_passthrough:
            raise ValueError("mcp_token_passthrough_forbidden")
        if not all((self.origin_validation, self.ssrf_policy_enforced, self.exact_redirect_validation,
                    self.state_binding, self.egress_allowlisted, self.revocation_supported)):
            raise ValueError("mcp_remote_controls_incomplete")
        if self.network_call_enabled:
            # CRITICAL: compat_114 qualifies metadata and denial behavior without contacting a transport.
            raise ValueError("mcp_remote_transport_not_qualified")


@dataclass(frozen=True, kw_only=True)
class StdioTransportAttestation:
    artifact_sha256: str
    executable_sha256: str
    arguments_sha256: str
    sandbox_profile_id: str
    secret_reference_ids: tuple[str, ...]
    direct_launch: bool
    shell_enabled: bool
    ambient_environment_inherited: bool
    filesystem_mode: str
    network_mode: str
    resource_limits_enforced: bool
    kill_supported: bool
    cleanup_required: bool
    process_launch_enabled: bool

    def __post_init__(self) -> None:
        for value in (self.artifact_sha256, self.executable_sha256, self.arguments_sha256):
            _sha256(value)
        _identifier(self.sandbox_profile_id)
        for value in self.secret_reference_ids:
            _identifier(value)
        if not self.direct_launch or self.shell_enabled:
            raise ValueError("mcp_stdio_shell_forbidden")
        if self.ambient_environment_inherited:
            raise ValueError("mcp_stdio_ambient_environment_forbidden")
        if self.network_mode != "none":
            raise ValueError("mcp_stdio_network_forbidden")
        if self.filesystem_mode != "read_only_explicit_roots" or not all(
            (self.resource_limits_enforced, self.kill_supported, self.cleanup_required)
        ):
            raise ValueError("mcp_stdio_controls_incomplete")
        if self.process_launch_enabled:
            # CRITICAL: no external executable is launched during compat_114 qualification.
            raise ValueError("mcp_stdio_transport_not_qualified")


@dataclass(frozen=True, kw_only=True)
class InventoryItem:
    name: str
    item_kind: InventoryItemKind
    description: str
    description_sha256: str
    input_schema_sha256: str
    output_schema_sha256: str
    risk_class: str
    data_class: str
    tool_mode: str

    def __post_init__(self) -> None:
        _item_name(self.name)
        if not isinstance(self.item_kind, InventoryItemKind):
            raise ValueError("mcp_inventory_kind_invalid")
        if not isinstance(self.description, str) or not 1 <= len(self.description) <= 500:
            raise ValueError("mcp_inventory_description_invalid")
        for value in (self.description_sha256, self.input_schema_sha256, self.output_schema_sha256):
            _sha256(value)
        if self.risk_class not in {"low", "medium", "high", "critical"}:
            raise ValueError("mcp_inventory_risk_invalid")
        if self.data_class not in {"public", "internal", "confidential", "restricted"}:
            raise ValueError("mcp_inventory_data_invalid")
        if self.tool_mode not in {"read_only", "proposal_only"}:
            raise ValueError("mcp_inventory_mode_invalid")
        if self.item_kind is not InventoryItemKind.TOOL and self.tool_mode != "read_only":
            raise ValueError("mcp_inventory_mode_invalid")


def _safe_https(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("mcp_remote_https_required")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("mcp_remote_destination_forbidden")
    if parsed.hostname.lower() == "localhost" or parsed.hostname.lower().endswith(".localhost"):
        raise ValueError("mcp_remote_destination_forbidden")


def _identifier(value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("mcp_identifier_invalid")


def _item_name(value: str) -> None:
    if not isinstance(value, str) or not _ITEM_NAME.fullmatch(value):
        raise ValueError("mcp_inventory_name_invalid")


def _sha256(value: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("mcp_sha256_invalid")


def _window(issued_at: datetime, expires_at: datetime, maximum: timedelta) -> None:
    if issued_at.tzinfo is None or expires_at.tzinfo is None or not issued_at < expires_at <= issued_at + maximum:
        raise ValueError("mcp_expiry_invalid")
