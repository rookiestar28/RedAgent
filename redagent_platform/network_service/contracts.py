"""Immutable compat_107 scope, authorization, profile, and target contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import ipaddress
import re
from types import MappingProxyType
from typing import Mapping


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class NetworkProfileId(str, Enum):
    TCP_CONNECT_DISCOVERY = "tcp-connect-discovery-v1"


class NetworkProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True, kw_only=True)
class NetworkProfile:
    profile_id: NetworkProfileId
    enabled: bool
    max_targets: int
    max_ports_per_target: int
    max_attempts: int
    rate_per_second: int
    concurrency: int
    max_retries: int
    connect_timeout_seconds: int
    run_timeout_seconds: int
    banner_bytes: int
    output_bytes: int
    raw_socket_allowed: bool
    dns_allowed: bool
    active_probe_allowed: bool
    script_allowed: bool


@dataclass(frozen=True, kw_only=True)
class NetworkAuthorization:
    tenant_id: str
    policy_decision_id: str
    policy_revision: str
    roe_version_id: str
    reservation_id: str
    topology_sha256: str
    approved_profile_ids: tuple[NetworkProfileId, ...]
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (
            self.tenant_id,
            self.policy_decision_id,
            self.policy_revision,
            self.roe_version_id,
            self.reservation_id,
        ):
            _identifier(value)
        _sha(self.topology_sha256)
        _aware(self.approved_at)
        _aware(self.expires_at)
        if not self.approved_at < self.expires_at or not self.approved_profile_ids:
            raise ValueError("network_authorization_invalid")


@dataclass(frozen=True, kw_only=True)
class NetworkTargetBinding:
    target_set_id: str
    topology_sha256: str
    route_sha256: str
    literal_targets: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    protocol: NetworkProtocol
    network_id: str
    non_production: bool
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.target_set_id)
        _sha(self.topology_sha256)
        _sha(self.route_sha256)
        _aware(self.issued_at)
        _aware(self.expires_at)
        if (
            not self.literal_targets
            or not self.allowed_ports
            or self.protocol is not NetworkProtocol.TCP
            or self.network_id != "redagent-r107-gateway-target"
            or self.non_production is not True
            or not self.issued_at < self.expires_at
        ):
            raise ValueError("network_target_binding_invalid")


def certified_profiles() -> Mapping[NetworkProfileId, NetworkProfile]:
    return MappingProxyType({
        NetworkProfileId.TCP_CONNECT_DISCOVERY: NetworkProfile(
            profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
            enabled=True,
            max_targets=8,
            max_ports_per_target=16,
            max_attempts=64,
            rate_per_second=4,
            concurrency=4,
            max_retries=0,
            connect_timeout_seconds=1,
            run_timeout_seconds=30,
            banner_bytes=256,
            output_bytes=64 * 1024,
            raw_socket_allowed=False,
            dns_allowed=False,
            active_probe_allowed=False,
            script_allowed=False,
        )
    })


def canonical_lab_ip(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("network_literal_ip_required")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("network_literal_ip_required") from exc
    # CRITICAL: compat_107 accepts only literal private fixture addresses; broad/native target syntax must never reach a worker.
    if address.is_unspecified or address.is_multicast or address.is_link_local or address.is_loopback:
        raise ValueError("network_target_address_forbidden")
    if not address.is_private:
        raise ValueError("network_target_not_private")
    return address.compressed


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("network_identifier_invalid")


def _sha(value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("network_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("network_time_invalid")
