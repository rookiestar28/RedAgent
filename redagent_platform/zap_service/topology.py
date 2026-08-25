"""Certified network/API topology facts for R104."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class ZapTopology:
    networks: Mapping[str, Mapping[str, bool]]
    attachments: Mapping[str, tuple[str, ...]]
    published_ports: Mapping[str, int]
    zap_api_bind: str
    file_transfer_enabled: bool
    jsonp_enabled: bool
    keyless_safe_operations: bool


_TOPOLOGY = ZapTopology(
    networks=MappingProxyType({
        "redagent-r104-zap-gateway": MappingProxyType({"internal": True}),
        "redagent-r104-gateway-target": MappingProxyType({"internal": True}),
    }),
    attachments=MappingProxyType({
        "zap": ("redagent-r104-zap-gateway",),
        "gateway": ("redagent-r104-zap-gateway", "redagent-r104-gateway-target"),
        "target": ("redagent-r104-gateway-target",),
    }),
    published_ports=MappingProxyType({}),
    zap_api_bind="127.0.0.1",
    file_transfer_enabled=False,
    jsonp_enabled=False,
    keyless_safe_operations=False,
)


def certified_topology() -> ZapTopology:
    return _TOPOLOGY
