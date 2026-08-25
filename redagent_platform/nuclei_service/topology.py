"""Certified network facts for the compat_105 worker/gateway/fixture topology."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class NucleiTopology:
    networks: Mapping[str, Mapping[str, bool]]
    attachments: Mapping[str, tuple[str, ...]]
    published_ports: Mapping[str, int]
    direct_target_route: bool
    public_egress: bool


_TOPOLOGY = NucleiTopology(
    networks=MappingProxyType({
        "redagent-r105-worker-gateway": MappingProxyType({"internal": True}),
        "redagent-r105-gateway-target": MappingProxyType({"internal": True}),
    }),
    attachments=MappingProxyType({
        "worker": ("redagent-r105-worker-gateway",),
        "gateway": ("redagent-r105-worker-gateway", "redagent-r105-gateway-target"),
        "target": ("redagent-r105-gateway-target",),
    }),
    published_ports=MappingProxyType({}), direct_target_route=False, public_egress=False,
)


def certified_topology() -> NucleiTopology:
    return _TOPOLOGY
