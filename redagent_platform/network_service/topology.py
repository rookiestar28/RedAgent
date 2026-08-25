"""Certified compat_107 dual-internal-network topology contract."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class NetworkContract:
    name: str
    internal: bool


@dataclass(frozen=True, kw_only=True)
class WorkloadContract:
    name: str
    networks: tuple[str, ...]
    user: str
    read_only: bool
    cap_drop: tuple[str, ...]
    no_new_privileges: bool
    published_ports: tuple[int, ...]


@dataclass(frozen=True, kw_only=True)
class TopologyContract:
    worker_network: NetworkContract
    target_network: NetworkContract
    worker: WorkloadContract
    gateway: WorkloadContract
    target: WorkloadContract


def certified_topology() -> TopologyContract:
    worker_network = NetworkContract(name="redagent-r107-worker-gateway", internal=True)
    target_network = NetworkContract(name="redagent-r107-gateway-target", internal=True)
    common = {
        "user": "65532:65532", "read_only": True, "cap_drop": ("ALL",),
        "no_new_privileges": True, "published_ports": (),
    }
    return TopologyContract(
        worker_network=worker_network,
        target_network=target_network,
        worker=WorkloadContract(name="redagent-r107-worker", networks=(worker_network.name,), **common),
        gateway=WorkloadContract(
            name="redagent-r107-gateway", networks=(worker_network.name, target_network.name), **common,
        ),
        target=WorkloadContract(name="redagent-r107-target", networks=(target_network.name,), **common),
    )
