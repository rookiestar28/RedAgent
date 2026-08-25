"""Closed compat_107 compiler: promoted literal fixture scope in, immutable tuples out."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

from redagent_platform.network_service.contracts import (
    NetworkAuthorization,
    NetworkProfileId,
    NetworkProtocol,
    NetworkTargetBinding,
    canonical_lab_ip,
    certified_profiles,
)


@dataclass(frozen=True, kw_only=True)
class CompiledNetworkTuple:
    tuple_id: str
    ip: str
    port: int
    protocol: NetworkProtocol


@dataclass(frozen=True, kw_only=True)
class CompiledNetworkPlan:
    profile_id: NetworkProfileId
    topology_sha256: str
    route_sha256: str
    target_set_id: str
    tuples: tuple[CompiledNetworkTuple, ...]
    target_count: int
    port_count: int
    attempt_limit: int
    rate_per_second: int
    concurrency: int
    retry_limit: int
    connect_timeout_seconds: int
    run_timeout_seconds: int
    banner_bytes: int
    output_bytes: int
    plan_sha256: str


def compile_network_plan(
    *,
    profile_id: NetworkProfileId,
    authorization: NetworkAuthorization,
    target_binding: NetworkTargetBinding,
    now: datetime,
) -> CompiledNetworkPlan:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("network_time_invalid")
    if now < authorization.approved_at or now >= authorization.expires_at:
        raise ValueError("network_authorization_inactive")
    if now < target_binding.issued_at or now >= target_binding.expires_at:
        raise ValueError("network_target_binding_inactive")
    if profile_id not in authorization.approved_profile_ids:
        raise ValueError("network_profile_not_authorized")
    if authorization.topology_sha256 != target_binding.topology_sha256:
        raise ValueError("network_topology_not_authorized")
    profile = certified_profiles().get(profile_id)
    if profile is None or not profile.enabled:
        raise ValueError("network_profile_disabled")

    targets = tuple(sorted({canonical_lab_ip(value) for value in target_binding.literal_targets}))
    if len(targets) != len(target_binding.literal_targets):
        raise ValueError("network_duplicate_target_denied")
    ports = tuple(sorted(set(target_binding.allowed_ports)))
    if len(ports) != len(target_binding.allowed_ports):
        raise ValueError("network_duplicate_port_denied")
    if any(not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535 for port in ports):
        raise ValueError("network_port_invalid")
    if len(targets) > profile.max_targets:
        raise ValueError("network_target_limit_exceeded")
    if len(ports) > profile.max_ports_per_target:
        raise ValueError("network_port_limit_exceeded")
    if len(targets) * len(ports) > profile.max_attempts:
        raise ValueError("network_attempt_limit_exceeded")

    tuples = tuple(
        CompiledNetworkTuple(
            tuple_id=f"r107:{hashlib.sha256(f'{ip}:{port}/tcp'.encode()).hexdigest()[:24]}",
            ip=ip,
            port=port,
            protocol=NetworkProtocol.TCP,
        )
        for ip in targets
        for port in ports
    )
    material = {
        "schema": "redagent.r107-plan/v1",
        "profile_id": profile_id.value,
        "topology_sha256": target_binding.topology_sha256,
        "route_sha256": target_binding.route_sha256,
        "target_set_id": target_binding.target_set_id,
        "tuples": [(item.tuple_id, item.ip, item.port, item.protocol.value) for item in tuples],
        "limits": [
            profile.max_attempts, profile.rate_per_second, profile.concurrency,
            profile.max_retries, profile.connect_timeout_seconds, profile.run_timeout_seconds,
            profile.banner_bytes, profile.output_bytes,
        ],
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return CompiledNetworkPlan(
        profile_id=profile_id,
        topology_sha256=target_binding.topology_sha256,
        route_sha256=target_binding.route_sha256,
        target_set_id=target_binding.target_set_id,
        tuples=tuples,
        target_count=len(targets),
        port_count=len(ports),
        attempt_limit=len(tuples),
        rate_per_second=profile.rate_per_second,
        concurrency=profile.concurrency,
        retry_limit=profile.max_retries,
        connect_timeout_seconds=profile.connect_timeout_seconds,
        run_timeout_seconds=profile.run_timeout_seconds,
        banner_bytes=profile.banner_bytes,
        output_bytes=profile.output_bytes,
        plan_sha256=digest,
    )
