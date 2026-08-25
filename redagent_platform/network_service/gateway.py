"""Independent compat_107 pre-connection tuple and budget admission policy."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class GatewayPolicy:
    plan_sha256: str
    topology_sha256: str
    route_sha256: str
    allowed_tuples: tuple[tuple[str, str, int, str], ...]
    attempt_limit: int
    rate_per_second: int
    concurrency_limit: int
    timeout_seconds: int
    banner_bytes: int
    total_data_bytes: int


@dataclass(frozen=True, kw_only=True)
class GatewayAttempt:
    tuple_id: str
    ip: str
    port: int
    protocol: str
    plan_sha256: str
    topology_sha256: str
    route_sha256: str
    banner_bytes: int


@dataclass(frozen=True, kw_only=True)
class GatewayUsage:
    attempt_count: int = 0
    attempts_this_second: int = 0
    active_connections: int = 0
    elapsed_seconds: int = 0
    total_data_bytes: int = 0


@dataclass(frozen=True, kw_only=True)
class GatewayDecision:
    allowed: bool
    reason: str
    tuple_id: str


def evaluate_gateway_attempt(attempt: GatewayAttempt, policy: GatewayPolicy, usage: GatewayUsage) -> GatewayDecision:
    def result(allowed: bool, reason: str) -> GatewayDecision:
        return GatewayDecision(allowed=allowed, reason=reason, tuple_id=attempt.tuple_id)

    if attempt.plan_sha256 != policy.plan_sha256:
        return result(False, "network_gateway_plan_denied")
    if attempt.topology_sha256 != policy.topology_sha256:
        return result(False, "network_gateway_topology_denied")
    if attempt.route_sha256 != policy.route_sha256:
        return result(False, "network_gateway_route_denied")
    if (attempt.tuple_id, attempt.ip, attempt.port, attempt.protocol) not in policy.allowed_tuples:
        return result(False, "network_gateway_tuple_denied")
    if attempt.banner_bytes < 0 or attempt.banner_bytes > policy.banner_bytes:
        return result(False, "network_gateway_banner_denied")
    if usage.attempt_count >= policy.attempt_limit:
        return result(False, "network_gateway_attempt_quota_exceeded")
    if usage.attempts_this_second >= policy.rate_per_second:
        return result(False, "network_gateway_rate_exceeded")
    if usage.active_connections >= policy.concurrency_limit:
        return result(False, "network_gateway_concurrency_exceeded")
    if usage.elapsed_seconds >= policy.timeout_seconds:
        return result(False, "network_gateway_time_exceeded")
    if usage.total_data_bytes >= policy.total_data_bytes:
        return result(False, "network_gateway_data_exceeded")
    return result(True, "network_gateway_allowed")
