from __future__ import annotations

from redagent_platform.network_service.gateway import (
    GatewayAttempt,
    GatewayPolicy,
    GatewayUsage,
    evaluate_gateway_attempt,
)
from redagent_platform.network_service.lifecycle import NetworkRunLifecycle, NetworkRunState


def policy() -> GatewayPolicy:
    return GatewayPolicy(
        plan_sha256="a" * 64,
        topology_sha256="b" * 64,
        route_sha256="c" * 64,
        allowed_tuples=(("tuple-1", "10.107.0.10", 8080, "tcp"),),
        attempt_limit=4,
        rate_per_second=2,
        concurrency_limit=1,
        timeout_seconds=10,
        banner_bytes=256,
        total_data_bytes=1024,
    )


def attempt(**overrides: object) -> GatewayAttempt:
    values = {
        "tuple_id": "tuple-1",
        "ip": "10.107.0.10",
        "port": 8080,
        "protocol": "tcp",
        "plan_sha256": "a" * 64,
        "topology_sha256": "b" * 64,
        "route_sha256": "c" * 64,
        "banner_bytes": 128,
    }
    values.update(overrides)
    return GatewayAttempt(**values)  # type: ignore[arg-type]


def test_gateway_rechecks_exact_tuple_plan_topology_route_and_budgets() -> None:
    assert evaluate_gateway_attempt(attempt(), policy(), GatewayUsage()).allowed
    cases = (
        (attempt(ip="10.107.0.99"), GatewayUsage(), "network_gateway_tuple_denied"),
        (attempt(plan_sha256="d" * 64), GatewayUsage(), "network_gateway_plan_denied"),
        (attempt(topology_sha256="d" * 64), GatewayUsage(), "network_gateway_topology_denied"),
        (attempt(route_sha256="d" * 64), GatewayUsage(), "network_gateway_route_denied"),
        (attempt(protocol="udp"), GatewayUsage(), "network_gateway_tuple_denied"),
        (attempt(), GatewayUsage(attempt_count=4), "network_gateway_attempt_quota_exceeded"),
        (attempt(), GatewayUsage(attempts_this_second=2), "network_gateway_rate_exceeded"),
        (attempt(), GatewayUsage(active_connections=1), "network_gateway_concurrency_exceeded"),
        (attempt(), GatewayUsage(elapsed_seconds=10), "network_gateway_time_exceeded"),
        (attempt(banner_bytes=257), GatewayUsage(), "network_gateway_banner_denied"),
        (attempt(), GatewayUsage(total_data_bytes=1024), "network_gateway_data_exceeded"),
    )
    for request, usage, reason in cases:
        decision = evaluate_gateway_attempt(request, policy(), usage)
        assert not decision.allowed and decision.reason == reason


def test_cancel_blocks_gateway_before_worker_stop_and_cleanup_proves_zero_residual() -> None:
    lifecycle = NetworkRunLifecycle.start("run-r107")
    lifecycle = lifecycle.request_cancel()
    assert lifecycle.state is NetworkRunState.CANCELLING
    assert lifecycle.events[-1] == "gateway_blocked"
    lifecycle = lifecycle.acknowledge_worker_stop(cooperative=True)
    assert lifecycle.events[-1] == "worker_stop_acknowledged"
    lifecycle = lifecycle.complete_cleanup(container_count=0, network_count=0, transient_file_count=0)
    assert lifecycle.state is NetworkRunState.CANCELLED
    assert lifecycle.residual_resource_count == 0


def test_cleanup_cannot_close_with_residual_resources_or_before_stop() -> None:
    lifecycle = NetworkRunLifecycle.start("run-r107")
    try:
        lifecycle.complete_cleanup(container_count=0, network_count=0, transient_file_count=0)
    except ValueError as exc:
        assert str(exc) == "network_cleanup_before_stop"
    else:  # pragma: no cover
        raise AssertionError("cleanup should fail before cancellation and stop")

    lifecycle = lifecycle.request_cancel().acknowledge_worker_stop(cooperative=False)
    try:
        lifecycle.complete_cleanup(container_count=1, network_count=0, transient_file_count=0)
    except ValueError as exc:
        assert str(exc) == "network_cleanup_residual_resources"
    else:  # pragma: no cover
        raise AssertionError("cleanup should fail with residual resources")
