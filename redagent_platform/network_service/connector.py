"""Bounded unprivileged TCP CONNECT execution for the owned compat_107 local lab."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import socket
import time
from typing import Callable, Protocol

from redagent_platform.network_service.compiler import CompiledNetworkPlan, CompiledNetworkTuple, compile_network_plan
from redagent_platform.network_service.contracts import NetworkAuthorization, NetworkTargetBinding
from redagent_platform.network_service.gateway import (
    GatewayAttempt,
    GatewayPolicy,
    GatewayUsage,
    evaluate_gateway_attempt,
)
from redagent_platform.network_service.lifecycle import NetworkRunLifecycle


class ConnectionState(str, Enum):
    OPEN = "open"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    DENIED = "denied"
    ERROR = "error"


@dataclass(frozen=True, kw_only=True)
class ConnectionOutcome:
    state: ConnectionState
    latency_ms: int
    received: bytes


class ConnectTransport(Protocol):
    def connect(self, *, ip: str, port: int, timeout_seconds: int, max_bytes: int) -> ConnectionOutcome: ...


@dataclass(frozen=True, kw_only=True)
class NetworkObservation:
    tuple_id: str
    ip: str
    port: int
    state: ConnectionState
    latency_bucket: str
    service_class: str
    sample_sha256: str
    uncertainty: str
    reason: str


@dataclass(frozen=True, kw_only=True)
class CancellationReceipt:
    gateway_blocked: bool
    worker_stop_acknowledged: bool
    forced_termination: bool


@dataclass(frozen=True, kw_only=True)
class CleanupReceipt:
    residual_resource_count: int
    transient_data_erased: bool


@dataclass(frozen=True, kw_only=True)
class NetworkExecutionResult:
    run_id: str
    plan_sha256: str
    observations: tuple[NetworkObservation, ...]
    completed_count: int
    denied_count: int
    total_count: int
    partial: bool
    cancelled: bool
    cancellation: CancellationReceipt | None
    cleanup: CleanupReceipt


class StdlibTcpConnectTransport:
    """No-shell, no-DNS, OS TCP connect transport; call only after gateway admission."""

    def connect(self, *, ip: str, port: int, timeout_seconds: int, max_bytes: int) -> ConnectionOutcome:
        started = time.monotonic()
        try:
            # CRITICAL: AF_INET/AF_INET6 plus a prevalidated literal prevents resolver or scanner-native expansion.
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout_seconds)
                connection.connect((ip, port))
                try:
                    received = connection.recv(max_bytes)
                except TimeoutError:
                    received = b""
            return ConnectionOutcome(
                state=ConnectionState.OPEN,
                latency_ms=max(0, int((time.monotonic() - started) * 1000)),
                received=received[:max_bytes],
            )
        except ConnectionRefusedError:
            return ConnectionOutcome(state=ConnectionState.REFUSED, latency_ms=_elapsed(started), received=b"")
        except TimeoutError:
            return ConnectionOutcome(state=ConnectionState.TIMEOUT, latency_ms=_elapsed(started), received=b"")
        except OSError:
            return ConnectionOutcome(state=ConnectionState.ERROR, latency_ms=_elapsed(started), received=b"")


def execute_network_plan(
    *,
    run_id: str,
    plan: CompiledNetworkPlan,
    authorization: NetworkAuthorization,
    target_binding: NetworkTargetBinding,
    now: object,
    confirmation: str,
    transport: ConnectTransport,
    revalidate: Callable[[CompiledNetworkTuple], tuple[str, str, bool]],
    cancel_requested: Callable[[], bool] = lambda: False,
) -> NetworkExecutionResult:
    if confirmation != "--confirm-r107-local-lab":
        raise ValueError("network_local_lab_confirmation_required")
    # Recompile from immutable promoted inputs so a caller cannot substitute a hand-built plan.
    expected = compile_network_plan(
        profile_id=plan.profile_id,
        authorization=authorization,
        target_binding=target_binding,
        now=now,  # type: ignore[arg-type]
    )
    if expected != plan:
        raise ValueError("network_plan_integrity_invalid")

    policy = GatewayPolicy(
        plan_sha256=plan.plan_sha256,
        topology_sha256=plan.topology_sha256,
        route_sha256=plan.route_sha256,
        allowed_tuples=tuple((item.tuple_id, item.ip, item.port, item.protocol.value) for item in plan.tuples),
        attempt_limit=plan.attempt_limit,
        rate_per_second=plan.rate_per_second,
        concurrency_limit=plan.concurrency,
        timeout_seconds=plan.run_timeout_seconds,
        banner_bytes=plan.banner_bytes,
        total_data_bytes=plan.output_bytes,
    )
    usage = GatewayUsage()
    observations: list[NetworkObservation] = []
    lifecycle = NetworkRunLifecycle.start(run_id)
    cancellation: CancellationReceipt | None = None

    for item in plan.tuples:
        if cancel_requested():
            lifecycle = lifecycle.request_cancel().acknowledge_worker_stop(cooperative=True)
            lifecycle = lifecycle.complete_cleanup(container_count=0, network_count=0, transient_file_count=0)
            cancellation = CancellationReceipt(
                gateway_blocked=True, worker_stop_acknowledged=True, forced_termination=False,
            )
            break
        topology_sha256, route_sha256, still_in_scope = revalidate(item)
        request = GatewayAttempt(
            tuple_id=item.tuple_id,
            ip=item.ip if still_in_scope else "scope-denied",
            port=item.port,
            protocol=item.protocol.value,
            plan_sha256=plan.plan_sha256,
            topology_sha256=topology_sha256,
            route_sha256=route_sha256,
            banner_bytes=plan.banner_bytes,
        )
        decision = evaluate_gateway_attempt(request, policy, usage)
        if not decision.allowed:
            observations.append(_denied(item, decision.reason))
            continue
        outcome = transport.connect(
            ip=item.ip, port=item.port,
            timeout_seconds=plan.connect_timeout_seconds,
            max_bytes=plan.banner_bytes,
        )
        bounded = outcome.received[:plan.banner_bytes]
        observations.append(NetworkObservation(
            tuple_id=item.tuple_id,
            ip=item.ip,
            port=item.port,
            state=outcome.state,
            latency_bucket=_latency_bucket(outcome.latency_ms),
            service_class=_service_class(bounded),
            sample_sha256=hashlib.sha256(bounded).hexdigest(),
            uncertainty="low" if outcome.state in {ConnectionState.OPEN, ConnectionState.REFUSED} else "high",
            reason=f"network_connect_{outcome.state.value}",
        ))
        usage = GatewayUsage(
            attempt_count=usage.attempt_count + 1,
            attempts_this_second=usage.attempts_this_second + 1,
            active_connections=0,
            elapsed_seconds=usage.elapsed_seconds,
            total_data_bytes=usage.total_data_bytes + len(bounded),
        )

    denied_count = sum(item.state is ConnectionState.DENIED for item in observations)
    cancelled = cancellation is not None
    completed_count = sum(item.state is not ConnectionState.DENIED for item in observations)
    return NetworkExecutionResult(
        run_id=run_id,
        plan_sha256=plan.plan_sha256,
        observations=tuple(observations),
        completed_count=completed_count,
        denied_count=denied_count,
        total_count=len(plan.tuples),
        partial=cancelled or len(observations) != len(plan.tuples) or denied_count > 0,
        cancelled=cancelled,
        cancellation=cancellation,
        cleanup=CleanupReceipt(residual_resource_count=0, transient_data_erased=True),
    )


def _denied(item: CompiledNetworkTuple, reason: str) -> NetworkObservation:
    return NetworkObservation(
        tuple_id=item.tuple_id, ip=item.ip, port=item.port,
        state=ConnectionState.DENIED, latency_bucket="not_attempted",
        service_class="unknown", sample_sha256=hashlib.sha256(b"").hexdigest(),
        uncertainty="high", reason=reason,
    )


def _service_class(received: bytes) -> str:
    prefix = received[:16].lower()
    if prefix.startswith(b"http/"):
        return "http"
    if prefix.startswith(b"ssh-"):
        return "ssh"
    if prefix.startswith(b"220 "):
        return "smtp_or_ftp"
    return "unknown"


def _latency_bucket(milliseconds: int) -> str:
    if milliseconds < 10:
        return "lt_10ms"
    if milliseconds < 100:
        return "10_99ms"
    if milliseconds < 1000:
        return "100_999ms"
    return "gte_1s"


def _elapsed(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))
