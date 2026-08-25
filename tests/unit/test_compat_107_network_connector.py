from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.network_service.compiler import compile_network_plan
from redagent_platform.network_service.connector import (
    ConnectionOutcome,
    ConnectionState,
    execute_network_plan,
)
from redagent_platform.network_service.contracts import (
    NetworkAuthorization,
    NetworkProfileId,
    NetworkProtocol,
    NetworkTargetBinding,
)


NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


def authorization() -> NetworkAuthorization:
    return NetworkAuthorization(
        tenant_id="tenant-r107", policy_decision_id="decision-r107",
        policy_revision="r099-v1", roe_version_id="roe-r107",
        reservation_id="reservation-r107", topology_sha256="a" * 64,
        approved_profile_ids=(NetworkProfileId.TCP_CONNECT_DISCOVERY,),
        approved_at=NOW, expires_at=NOW + timedelta(minutes=15),
    )


def binding() -> NetworkTargetBinding:
    return NetworkTargetBinding(
        target_set_id="r107-local-fixture", topology_sha256="a" * 64,
        route_sha256="b" * 64, literal_targets=("10.107.0.10",),
        allowed_ports=(8080, 8443), protocol=NetworkProtocol.TCP,
        network_id="redagent-r107-gateway-target", non_production=True,
        issued_at=NOW, expires_at=NOW + timedelta(minutes=15),
    )


@dataclass
class FakeTransport:
    calls: list[tuple[str, int, int, int]]

    def connect(self, *, ip: str, port: int, timeout_seconds: int, max_bytes: int) -> ConnectionOutcome:
        self.calls.append((ip, port, timeout_seconds, max_bytes))
        if port == 8080:
            return ConnectionOutcome(state=ConnectionState.OPEN, latency_ms=4, received=b"HTTP/1.1 200 OK\r\nServer: fixture\r\n")
        return ConnectionOutcome(state=ConnectionState.REFUSED, latency_ms=2, received=b"")


def test_connector_executes_only_compiled_tuples_and_persists_no_raw_banner() -> None:
    plan = compile_network_plan(
        profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
        authorization=authorization(), target_binding=binding(), now=NOW,
    )
    transport = FakeTransport(calls=[])
    result = execute_network_plan(
        run_id="run-r107", plan=plan, authorization=authorization(),
        target_binding=binding(), now=NOW, confirmation="--confirm-r107-local-lab",
        transport=transport,
        revalidate=lambda item: ("a" * 64, "b" * 64, item.ip in binding().literal_targets),
    )
    assert transport.calls == [("10.107.0.10", 8080, 1, 256), ("10.107.0.10", 8443, 1, 256)]
    assert result.completed_count == 2 and result.partial is False
    assert result.observations[0].service_class == "http"
    assert result.observations[0].sample_sha256 != "0" * 64
    serialized = repr(result)
    assert "HTTP/1.1" not in serialized and "Server: fixture" not in serialized
    assert result.cleanup.residual_resource_count == 0


def test_connector_denies_before_transport_on_route_or_topology_drift() -> None:
    plan = compile_network_plan(
        profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
        authorization=authorization(), target_binding=binding(), now=NOW,
    )
    transport = FakeTransport(calls=[])
    result = execute_network_plan(
        run_id="run-r107", plan=plan, authorization=authorization(),
        target_binding=binding(), now=NOW, confirmation="--confirm-r107-local-lab",
        transport=transport,
        revalidate=lambda item: ("a" * 64, "c" * 64, True),
    )
    assert transport.calls == []
    assert result.partial is True and result.denied_count == 2
    assert all(item.reason == "network_gateway_route_denied" for item in result.observations)


def test_connector_cancellation_blocks_remaining_attempts_and_cleans_up() -> None:
    plan = compile_network_plan(
        profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
        authorization=authorization(), target_binding=binding(), now=NOW,
    )
    transport = FakeTransport(calls=[])
    checks = iter((False, True))
    result = execute_network_plan(
        run_id="run-r107", plan=plan, authorization=authorization(),
        target_binding=binding(), now=NOW, confirmation="--confirm-r107-local-lab",
        transport=transport,
        revalidate=lambda item: ("a" * 64, "b" * 64, True),
        cancel_requested=lambda: next(checks),
    )
    assert len(transport.calls) == 1
    assert result.cancelled is True and result.partial is True
    assert result.cancellation is not None
    assert result.cancellation.gateway_blocked is True
    assert result.cancellation.worker_stop_acknowledged is True
    assert result.cleanup.residual_resource_count == 0


def test_connector_requires_literal_confirmation_and_active_bindings() -> None:
    plan = compile_network_plan(
        profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
        authorization=authorization(), target_binding=binding(), now=NOW,
    )
    with pytest.raises(ValueError, match="network_local_lab_confirmation_required"):
        execute_network_plan(
            run_id="run-r107", plan=plan, authorization=authorization(),
            target_binding=binding(), now=NOW, confirmation="yes",
            transport=FakeTransport(calls=[]),
            revalidate=lambda item: ("a" * 64, "b" * 64, True),
        )
