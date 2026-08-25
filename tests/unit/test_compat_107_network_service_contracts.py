from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.network_service.compiler import compile_network_plan
from redagent_platform.network_service.contracts import (
    NetworkAuthorization,
    NetworkProfileId,
    NetworkProtocol,
    NetworkTargetBinding,
    certified_profiles,
)


NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


def authorization(**overrides: object) -> NetworkAuthorization:
    values = {
        "tenant_id": "tenant-r107",
        "policy_decision_id": "decision-r107",
        "policy_revision": "r099-v1",
        "roe_version_id": "roe-r107",
        "reservation_id": "reservation-r107",
        "topology_sha256": "a" * 64,
        "approved_profile_ids": (NetworkProfileId.TCP_CONNECT_DISCOVERY,),
        "approved_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
    }
    values.update(overrides)
    return NetworkAuthorization(**values)  # type: ignore[arg-type]


def binding(**overrides: object) -> NetworkTargetBinding:
    values = {
        "target_set_id": "r107-local-fixture",
        "topology_sha256": "a" * 64,
        "route_sha256": "b" * 64,
        "literal_targets": ("10.107.0.10", "10.107.0.11"),
        "allowed_ports": (8080, 8443),
        "protocol": NetworkProtocol.TCP,
        "network_id": "redagent-r107-gateway-target",
        "non_production": True,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
    }
    values.update(overrides)
    return NetworkTargetBinding(**values)  # type: ignore[arg-type]


def test_only_low_risk_connect_profile_is_enabled_and_independently_bounded() -> None:
    profiles = certified_profiles()
    assert set(profiles) == {NetworkProfileId.TCP_CONNECT_DISCOVERY}
    profile = profiles[NetworkProfileId.TCP_CONNECT_DISCOVERY]
    assert profile.enabled is True
    assert profile.raw_socket_allowed is False
    assert profile.dns_allowed is False
    assert profile.active_probe_allowed is False
    assert profile.script_allowed is False
    assert profile.max_targets <= 8 and profile.max_ports_per_target <= 16
    assert profile.max_attempts <= 64 and profile.concurrency <= 4
    assert profile.rate_per_second <= 4 and profile.max_retries == 0
    assert profile.banner_bytes <= 256 and profile.output_bytes <= 64 * 1024


def test_compiler_emits_canonical_literal_tuples_and_stable_hash() -> None:
    first = compile_network_plan(
        profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
        authorization=authorization(),
        target_binding=binding(literal_targets=("10.107.0.11", "10.107.0.10"), allowed_ports=(8443, 8080)),
        now=NOW,
    )
    second = compile_network_plan(
        profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
        authorization=authorization(),
        target_binding=binding(),
        now=NOW,
    )
    assert first == second
    assert [(item.ip, item.port, item.protocol.value) for item in first.tuples] == [
        ("10.107.0.10", 8080, "tcp"),
        ("10.107.0.10", 8443, "tcp"),
        ("10.107.0.11", 8080, "tcp"),
        ("10.107.0.11", 8443, "tcp"),
    ]
    assert len(first.plan_sha256) == 64
    assert first.target_count == 2 and first.attempt_limit == 4


@pytest.mark.parametrize(
    ("targets", "reason"),
    [
        (("fixture.local",), "network_literal_ip_required"),
        (("10.107.0.0/24",), "network_literal_ip_required"),
        (("10.107.0.10-20",), "network_literal_ip_required"),
        (("0.0.0.0",), "network_target_address_forbidden"),
        (("224.0.0.1",), "network_target_address_forbidden"),
        (("8.8.8.8",), "network_target_not_private"),
    ],
)
def test_compiler_rejects_scope_expansion_and_non_lab_addresses(targets: tuple[str, ...], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        compile_network_plan(
            profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
            authorization=authorization(),
            target_binding=binding(literal_targets=targets),
            now=NOW,
        )


def test_compiler_rejects_authorization_topology_profile_and_time_drift() -> None:
    with pytest.raises(ValueError, match="network_topology_not_authorized"):
        compile_network_plan(
            profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
            authorization=authorization(topology_sha256="c" * 64),
            target_binding=binding(),
            now=NOW,
        )
    with pytest.raises(ValueError, match="network_authorization_inactive"):
        compile_network_plan(
            profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
            authorization=authorization(),
            target_binding=binding(),
            now=NOW + timedelta(minutes=16),
        )


def test_target_binding_rejects_udp_privilege_and_wrong_topology() -> None:
    with pytest.raises(ValueError, match="network_target_binding_invalid"):
        binding(protocol=NetworkProtocol.UDP)
    with pytest.raises(ValueError, match="network_target_binding_invalid"):
        binding(network_id="host")
    with pytest.raises(ValueError, match="network_target_binding_invalid"):
        binding(non_production=False)
