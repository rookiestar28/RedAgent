from __future__ import annotations

from dataclasses import replace

import pytest

from redagent_platform.api_differential_service.gateway import (
    GatewayPolicy,
    GatewayRequest,
    GatewayUsage,
    evaluate_gateway_request,
)
from redagent_platform.api_differential_service.lifecycle import ResourceLedger, RuntimeLifecycle
from redagent_platform.api_differential_service.topology import certified_topology


def policy() -> GatewayPolicy:
    return GatewayPolicy(
        expected_destination="redagent-r106-target:8080",
        allowed_operations=(
            ("getDocument", "GET", "/documents/{documentId}"),
            ("getAudit", "GET", "/admin/audit"),
        ),
        identity_handles=("identity-owner", "identity-peer", "identity-admin"),
        request_limit=64, request_rate_per_second=2, concurrency_limit=1,
        timeout_seconds=120, request_body_bytes=16 * 1024,
        response_body_bytes=64 * 1024, total_data_bytes=2 * 1024 * 1024,
    )


def request(**overrides: object) -> GatewayRequest:
    values: dict[str, object] = {
        "operation_id": "getDocument", "identity_handle": "identity-peer",
        "method": "GET", "path": "/documents/document-owner-a",
        "path_template": "/documents/{documentId}", "destination": "redagent-r106-target:8080",
        "content_type": None, "body_bytes": 0, "redirect": False,
        "callback": False, "dns_changed": False,
    }
    values.update(overrides)
    return GatewayRequest(**values)  # type: ignore[arg-type]


def test_gateway_allows_only_compiled_operation_and_opaque_identity_handle() -> None:
    decision = evaluate_gateway_request(request(), policy(), GatewayUsage(elapsed_seconds=1))
    assert decision.allowed and decision.reason == "api_gateway_allowed"
    assert decision.identity_handle == "identity-peer"
    assert "token" not in repr(decision).lower() and "authorization" not in repr(decision).lower()

    denials = (
        (replace(request(), identity_handle="identity-unknown"), "api_gateway_identity_denied"),
        (replace(request(), destination="public.example:443"), "api_gateway_destination_denied"),
        (replace(request(), method="DELETE"), "api_gateway_operation_denied"),
        (replace(request(), path="/documents/../admin/audit"), "api_gateway_path_denied"),
        (replace(request(), redirect=True), "api_gateway_redirect_denied"),
        (replace(request(), callback=True), "api_gateway_callback_denied"),
        (replace(request(), dns_changed=True), "api_gateway_resolution_denied"),
        (replace(request(), body_bytes=1), "api_gateway_body_denied"),
    )
    for candidate, reason in denials:
        denied = evaluate_gateway_request(candidate, policy(), GatewayUsage(elapsed_seconds=1))
        assert not denied.allowed and denied.reason == reason


def test_gateway_enforces_independent_request_rate_concurrency_time_and_data_quotas() -> None:
    cases = (
        (GatewayUsage(request_count=64), "api_gateway_request_quota_exceeded"),
        (GatewayUsage(requests_this_second=2), "api_gateway_rate_quota_exceeded"),
        (GatewayUsage(active_requests=1), "api_gateway_concurrency_exceeded"),
        (GatewayUsage(elapsed_seconds=120), "api_gateway_time_quota_exceeded"),
        (GatewayUsage(total_data_bytes=2 * 1024 * 1024), "api_gateway_data_quota_exceeded"),
    )
    for usage, reason in cases:
        denied = evaluate_gateway_request(request(), policy(), usage)
        assert not denied.allowed and denied.reason == reason


def test_resource_ledger_compensates_reverse_dependency_order_and_replay_is_idempotent() -> None:
    ledger = ResourceLedger()
    ledger = ledger.record_created(
        resource_id="document-a", resource_lineage_sha256="a" * 64,
        owner_identity_handle="identity-owner", tenant_handle="tenant-a",
        idempotency_key="create-document-a", compensation_operation="deleteDocument",
    )
    ledger = ledger.record_created(
        resource_id="share-a", resource_lineage_sha256="b" * 64,
        owner_identity_handle="identity-owner", tenant_handle="tenant-a",
        idempotency_key="create-share-a", compensation_operation="deleteShare",
        depends_on=("document-a",),
    )
    replay = ledger.record_created(
        resource_id="share-a", resource_lineage_sha256="b" * 64,
        owner_identity_handle="identity-owner", tenant_handle="tenant-a",
        idempotency_key="create-share-a", compensation_operation="deleteShare",
        depends_on=("document-a",),
    )
    assert replay == ledger
    assert tuple(item.resource_id for item in ledger.compensation_order()) == ("share-a", "document-a")
    with pytest.raises(ValueError, match="api_resource_replay_mismatch"):
        ledger.record_created(
            resource_id="share-a", resource_lineage_sha256="c" * 64,
            owner_identity_handle="identity-owner", tenant_handle="tenant-a",
            idempotency_key="create-share-a", compensation_operation="deleteShare",
        )


def test_cancel_and_cleanup_order_gateway_stop_lease_compensation_and_zero_residue() -> None:
    lifecycle = RuntimeLifecycle.initial()
    with pytest.raises(ValueError, match="api_cancel_gateway_block_required"):
        lifecycle.acknowledge_native_stop()
    lifecycle = lifecycle.block_gateway().attempt_native_stop().acknowledge_native_stop()
    with pytest.raises(ValueError, match="api_cleanup_lease_revocation_required"):
        lifecycle.complete_cleanup(compensation_complete=True, residual_resource_count=0)
    lifecycle = lifecycle.revoke_leases().complete_cleanup(
        compensation_complete=True, residual_resource_count=0,
    )
    assert lifecycle.cleanup_complete and lifecycle.forced_termination is False


def test_topology_is_dual_internal_non_root_read_only_and_has_no_published_ports() -> None:
    topology = certified_topology()
    assert topology.worker_network.internal and topology.target_network.internal
    assert topology.worker.networks == (topology.worker_network.name,)
    assert topology.target.networks == (topology.target_network.name,)
    assert set(topology.gateway.networks) == {topology.worker_network.name, topology.target_network.name}
    for workload in (topology.worker, topology.gateway, topology.target):
        assert workload.user == "65532:65532" and workload.read_only
        assert workload.cap_drop == ("ALL",) and workload.no_new_privileges
        assert workload.published_ports == ()
