from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.nuclei_service.compiler import compile_nuclei_plan
from redagent_platform.nuclei_service.gateway import (
    NucleiGatewayRequest,
    NucleiGatewayUsage,
    build_gateway_policy,
    decide_gateway_request,
)
from redagent_platform.nuclei_service.lifecycle import cancellation_actions
from redagent_platform.nuclei_service.topology import certified_topology
from tests.unit.test_compat_105_nuclei_contracts import NOW, authorization, bundle, target
from redagent_platform.nuclei_service.contracts import NucleiProfileId


def test_compiler_rejects_not_yet_valid_authorization_target_and_bundle() -> None:
    for changed_bundle, changed_target, changed_authorization, reason in (
        (replace(bundle(), promoted_at=NOW + timedelta(seconds=1)), target(), authorization(), "nuclei_bundle_not_yet_valid"),
        (bundle(), replace(target(), issued_at=NOW + timedelta(seconds=1)), authorization(), "nuclei_target_not_yet_valid"),
        (bundle(), target(), replace(authorization(), approved_at=NOW + timedelta(seconds=1)), "nuclei_authorization_not_yet_valid"),
    ):
        with pytest.raises(ValueError, match=reason):
            compile_nuclei_plan(
                profile_id=NucleiProfileId.HTTP_HEADER,
                bundle=changed_bundle,
                target=changed_target,
                authorization=changed_authorization,
                now=NOW,
            )


def test_gateway_allows_only_exact_private_get_and_enforces_every_quota() -> None:
    policy = build_gateway_policy(NucleiProfileId.HTTP_HEADER, expected_target_ip="172.30.0.8")
    base = NucleiGatewayRequest(
        method="GET", path="/nuclei/missing-header", query_bytes=0,
        request_body_bytes=0, expected_target_ip="172.30.0.8",
        resolved_target_ip="172.30.0.8", redirect_hops=0,
        active_requests=0, elapsed_seconds=0,
    )
    usage = NucleiGatewayUsage.empty()
    assert decide_gateway_request(policy=policy, usage=usage, request=base).allowed is True
    cases = (
        (replace(base, method="POST"), "nuclei_gateway_method_denied"),
        (replace(base, path="/admin"), "nuclei_gateway_path_denied"),
        (replace(base, resolved_target_ip="172.30.0.9"), "nuclei_gateway_resolution_denied"),
        (replace(base, redirect_hops=1), "nuclei_gateway_redirect_denied"),
        (replace(base, request_body_bytes=1), "nuclei_gateway_body_denied"),
        (replace(base, query_bytes=1), "nuclei_gateway_query_denied"),
        (replace(base, active_requests=1), "nuclei_gateway_concurrency_exceeded"),
        (replace(base, elapsed_seconds=60), "nuclei_gateway_time_quota_exceeded"),
    )
    for request, reason in cases:
        decision = decide_gateway_request(policy=policy, usage=usage, request=request)
        assert decision.allowed is False and decision.reason_code == reason


def test_topology_capability_and_cancel_order_are_closed() -> None:
    topology = certified_topology()
    assert topology.published_ports == {}
    assert topology.attachments["worker"] == ("redagent-r105-worker-gateway",)
    assert topology.attachments["target"] == ("redagent-r105-gateway-target",)
    assert set(topology.attachments["gateway"]) == {
        "redagent-r105-worker-gateway", "redagent-r105-gateway-target",
    }
    manifest = build_nuclei_capability_manifest(
        platform="linux/amd64", artifact_receipt_id="artifact-r105-nuclei-380-r105-1",
    )
    assert manifest.capability_id == "nuclei-trusted-runtime"
    assert "arbitrary_template" in manifest.unsupported_features
    assert manifest.supported_modes == ("nuclei-http-header-v1",)
    graceful = cancellation_actions(native_stop_acknowledged=True)
    forced = cancellation_actions(native_stop_acknowledged=False)
    assert graceful.index("block_gateway") < graceful.index("signal_workload") < graceful.index("finalize_partial_evidence")
    assert "terminate_workload" not in graceful and "terminate_workload" in forced
    assert forced[-1] == "verify_absence"
