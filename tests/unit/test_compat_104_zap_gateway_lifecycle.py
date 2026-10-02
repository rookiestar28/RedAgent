from __future__ import annotations

from dataclasses import replace

import pytest

from redagent_platform.runner_service.contracts import CredentialClass, NetworkMode
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from redagent_platform.zap_service.contracts import CertifiedProfileId
from redagent_platform.zap_service.gateway import (
    GatewayRequest,
    GatewayUsage,
    build_gateway_policy,
    decide_gateway_request,
)
from redagent_platform.zap_service.lifecycle import cancellation_actions


def request(**overrides: object) -> GatewayRequest:
    values: dict[str, object] = {
        "method": "GET",
        "path": "/passive/missing-header",
        "query_bytes": 0,
        "request_body_bytes": 0,
        "expected_target_ip": "172.30.0.10",
        "resolved_target_ip": "172.30.0.10",
        "redirect_hops": 0,
        "active_requests": 0,
        "elapsed_seconds": 1,
    }
    values.update(overrides)
    return GatewayRequest(**values)  # type: ignore[arg-type]


def test_r100_capability_manifest_projects_closed_r104_runtime() -> None:
    manifest = build_zap_capability_manifest(
        platform="linux/amd64", artifact_receipt_id="artifact-r104-zap-2170",
    )
    assert manifest.capability_id == "zap-controlled-runtime"
    assert manifest.adapter_id == "zap-service"
    assert manifest.adapter_version == "2.17.0-r104.3"
    assert manifest.network_mode is NetworkMode.TARGET_ALLOWLIST
    assert manifest.credential_class is CredentialClass.HTTP_HEADER
    assert set(manifest.supported_modes) == {profile.value for profile in CertifiedProfileId}
    assert {"arbitrary_command", "native_template", "plugin_loading", "arbitrary_url",
            "native_api", "script_loading", "file_transfer", "oast"}.issubset(manifest.unsupported_features)
    with pytest.raises(ValueError, match="zap_platform_unsupported"):
        build_zap_capability_manifest(platform="windows/amd64", artifact_receipt_id="artifact-r104-zap-2170")


def test_gateway_allows_only_exact_get_head_path_and_attested_ip() -> None:
    policy = build_gateway_policy(CertifiedProfileId.PASSIVE, expected_target_ip="172.30.0.10")
    allowed = decide_gateway_request(policy=policy, usage=GatewayUsage.empty(), request=request())
    assert allowed.allowed is True and allowed.reason_code == "zap_gateway_allowed"
    assert allowed.usage.request_count == 1
    for change, reason in (
        ({"method": "POST"}, "zap_gateway_method_denied"),
        ({"path": "/active/reflected-input"}, "zap_gateway_path_denied"),
        ({"resolved_target_ip": "172.30.0.11"}, "zap_gateway_resolution_denied"),
        ({"redirect_hops": 1}, "zap_gateway_redirect_denied"),
        ({"request_body_bytes": 1}, "zap_gateway_body_denied"),
    ):
        decision = decide_gateway_request(policy=policy, usage=GatewayUsage.empty(), request=request(**change))
        assert decision.allowed is False and decision.reason_code == reason
        assert decision.usage == GatewayUsage.empty()


def test_gateway_enforces_request_rate_concurrency_time_and_data_before_forwarding() -> None:
    policy = build_gateway_policy(CertifiedProfileId.PASSIVE, expected_target_ip="172.30.0.10")
    full = GatewayUsage(
        request_count=policy.request_limit, response_bytes=0,
        requests_in_current_second=0, current_second=1,
    )
    assert decide_gateway_request(policy=policy, usage=full, request=request()).reason_code == "zap_gateway_request_quota_exceeded"
    rate = GatewayUsage(request_count=1, response_bytes=0, requests_in_current_second=3, current_second=1)
    assert decide_gateway_request(policy=policy, usage=rate, request=request()).reason_code == "zap_gateway_rate_quota_exceeded"
    assert decide_gateway_request(
        policy=policy, usage=GatewayUsage.empty(),
        request=request(active_requests=policy.concurrency),
    ).reason_code == "zap_gateway_concurrency_exceeded"
    assert decide_gateway_request(
        policy=policy, usage=GatewayUsage.empty(),
        request=request(elapsed_seconds=policy.timeout_seconds),
    ).reason_code == "zap_gateway_time_quota_exceeded"
    bytes_full = replace(GatewayUsage.empty(), response_bytes=policy.response_bytes_limit)
    assert decide_gateway_request(policy=policy, usage=bytes_full, request=request()).reason_code == "zap_gateway_data_quota_exceeded"


def test_active_profile_accepts_only_bounded_query_on_the_isolated_reflection_path() -> None:
    policy = build_gateway_policy(CertifiedProfileId.ACTIVE_XSS_LAB, expected_target_ip="172.30.0.10")
    allowed = decide_gateway_request(
        policy=policy, usage=GatewayUsage.empty(),
        request=request(path="/active/reflected-input", query_bytes=256),
    )
    assert allowed.allowed is True
    denied = decide_gateway_request(
        policy=policy, usage=GatewayUsage.empty(),
        request=request(path="/active/reflected-input", query_bytes=2049),
    )
    assert denied.reason_code == "zap_gateway_query_too_large"


def test_cancellation_always_attempts_native_stop_before_containment_and_cleanup() -> None:
    acknowledged = cancellation_actions(native_stop_acknowledged=True)
    forced = cancellation_actions(native_stop_acknowledged=False)
    common_prefix = (
        "block_gateway", "automation_stop", "spider_stop", "client_spider_stop",
        "active_scan_stop", "wait_native_ack", "revoke_credential_lease", "finalize_partial_evidence",
    )
    assert acknowledged[:len(common_prefix)] == common_prefix
    assert "terminate_workload" not in acknowledged
    assert forced[:len(common_prefix)] == common_prefix
    assert forced.index("terminate_workload") > forced.index("finalize_partial_evidence")
    assert forced[-3:] == ("erase_key_and_home", "remove_owned_resources", "verify_absence")
