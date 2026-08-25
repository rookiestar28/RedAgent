"""Pure fail-closed request decisions for the independent compat_104 quota gateway."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from redagent_platform.zap_service.contracts import CertifiedProfileId, certified_profiles


@dataclass(frozen=True, slots=True)
class GatewayPolicy:
    profile_id: CertifiedProfileId
    expected_target_ip: str
    allowed_paths: tuple[str, ...]
    request_limit: int
    request_rate_per_second: int
    concurrency: int
    timeout_seconds: int
    response_bytes_limit: int
    max_query_bytes: int


@dataclass(frozen=True, slots=True)
class GatewayRequest:
    method: str
    path: str
    query_bytes: int
    request_body_bytes: int
    expected_target_ip: str
    resolved_target_ip: str
    redirect_hops: int
    active_requests: int
    elapsed_seconds: int

    def __post_init__(self) -> None:
        if self.method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ValueError("zap_gateway_method_invalid")
        if not isinstance(self.path, str) or not self.path.startswith("/") or len(self.path) > 256:
            raise ValueError("zap_gateway_path_invalid")
        for value in (
            self.query_bytes, self.request_body_bytes, self.redirect_hops,
            self.active_requests, self.elapsed_seconds,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("zap_gateway_request_measurement_invalid")
        _private_ip(self.expected_target_ip)
        _private_ip(self.resolved_target_ip)


@dataclass(frozen=True, slots=True)
class GatewayUsage:
    request_count: int
    response_bytes: int
    requests_in_current_second: int
    current_second: int

    def __post_init__(self) -> None:
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (
            self.request_count, self.response_bytes, self.requests_in_current_second,
        )) or not isinstance(self.current_second, int):
            raise ValueError("zap_gateway_usage_invalid")

    @classmethod
    def empty(cls) -> GatewayUsage:
        return cls(request_count=0, response_bytes=0, requests_in_current_second=0, current_second=-1)


@dataclass(frozen=True, slots=True)
class GatewayDecision:
    allowed: bool
    reason_code: str
    usage: GatewayUsage


def build_gateway_policy(profile_id: CertifiedProfileId, *, expected_target_ip: str) -> GatewayPolicy:
    _private_ip(expected_target_ip)
    profile = certified_profiles().get(profile_id)
    if profile is None:
        raise ValueError("zap_profile_unknown")
    return GatewayPolicy(
        profile_id=profile_id, expected_target_ip=expected_target_ip,
        allowed_paths=profile.allowed_paths, request_limit=profile.request_limit,
        request_rate_per_second=profile.request_rate_per_second,
        concurrency=profile.concurrency, timeout_seconds=profile.timeout_seconds,
        response_bytes_limit=profile.response_bytes_limit,
        max_query_bytes=2048 if profile_id is CertifiedProfileId.ACTIVE_XSS_LAB else 0,
    )


def decide_gateway_request(
    *, policy: GatewayPolicy, usage: GatewayUsage, request: GatewayRequest,
) -> GatewayDecision:
    def deny(reason: str) -> GatewayDecision:
        return GatewayDecision(allowed=False, reason_code=reason, usage=usage)

    if request.method not in {"GET", "HEAD"}:
        return deny("zap_gateway_method_denied")
    if request.path not in policy.allowed_paths:
        return deny("zap_gateway_path_denied")
    if request.expected_target_ip != policy.expected_target_ip or request.resolved_target_ip != policy.expected_target_ip:
        return deny("zap_gateway_resolution_denied")
    if request.redirect_hops:
        return deny("zap_gateway_redirect_denied")
    if request.request_body_bytes:
        return deny("zap_gateway_body_denied")
    if request.query_bytes > policy.max_query_bytes:
        return deny("zap_gateway_query_too_large")
    if usage.request_count >= policy.request_limit:
        return deny("zap_gateway_request_quota_exceeded")
    if request.active_requests >= policy.concurrency:
        return deny("zap_gateway_concurrency_exceeded")
    if request.elapsed_seconds >= policy.timeout_seconds:
        return deny("zap_gateway_time_quota_exceeded")
    if usage.response_bytes >= policy.response_bytes_limit:
        return deny("zap_gateway_data_quota_exceeded")
    same_second = usage.current_second == request.elapsed_seconds
    count_in_second = usage.requests_in_current_second if same_second else 0
    if count_in_second >= policy.request_rate_per_second:
        return deny("zap_gateway_rate_quota_exceeded")
    next_usage = GatewayUsage(
        request_count=usage.request_count + 1,
        response_bytes=usage.response_bytes,
        requests_in_current_second=count_in_second + 1,
        current_second=request.elapsed_seconds,
    )
    return GatewayDecision(allowed=True, reason_code="zap_gateway_allowed", usage=next_usage)


def _private_ip(value: str) -> None:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("zap_gateway_target_ip_invalid") from exc
    if not parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
        raise ValueError("zap_gateway_target_ip_invalid")
