"""Independent compat_106 scope, identity-handle, and quota admission policy."""

from __future__ import annotations

from dataclasses import dataclass
import re


_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True, kw_only=True)
class GatewayPolicy:
    expected_destination: str
    allowed_operations: tuple[tuple[str, str, str], ...]
    identity_handles: tuple[str, ...]
    request_limit: int
    request_rate_per_second: int
    concurrency_limit: int
    timeout_seconds: int
    request_body_bytes: int
    response_body_bytes: int
    total_data_bytes: int


@dataclass(frozen=True, kw_only=True)
class GatewayRequest:
    operation_id: str
    identity_handle: str
    method: str
    path: str
    path_template: str
    destination: str
    content_type: str | None
    body_bytes: int
    redirect: bool
    callback: bool
    dns_changed: bool


@dataclass(frozen=True, kw_only=True)
class GatewayUsage:
    request_count: int = 0
    requests_this_second: int = 0
    active_requests: int = 0
    elapsed_seconds: int = 0
    total_data_bytes: int = 0


@dataclass(frozen=True, kw_only=True)
class GatewayDecision:
    allowed: bool
    reason: str
    operation_id: str
    identity_handle: str


def evaluate_gateway_request(request: GatewayRequest, policy: GatewayPolicy, usage: GatewayUsage) -> GatewayDecision:
    def decision(allowed: bool, reason: str) -> GatewayDecision:
        return GatewayDecision(
            allowed=allowed, reason=reason,
            operation_id=request.operation_id, identity_handle=request.identity_handle,
        )

    if request.identity_handle not in policy.identity_handles:
        return decision(False, "api_gateway_identity_denied")
    if request.destination != policy.expected_destination:
        return decision(False, "api_gateway_destination_denied")
    operation = (request.operation_id, request.method, request.path_template)
    if operation not in policy.allowed_operations:
        return decision(False, "api_gateway_operation_denied")
    if not _matches_path(request.path_template, request.path):
        return decision(False, "api_gateway_path_denied")
    if request.redirect:
        return decision(False, "api_gateway_redirect_denied")
    if request.callback:
        return decision(False, "api_gateway_callback_denied")
    if request.dns_changed:
        return decision(False, "api_gateway_resolution_denied")
    if request.body_bytes < 0 or request.body_bytes > policy.request_body_bytes:
        return decision(False, "api_gateway_body_denied")
    if request.method == "GET" and (request.body_bytes != 0 or request.content_type is not None):
        return decision(False, "api_gateway_body_denied")
    if usage.request_count >= policy.request_limit:
        return decision(False, "api_gateway_request_quota_exceeded")
    if usage.requests_this_second >= policy.request_rate_per_second:
        return decision(False, "api_gateway_rate_quota_exceeded")
    if usage.active_requests >= policy.concurrency_limit:
        return decision(False, "api_gateway_concurrency_exceeded")
    if usage.elapsed_seconds >= policy.timeout_seconds:
        return decision(False, "api_gateway_time_quota_exceeded")
    if usage.total_data_bytes >= policy.total_data_bytes:
        return decision(False, "api_gateway_data_quota_exceeded")
    return decision(True, "api_gateway_allowed")


def _matches_path(template: str, path: str) -> bool:
    if "?" in path or "#" in path or "%" in path or "//" in path or ".." in path:
        return False
    template_segments = template.strip("/").split("/")
    path_segments = path.strip("/").split("/")
    if len(template_segments) != len(path_segments):
        return False
    for expected, observed in zip(template_segments, path_segments, strict=True):
        if expected.startswith("{") and expected.endswith("}"):
            if not _PATH_SEGMENT.fullmatch(observed):
                return False
        elif expected != observed:
            return False
    return True
