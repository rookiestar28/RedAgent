"""R106 gateway: exact operation, identity-handle injection, and hard quota boundary."""

from __future__ import annotations

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import socket
import threading
import time
from urllib.parse import urlsplit


UPSTREAM_HOST = "redagent-r106-target"
UPSTREAM_PORT = 8080
POLICY_FILE = Path("/run/redagent/gateway-policy.json")
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_LOCK = threading.Lock()
_REQUEST_COUNT = 0
_REQUESTS_IN_SECOND = 0
_SECOND = -1
_ACTIVE = 0
_DATA_BYTES = 0
_STARTED = time.monotonic()


class Handler(BaseHTTPRequestHandler):
    server_version = "RedAgentR106Gateway/1.0"

    def do_GET(self) -> None:  # noqa: N802
        self._forward("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._forward("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._forward("DELETE")

    def _forward(self, method: str) -> None:
        global _ACTIVE, _DATA_BYTES, _REQUEST_COUNT, _REQUESTS_IN_SECOND, _SECOND
        admitted = False
        try:
            policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
            parsed = urlsplit(self.path)
            if parsed.query or parsed.fragment or "%" in parsed.path or ".." in parsed.path or "//" in parsed.path:
                self._deny(403, "api_gateway_path_denied")
                return
            operation_id = self.headers.get("X-R106-Operation-ID", "")
            identity_handle = self.headers.get("X-R106-Identity-Handle", "")
            operation = next((item for item in policy["operations"] if item == {
                "operation_id": operation_id, "method": method,
                "path_template": self.headers.get("X-R106-Path-Template", ""),
            }), None)
            if operation is None or not _matches(operation["path_template"], parsed.path):
                self._deny(403, "api_gateway_operation_denied")
                return
            identity = policy["identities"].get(identity_handle)
            if not isinstance(identity, dict):
                self._deny(403, "api_gateway_identity_denied")
                return
            observed_ip = socket.gethostbyname(UPSTREAM_HOST)
            if observed_ip != str(ipaddress.ip_address(policy["expected_target_ip"])):
                self._deny(403, "api_gateway_resolution_denied")
                return
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > int(policy["request_body_bytes"]):
                self._deny(413, "api_gateway_body_denied")
                return
            if method == "GET" and size != 0:
                self._deny(405, "api_gateway_body_denied")
                return
            body = self.rfile.read(size) if size else b""
            elapsed = int(time.monotonic() - _STARTED)
            with _LOCK:
                second_count = _REQUESTS_IN_SECOND if _SECOND == elapsed else 0
                reason = _quota_reason(policy, elapsed, second_count)
                if reason:
                    self._deny(429, reason)
                    return
                _REQUEST_COUNT += 1; _REQUESTS_IN_SECOND = second_count + 1; _SECOND = elapsed
                _ACTIVE += 1; admitted = True
            headers = {
                "X-R106-Gateway-Marker": "r106-owned-gateway",
                "X-R106-Tenant": identity["tenant_id"], "X-R106-User": identity["user_id"],
                "X-R106-Role": identity["role"], "X-R106-Identity-State": identity["state"],
                "X-R106-Idempotency-Key": self.headers.get("X-R106-Idempotency-Key", ""),
            }
            if body:
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(len(body))
            connection = HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=3)
            connection.request(method, parsed.path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(int(policy["response_body_bytes"]) + 1)
            connection.close()
            if len(response_body) > int(policy["response_body_bytes"]):
                self._deny(502, "api_gateway_response_too_large")
                return
            with _LOCK:
                if _DATA_BYTES + len(body) + len(response_body) > int(policy["total_data_bytes"]):
                    self._deny(429, "api_gateway_data_quota_exceeded")
                    return
                _DATA_BYTES += len(body) + len(response_body)
            self.send_response(response.status)
            if response.status != 204:
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if response_body:
                self.wfile.write(response_body)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._deny(502, "api_gateway_upstream_failure")
        finally:
            if admitted:
                with _LOCK:
                    _ACTIVE = max(_ACTIVE - 1, 0)

    def _deny_method(self) -> None:
        self._deny(405, "api_gateway_method_denied")

    do_HEAD = _deny_method
    do_PUT = _deny_method
    do_PATCH = _deny_method
    do_OPTIONS = _deny_method
    do_CONNECT = _deny_method

    def _deny(self, status: int, reason: str) -> None:
        body = json.dumps({"ok": False, "reason": reason}, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def _matches(template: str, path: str) -> bool:
    expected = template.strip("/").split("/")
    observed = path.strip("/").split("/")
    return len(expected) == len(observed) and all(
        (_SEGMENT.fullmatch(right) is not None) if left.startswith("{") and left.endswith("}") else left == right
        for left, right in zip(expected, observed, strict=True)
    )


def _quota_reason(policy: dict[str, object], elapsed: int, second_count: int) -> str | None:
    if _REQUEST_COUNT >= int(policy["request_limit"]): return "api_gateway_request_quota_exceeded"
    if second_count >= int(policy["request_rate_per_second"]): return "api_gateway_rate_quota_exceeded"
    if _ACTIVE >= int(policy["concurrency"]): return "api_gateway_concurrency_exceeded"
    if elapsed >= int(policy["timeout_seconds"]): return "api_gateway_time_quota_exceeded"
    if _DATA_BYTES >= int(policy["total_data_bytes"]): return "api_gateway_data_quota_exceeded"
    return None


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
