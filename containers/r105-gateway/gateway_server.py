"""Fixed R105 scope and quota gateway with no redirect or external route."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ipaddress
import json
import socket
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


UPSTREAM_HOST = "redagent-r105-target"
UPSTREAM_PORT = 8080
POLICY_FILE = Path("/run/redagent/gateway-policy.json")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_LOCK = threading.Lock()
_REQUEST_COUNT = 0
_RESPONSE_BYTES = 0
_SECOND = -1
_REQUESTS_IN_SECOND = 0
_ACTIVE_REQUESTS = 0
_STARTED = time.monotonic()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "RedAgentR105Gateway/1.0"

    def do_GET(self) -> None:  # noqa: N802
        global _ACTIVE_REQUESTS, _REQUEST_COUNT, _REQUESTS_IN_SECOND, _RESPONSE_BYTES, _SECOND
        admitted = False
        try:
            policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
            parsed = urlsplit(self.path)
            if parsed.path != "/nuclei/missing-header" or parsed.path not in policy["allowed_paths"]:
                self._deny(403, "nuclei_gateway_path_denied")
                return
            if parsed.query:
                self._deny(403, "nuclei_gateway_query_denied")
                return
            if int(self.headers.get("Content-Length", "0")) != 0 or self.headers.get("Transfer-Encoding") is not None:
                self._deny(405, "nuclei_gateway_body_denied")
                return
            observed_ip = socket.gethostbyname(UPSTREAM_HOST)
            expected_ip = str(ipaddress.ip_address(policy["expected_target_ip"]))
            if observed_ip != expected_ip:
                self._deny(403, "nuclei_gateway_resolution_denied")
                return
            elapsed = int(time.monotonic() - _STARTED)
            with _LOCK:
                second_count = _REQUESTS_IN_SECOND if _SECOND == elapsed else 0
                reason = _quota_reason(policy, elapsed, second_count)
                if reason is not None:
                    self._deny(429, reason)
                    return
                _REQUEST_COUNT += 1
                _SECOND = elapsed
                _REQUESTS_IN_SECOND = second_count + 1
                _ACTIVE_REQUESTS += 1
                admitted = True
            request = Request(
                f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}{parsed.path}",
                method="GET", headers={"User-Agent": "RedAgent-R105-Nuclei-Gateway/1.0"},
            )
            response = build_opener(NoRedirect).open(request, timeout=3)
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                self._deny(502, "nuclei_gateway_response_too_large")
                return
            with _LOCK:
                if _RESPONSE_BYTES + len(body) > int(policy["response_bytes_limit"]):
                    self._deny(429, "nuclei_gateway_data_quota_exceeded")
                    return
                _RESPONSE_BYTES += len(body)
            self.send_response(response.status)
            self.send_header("Content-Type", response.headers.get("Content-Type", "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except HTTPError as exc:
            self._deny(403 if 300 <= exc.code < 400 else 502,
                       "nuclei_gateway_redirect_denied" if 300 <= exc.code < 400 else "nuclei_gateway_upstream_failure")
        except (OSError, KeyError, TypeError, ValueError, URLError, json.JSONDecodeError):
            self._deny(502, "nuclei_gateway_upstream_failure")
        finally:
            if admitted:
                with _LOCK:
                    _ACTIVE_REQUESTS = max(_ACTIVE_REQUESTS - 1, 0)

    def _deny_method(self) -> None:
        self._deny(405, "nuclei_gateway_method_denied")

    do_HEAD = _deny_method
    do_POST = _deny_method
    do_PUT = _deny_method
    do_PATCH = _deny_method
    do_DELETE = _deny_method
    do_OPTIONS = _deny_method
    do_CONNECT = _deny_method

    def log_message(self, format: str, *args: object) -> None:
        return

    def _deny(self, status: int, reason: str) -> None:
        body = json.dumps({"ok": False, "reason": reason}, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def _quota_reason(policy: dict[str, object], elapsed: int, second_count: int) -> str | None:
    if _REQUEST_COUNT >= int(policy["request_limit"]):
        return "nuclei_gateway_request_quota_exceeded"
    if second_count >= int(policy["request_rate_per_second"]):
        return "nuclei_gateway_rate_quota_exceeded"
    if _ACTIVE_REQUESTS >= int(policy["concurrency"]):
        return "nuclei_gateway_concurrency_exceeded"
    if elapsed >= int(policy["timeout_seconds"]):
        return "nuclei_gateway_time_quota_exceeded"
    if _RESPONSE_BYTES >= int(policy["response_bytes_limit"]):
        return "nuclei_gateway_data_quota_exceeded"
    return None


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
