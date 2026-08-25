"""R107 independent literal-tuple, route-hash, and traffic-budget gateway."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import socket
import socketserver
import threading
import time


POLICY_FILE = Path("/run/redagent/policy.json")
_LOCK = threading.Lock()
_ATTEMPTS = 0
_ACTIVE = 0
_DATA = 0
_STARTED = time.monotonic()


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        global _ACTIVE, _ATTEMPTS, _DATA
        admitted = False
        try:
            policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
            raw = self.rfile.readline(4097)
            if not raw or len(raw) > 4096:
                return self._reply(False, "network_gateway_request_invalid")
            request = json.loads(raw)
            expected = [request.get("tuple_id"), request.get("ip"), request.get("port"), request.get("protocol")]
            if request.get("plan_sha256") != policy["plan_sha256"]:
                return self._reply(False, "network_gateway_plan_denied")
            if request.get("topology_sha256") != policy["topology_sha256"]:
                return self._reply(False, "network_gateway_topology_denied")
            if request.get("route_sha256") != policy["route_sha256"]:
                return self._reply(False, "network_gateway_route_denied")
            if expected not in policy["tuples"]:
                return self._reply(False, "network_gateway_tuple_denied")
            with _LOCK:
                if _ATTEMPTS >= policy["attempt_limit"]:
                    return self._reply(False, "network_gateway_attempt_quota_exceeded")
                if _ACTIVE >= policy["concurrency"]:
                    return self._reply(False, "network_gateway_concurrency_exceeded")
                if time.monotonic() - _STARTED >= policy["run_timeout_seconds"]:
                    return self._reply(False, "network_gateway_time_exceeded")
                if _DATA >= policy["output_bytes"]:
                    return self._reply(False, "network_gateway_data_exceeded")
                _ATTEMPTS += 1
                _ACTIVE += 1
                admitted = True
            started = time.monotonic()
            try:
                # CRITICAL: the upstream address and port came from the exact mounted tuple policy, not request syntax.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.settimeout(policy["connect_timeout_seconds"])
                    connection.connect((request["ip"], int(request["port"])))
                    try:
                        received = connection.recv(policy["banner_bytes"])
                    except TimeoutError:
                        received = b""
                state = "open"
            except ConnectionRefusedError:
                state, received = "refused", b""
            except TimeoutError:
                state, received = "timeout", b""
            except OSError:
                state, received = "error", b""
            bounded = received[:policy["banner_bytes"]]
            with _LOCK:
                _DATA += len(bounded)
            prefix = bounded[:16].lower()
            service = "http" if prefix.startswith(b"http/") else "ssh" if prefix.startswith(b"ssh-") else "unknown"
            self._reply(True, f"network_connect_{state}", {
                "state": state,
                "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
                "service_class": service,
                "sample_sha256": hashlib.sha256(bounded).hexdigest(),
                "data_bytes": len(bounded),
            })
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            self._reply(False, "network_gateway_request_invalid")
        finally:
            if admitted:
                with _LOCK:
                    _ACTIVE -= 1

    def _reply(self, allowed: bool, reason: str, observation: dict[str, object] | None = None) -> None:
        body = {"allowed": allowed, "reason": reason, "observation": observation}
        self.wfile.write(json.dumps(body, sort_keys=True, separators=(",", ":")).encode() + b"\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


Server(("0.0.0.0", 8080), Handler).serve_forever()
