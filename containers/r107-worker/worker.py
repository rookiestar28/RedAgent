"""R107 no-shell worker that can connect only to the independent gateway."""

from __future__ import annotations

import json
from pathlib import Path
import signal
import socket
import time


PLAN_FILE = Path("/run/redagent/plan.json")
RESULT_FILE = Path("/run/redagent/result.json")
GATEWAY = ("redagent-r107-gateway", 8080)
_CANCELLED = False


def _cancel(_signum: int, _frame: object) -> None:
    global _CANCELLED
    _CANCELLED = True


signal.signal(signal.SIGTERM, _cancel)


plan = json.loads(PLAN_FILE.read_text(encoding="utf-8"))
if plan.get("schema") != "redagent.r107-worker-plan/v1":
    raise SystemExit("network_plan_invalid")
observations = []
started = time.monotonic()
for item in plan["tuples"]:
    if _CANCELLED or time.monotonic() - started >= plan["run_timeout_seconds"]:
        break
    request = {
        "tuple_id": item[0], "ip": item[1], "port": item[2], "protocol": item[3],
        "plan_sha256": plan["plan_sha256"],
        "topology_sha256": plan["topology_sha256"],
        "route_sha256": plan["route_sha256"],
    }
    try:
        with socket.create_connection(GATEWAY, timeout=2) as connection:
            connection.sendall(json.dumps(request, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            response = b""
            while not response.endswith(b"\n") and len(response) <= 4096:
                chunk = connection.recv(4096 - len(response))
                if not chunk:
                    break
                response += chunk
        observations.append(json.loads(response))
    except OSError:
        if not _CANCELLED:
            observations.append({"allowed": False, "reason": "network_gateway_unavailable", "observation": None})
    delay = min(max(int(plan.get("inter_attempt_delay_ms", 0)), 0), 1000) / 1000
    deadline = time.monotonic() + delay
    while not _CANCELLED and time.monotonic() < deadline:
        time.sleep(min(0.05, deadline - time.monotonic()))
result = {
    "schema": "redagent.r107-worker-result/v1",
    "plan_sha256": plan["plan_sha256"],
    "total_count": len(plan["tuples"]),
    "completed_count": sum(bool(item.get("allowed")) for item in observations),
    "denied_count": sum(not bool(item.get("allowed")) for item in observations),
    "partial": len(observations) != len(plan["tuples"]) or any(not item.get("allowed") for item in observations),
    "cancelled": _CANCELLED,
    "observations": observations,
}
RESULT_FILE.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
