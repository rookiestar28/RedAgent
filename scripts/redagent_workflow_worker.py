#!/usr/bin/env python3
"""Run the bounded compat_096 database-only Temporal worker."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
from typing import Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from redagent_platform.orchestration.config import TemporalConfigError  # noqa: E402
from redagent_platform.campaign_service.composition import (  # noqa: E402
    build_stock_r123_coordinator_factory,
    build_stock_r123_relay_factory,
)
from redagent_platform.orchestration.gateway import OrchestrationUnavailable  # noqa: E402
from redagent_platform.orchestration.worker import run_workflow_worker  # noqa: E402
from redagent_platform.persistence.database import DatabaseConfigError  # noqa: E402


def build_runtime_r123_factory(
    workspace: Path,
    env: Mapping[str, str],
):
    """Select the stock compat_123 graph from the same immutable startup environment."""
    return build_stock_r123_coordinator_factory(workspace, env)


def build_runtime_r123_relay_factory(env: Mapping[str, str]):
    """Select the mandatory compat_123 outbox relay from the same startup environment."""
    return build_stock_r123_relay_factory(env)


def worker_health_response(path: str, *, ready: bool) -> tuple[int, bytes]:
    if path == "/health/live":
        payload = {"ok": True, "status": "live"}
        status = 200
    elif path == "/health/startup":
        payload = {"ok": True, "status": "started"}
        status = 200
    elif path == "/health/ready":
        payload = {"ok": ready, "status": "ready" if ready else "not_ready"}
        status = 200 if ready else 503
    else:
        payload = {"ok": False, "status": "not_found"}
        status = 404
    return status, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


async def _serve_health(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ready: asyncio.Event) -> None:
    try:
        request = await asyncio.wait_for(reader.readline(), timeout=2)
        parts = request.decode("ascii", errors="replace").strip().split()
        path = parts[1] if len(parts) >= 2 and parts[0] == "GET" else "/invalid"
        status, body = worker_health_response(path, ready=ready.is_set())
        reason = {200: "OK", 404: "Not Found", 503: "Service Unavailable"}[status]
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def _run(*, health_host: str, health_port: int, graceful_shutdown_seconds: int) -> None:
    ready = asyncio.Event()
    server = await asyncio.start_server(
        lambda reader, writer: _serve_health(reader, writer, ready),
        host=health_host,
        port=health_port,
        limit=8192,
    )
    async with server:
        values = dict(os.environ)
        r123_factory = await asyncio.to_thread(
            build_runtime_r123_factory,
            REPO_ROOT,
            values,
        )
        r123_relay_factory = build_runtime_r123_relay_factory(values)
        await run_workflow_worker(
            REPO_ROOT,
            env=values,
            graceful_shutdown_seconds=graceful_shutdown_seconds,
            r123_coordinator_factory=r123_factory,
            r123_relay_factory=r123_relay_factory,
            readiness_event=ready,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graceful-shutdown-seconds", type=int, default=30)
    parser.add_argument("--health-host", default="0.0.0.0")
    parser.add_argument("--health-port", type=int, default=9090)
    args = parser.parse_args()
    if not 1 <= args.health_port <= 65535:
        parser.error("--health-port must be between 1 and 65535")
    try:
        asyncio.run(
            _run(
                health_host=args.health_host,
                health_port=args.health_port,
                graceful_shutdown_seconds=args.graceful_shutdown_seconds,
            )
        )
    except (DatabaseConfigError, TemporalConfigError, OrchestrationUnavailable, OSError, ValueError) as exc:
        print(f"workflow_worker_error={exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
