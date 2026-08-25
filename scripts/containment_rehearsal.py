#!/usr/bin/env python3
"""Run the fixed ten-job/two-worker benign compat_101 stop acknowledgement rehearsal."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sys
from time import monotonic_ns

# IMPORTANT: direct script execution must resolve the repo package without a global install.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.containment_service.contracts import ContainmentPhase
from redagent_platform.containment_service.coordinator import ContainmentCoordinator


JOB_COUNT = 10
WORKER_COUNT = 2
ACK_SLO_MS = 10_000


class _Backend:
    def __init__(self, stopped: asyncio.Event) -> None:
        self._stopped = stopped

    async def execute_phase(self, phase: ContainmentPhase) -> str:
        if phase in {ContainmentPhase.RUNNER_ACK, ContainmentPhase.WORKLOAD_STOP}:
            await asyncio.wait_for(self._stopped.wait(), timeout=2)
        return f"{phase.value}_verified"


async def _dispatch(started: asyncio.Event, stopped: asyncio.Event) -> None:
    started.set()
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        stopped.set()
        raise


async def run_rehearsal() -> dict[str, object]:
    jobs = []
    for index in range(JOB_COUNT):
        started, stopped = asyncio.Event(), asyncio.Event()
        task = asyncio.create_task(_dispatch(started, stopped))
        jobs.append((index, started, stopped, task))
    await asyncio.gather(*(started.wait() for _, started, _, _ in jobs))
    requested = monotonic_ns()
    for _, _, _, task in jobs:
        task.cancel()
    await asyncio.gather(*(task for _, _, _, task in jobs), return_exceptions=True)

    async def contain(item):
        index, _, stopped, _ = item
        run = await ContainmentCoordinator(
            _Backend(stopped), clock=lambda: datetime.now(timezone.utc),
        ).contain()
        acknowledgement_ms = (monotonic_ns() - requested) // 1_000_000
        return {
            "job_id": f"synthetic-job-{index + 1:02d}",
            "worker_id": f"synthetic-worker-{index % WORKER_COUNT + 1}",
            "acknowledgement_ms": int(acknowledgement_ms),
            "outcome": run.assessment.outcome.value,
            "phase_count": len(run.receipts),
        }

    results = await asyncio.gather(*(contain(item) for item in jobs))
    maximum = max(int(row["acknowledgement_ms"]) for row in results)
    return {
        "schema": "redagent-r101-emergency-stop-rehearsal/v1",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "environment": {"os": platform.system(), "python": platform.python_version()},
        "job_count": JOB_COUNT, "worker_count": WORKER_COUNT,
        "ack_slo_ms": ACK_SLO_MS, "max_acknowledgement_ms": maximum,
        "passed": maximum <= ACK_SLO_MS and all(row["outcome"] == "contained" for row in results),
        "jobs": results,
    }


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run_rehearsal()), sort_keys=True))
