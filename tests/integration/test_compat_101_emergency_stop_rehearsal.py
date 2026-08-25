from __future__ import annotations

import asyncio

from scripts.containment_rehearsal import ACK_SLO_MS, JOB_COUNT, WORKER_COUNT, run_rehearsal


def test_ten_jobs_two_workers_acknowledge_within_r091_slo() -> None:
    result = asyncio.run(run_rehearsal())
    assert result["job_count"] == JOB_COUNT == 10
    assert result["worker_count"] == WORKER_COUNT == 2
    assert result["ack_slo_ms"] == ACK_SLO_MS == 10_000
    assert result["passed"] is True
    assert result["max_acknowledgement_ms"] <= ACK_SLO_MS
    assert {row["worker_id"] for row in result["jobs"]} == {"synthetic-worker-1", "synthetic-worker-2"}
    assert all(row["phase_count"] == 8 and row["outcome"] == "contained" for row in result["jobs"])
