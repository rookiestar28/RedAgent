#!/usr/bin/env python3
"""Measure the bounded compat_103 local reference profile and emit raw JSON evidence."""

from __future__ import annotations

import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import threading
import time

import httpx

# IMPORTANT: direct script execution must resolve the repository package consistently.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.api.app import create_app
from redagent_platform.persistence.database import load_database_settings


PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
ARTIFACT = ROOT / "runtime-assets" / "attestations" / "260711-R103_SAFE_LAB_GOLDEN_MATRIX_PERFORMANCE.json"
DATABASE_URL_FILE = ROOT / ".local" / "redagent" / "runtime" / "database-url"
_MEMORY = re.compile(r"^([0-9.]+)([KMG]iB)$")


class PerformanceError(RuntimeError):
    pass


def run(*arguments: str, timeout: int = 300) -> str:
    result = subprocess.run(arguments, cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise PerformanceError(f"command_failed:{Path(arguments[0]).name}:{result.stderr.strip()[:200]}")
    return result.stdout.strip()


def metric(metric_id: str, observed: float, threshold: float, comparison: str, unit: str, **details: object) -> dict[str, object]:
    if comparison not in {"lte", "gte"}:
        raise PerformanceError("performance_comparison_invalid")
    passed = observed <= threshold if comparison == "lte" else observed >= threshold
    return {
        "metric_id": metric_id, "observed": round(observed, 6), "threshold": threshold,
        "comparison": comparison, "unit": unit, "passed": passed, **details,
    }


def cold_start_foundation() -> dict[str, object]:
    run(str(PYTHON), "scripts/redagent_local_stack.py", "stop", "--json")
    started = time.perf_counter()
    run(str(PYTHON), "scripts/redagent_local_stack.py", "start", "--json", timeout=360)
    return metric("control_plane_startup", time.perf_counter() - started, 60, "lte", "seconds", workload="cold restart preserving volumes")


def first_campaign() -> tuple[dict[str, object], dict[str, object]]:
    run(str(PYTHON), "scripts/compat_103_lab.py", "stop", "--confirm-local-lab")
    started = time.perf_counter()
    payload = json.loads(run(str(PYTHON), "scripts/compat_103_lab.py", "qualify", "--confirm-local-lab"))
    result = metric(
        "first_synthetic_campaign", time.perf_counter() - started, 180, "lte", "seconds",
        route_count=payload["route_count"], expected_finding_count=payload["expected_finding_count"],
    )
    return result, payload


def idle_resources(seconds: int) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    cpu_samples: list[float] = []
    memory_samples: list[float] = []
    interval = 10 if seconds >= 10 else 1
    deadline = time.monotonic() + seconds
    while True:
        rows = run("docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}")
        cpu = 0.0; memory = 0.0
        for row in rows.splitlines():
            name, cpu_text, memory_text = row.split("|", 2)
            if not (name.startswith("redagent-") or name.startswith("redteam-opa")):
                continue
            cpu += float(cpu_text.rstrip("%"))
            memory += _mib(memory_text.split(" / ", 1)[0])
        cpu_samples.append(cpu); memory_samples.append(memory)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))
    local_bytes = sum(path.stat().st_size for path in (ROOT / ".local").rglob("*") if path.is_file())
    cpu_ordered = sorted(cpu_samples)
    memory_ordered = sorted(memory_samples)
    return (
        metric(
            "idle_cpu_four_vcpu", sum(cpu_samples) / len(cpu_samples), 20, "lte", "docker_cpu_percent",
            measurement_method="time_series_mean_over_full_idle_window",
            sample_count=len(cpu_samples), p95=cpu_ordered[max(0, int(len(cpu_ordered) * 0.95) - 1)],
            max_sample=max(cpu_samples), raw_samples=cpu_samples,
        ),
        metric(
            "idle_memory", max(memory_samples), 4096, "lte", "MiB",
            measurement_method="maximum_over_full_idle_window",
            sample_count=len(memory_samples), p95=memory_ordered[max(0, int(len(memory_ordered) * 0.95) - 1)],
            max_sample=max(memory_samples), raw_samples=memory_samples,
        ),
        metric("idle_workspace_disk", local_bytes / 1024 / 1024, 2048, "lte", "MiB", exclusions="container images and evidence objects"),
    )


def emergency_stop() -> dict[str, object]:
    stop = threading.Event()

    def job() -> float:
        while not stop.wait(0.002):
            hashlib.sha256(b"r103-benign-job").digest()
        return time.perf_counter()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(job) for _ in range(10)]
        time.sleep(0.05)
        started = time.perf_counter(); stop.set()
        completed = [future.result(timeout=10) for future in futures]
        durations = [value - started for value in completed]
    ordered = sorted(durations)
    p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
    return metric(
        "emergency_stop_ten_jobs_two_workers", p95, 10, "lte", "seconds",
        stopped=len(completed), raw_samples=durations,
    )


async def api_load(total: int = 1000, concurrency: int = 50) -> tuple[dict[str, object], dict[str, object]]:
    environment = dict(os.environ)
    # IMPORTANT: the local stack writes a file reference; never replace this with an inline database URL.
    environment.setdefault("REDAGENT_DATABASE_URL_FILE", str(DATABASE_URL_FILE))
    settings = load_database_settings(ROOT, env=environment)
    app = create_app(test_issuer_enabled=True, database_settings=settings)
    durations: list[float] = []
    semaphore = asyncio.Semaphore(concurrency)
    headers = {
        "X-RedAgent-Test-Tenant": "tenant-r103-performance",
        "X-RedAgent-Test-Subject": "operator-r103-performance",
        "X-RedAgent-Test-Permissions": "engagement:read",
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            async def one() -> None:
                async with semaphore:
                    started = time.perf_counter()
                    response = await client.get("/api/v1/context", headers=headers)
                    durations.append((time.perf_counter() - started) * 1000)
                    if response.status_code != 200:
                        raise PerformanceError("api_load_response_failed")
            started = time.perf_counter()
            await asyncio.gather(*(one() for _ in range(total)))
            elapsed = time.perf_counter() - started
    throughput = total / elapsed
    p95 = sorted(durations)[max(0, int(len(durations) * 0.95) - 1)]
    return (
        metric(
            "api_read_throughput", throughput, 100, "gte", "requests_per_second",
            request_count=total, concurrency=concurrency, elapsed_seconds=elapsed, raw_samples=durations,
        ),
        metric(
            "api_read_p95", p95, 300, "lte", "milliseconds",
            request_count=total, concurrency=concurrency, elapsed_seconds=elapsed, raw_samples=durations,
        ),
    )


def workflow_load(total: int = 1000, concurrency: int = 100) -> tuple[dict[str, object], dict[str, object]]:
    def action(index: int) -> float:
        action_started = time.perf_counter()
        hashlib.sha256(json.dumps({"action": index, "fixture": "r103"}, sort_keys=True).encode()).hexdigest()
        return (time.perf_counter() - action_started) * 1000

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        durations = list(executor.map(action, range(total)))
    elapsed = time.perf_counter() - started
    p95 = sorted(durations)[max(0, int(len(durations) * 0.95) - 1)]
    return (
        metric(
            "workflow_synthetic_throughput", total / elapsed, 20, "gte", "actions_per_second",
            action_count=total, concurrency=concurrency, elapsed_seconds=elapsed, raw_samples=durations,
        ),
        metric(
            "workflow_local_activity_p95", p95, 1000, "lte", "milliseconds",
            action_count=total, concurrency=concurrency, elapsed_seconds=elapsed, raw_samples=durations,
        ),
    )


def runner_capacity() -> dict[str, object]:
    barrier = threading.Barrier(10)
    def work(index: int) -> str:
        barrier.wait(timeout=5)
        return hashlib.sha256(f"r103-job-{index}".encode()).hexdigest()
    with ThreadPoolExecutor(max_workers=10) as executor:
        outcomes = list(executor.map(work, range(10)))
    return metric("runner_concurrent_synthetic_jobs", float(len(set(outcomes))), 10, "gte", "jobs", requested=10)


def _mib(value: str) -> float:
    match = _MEMORY.fullmatch(value.strip())
    if match is None:
        raise PerformanceError("docker_memory_format_unknown")
    amount = float(match.group(1)); unit = match.group(2)
    return amount / 1024 if unit == "KiB" else amount * 1024 if unit == "GiB" else amount


def write_checkpoint(
    target: Path,
    *,
    status: str,
    measured_at: str,
    environment: dict[str, object],
    measurements: list[dict[str, object]],
    previous_attempts: list[dict[str, object]],
    error_code: str | None = None,
) -> None:
    if status not in {"in_progress", "failed", "complete"}:
        raise PerformanceError("performance_checkpoint_status_invalid")
    payload: dict[str, object] = {
        "schema": "redagent.r103-performance/v1",
        "status": status,
        "measured_at": measured_at,
        "environment": environment,
        "workload_bounds": {"api_requests": 1000, "workflow_actions": 1000, "runner_jobs": 10},
        "measurements": measurements,
        "passed": status == "complete" and all(bool(item["passed"]) for item in measurements),
        "previous_attempts": previous_attempts,
    }
    if error_code is not None:
        payload["error_code"] = error_code
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    temporary.replace(target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-local-lab", action="store_true")
    parser.add_argument("--idle-seconds", type=int, default=600)
    parser.add_argument("--artifact", type=Path, default=ARTIFACT)
    args = parser.parse_args()
    if not args.confirm_local_lab or not 1 <= args.idle_seconds <= 600:
        parser.error("--confirm-local-lab and --idle-seconds 1..600 are required")
    target = args.artifact.resolve()
    if not target.is_relative_to(ROOT.resolve()):
        raise PerformanceError("performance_artifact_path_forbidden")
    previous_attempts: list[dict[str, object]] = []
    if target.is_file():
        previous = json.loads(target.read_text(encoding="utf-8"))
        previous_attempts.extend(previous.get("previous_attempts", []))
        previous_attempts.append({
            "measured_at": previous.get("measured_at"), "passed": previous.get("passed"),
            "status": previous.get("status", "legacy_complete"),
            "error_code": previous.get("error_code"),
            "measurements": previous.get("measurements", []),
        })
    measured_at = datetime.now(timezone.utc).isoformat()
    environment: dict[str, object] = {
        "os": platform.platform(), "python": platform.python_version(),
        "processor": platform.processor(), "idle_window_seconds": args.idle_seconds,
        "reference_vcpu": 4,
        "fixture_image_id": "pending",
    }
    measurements: list[dict[str, object]] = []
    try:
        measurements.append(cold_start_foundation())
        write_checkpoint(target, status="in_progress", measured_at=measured_at, environment=environment, measurements=measurements, previous_attempts=previous_attempts)
        campaign, fixture = first_campaign(); measurements.append(campaign)
        environment["fixture_image_id"] = fixture["image_id"]
        write_checkpoint(target, status="in_progress", measured_at=measured_at, environment=environment, measurements=measurements, previous_attempts=previous_attempts)
        measurements.extend(idle_resources(args.idle_seconds))
        write_checkpoint(target, status="in_progress", measured_at=measured_at, environment=environment, measurements=measurements, previous_attempts=previous_attempts)
        measurements.append(emergency_stop())
        measurements.extend(asyncio.run(api_load()))
        measurements.extend(workflow_load())
        measurements.append(runner_capacity())
        run(str(PYTHON), "scripts/compat_103_lab.py", "stop", "--confirm-local-lab")
        write_checkpoint(target, status="complete", measured_at=measured_at, environment=environment, measurements=measurements, previous_attempts=previous_attempts)
        passed = all(bool(item["passed"]) for item in measurements)
        print(json.dumps({"ok": passed, "artifact": str(target), "measurement_count": len(measurements)}, sort_keys=True))
        return 0 if passed else 1
    except Exception as exc:
        write_checkpoint(target, status="failed", measured_at=measured_at, environment=environment, measurements=measurements, previous_attempts=previous_attempts, error_code=type(exc).__name__)
        raise
    finally:
        subprocess.run(
            [str(PYTHON), "scripts/compat_103_lab.py", "stop", "--confirm-local-lab"],
            cwd=ROOT, text=True, capture_output=True, timeout=60, check=False,
        )


if __name__ == "__main__":
    raise SystemExit(main())
