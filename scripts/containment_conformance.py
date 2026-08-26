#!/usr/bin/env python3
"""Build and contain fixed benign compat_101 process-tree fixtures with no external target."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
# IMPORTANT: direct execution places scripts/ on sys.path; keep repo imports deterministic.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.conformance_builder import attest_docker_image_config, pinned_conformance_builder


CONTEXT = ROOT / "containers" / "containment-synthetic"
LOCK = ROOT / "config" / "containment-conformance-image.json"
NETWORK = "redagent-r101-containment"
COOPERATIVE = "redagent-r101-cooperative"
FORCED = "redagent-r101-forced"


class ConformanceError(RuntimeError):
    pass


def _docker(
    *arguments: str,
    check: bool = True,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *arguments], cwd=ROOT, env=environment, text=True, capture_output=True,
        timeout=180, check=False,
    )
    if check and result.returncode != 0:
        raise ConformanceError(f"containment_docker_failed:{arguments[0]}:{result.stderr.strip()[:160]}")
    return result


def _lock() -> dict[str, object]:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def build() -> str:
    values = _lock()
    dockerfile_source = (CONTEXT / "Dockerfile").read_text(encoding="utf-8")
    # CRITICAL: keep the reviewed platform digest bound to the actual build input.
    if str(values["base_linux_amd64_digest"]) not in dockerfile_source:
        raise ConformanceError("containment_base_image_lock_mismatch")
    source_date_epoch = values.get("source_date_epoch")
    compatibility_version = values.get("buildkit_compatibility_version")
    if source_date_epoch != 1760544000 or compatibility_version != "20":
        raise ConformanceError("containment_reproducible_build_lock_invalid")
    output = ",".join((
        "type=docker",
        f"name={values['local_tag']}",
        "rewrite-timestamp=true",
        f"compatibility-version={compatibility_version}",
    ))
    # CRITICAL: rewrite COPY-layer timestamps before comparing the locked ID;
    # checkout mtimes are not an acceptable supply-chain identity input.
    with pinned_conformance_builder(ROOT, purpose="r101") as builder:
        _docker(
            *builder.build_prefix, "--no-cache", "--network", "none", "--provenance=false",
            "--build-arg", f"SOURCE_DATE_EPOCH={source_date_epoch}", "--output", output,
            "--file", str(CONTEXT / "Dockerfile"),
            str(CONTEXT),
            environment=dict(builder.environment),
        )
    observed = attest_docker_image_config(
        ROOT, str(values["local_tag"]), str(values["derived_image_id"])
    )
    return observed


def _remove_fixture(name: str) -> None:
    _docker("rm", "--force", name, check=False)


def _wait_ready(name: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if '"state": "ready"' in _docker("logs", name, check=False).stdout:
            return
        time.sleep(0.05)
    raise ConformanceError("containment_fixture_readiness_timeout")


def _run(name: str, *, ignore_term: bool) -> dict[str, object]:
    _remove_fixture(name)
    arguments = [
        "create", "--name", name, "--network", NETWORK, "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--pids-limit", "32", "--memory", "128m", "--cpus", "0.5",
        "--restart", "no", "--stop-timeout", "2", "--user", "65532:65532",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1m",
    ]
    if ignore_term:
        arguments.extend(("--env", "REDAGENT_SYNTHETIC_IGNORE_TERM=1"))
    arguments.append(str(_lock()["local_tag"]))
    _docker(*arguments)
    _docker("start", name)
    _wait_ready(name)
    before = json.loads(_docker("inspect", name).stdout)[0]
    if NETWORK not in before["NetworkSettings"]["Networks"]:
        raise ConformanceError("containment_network_attachment_missing")
    _docker("network", "disconnect", "--force", NETWORK, name)
    after_cut = json.loads(_docker("inspect", name).stdout)[0]
    disconnected = not after_cut["NetworkSettings"]["Networks"]
    _docker("stop", "--time", "2", name)
    stopped = json.loads(_docker("inspect", name).stdout)[0]
    logs = _docker("logs", name, check=False).stdout
    result = {
        "network_disconnected": disconnected,
        "running": bool(stopped["State"]["Running"]),
        "exit_code": int(stopped["State"]["ExitCode"]),
        "cleanup": '"cleanup": "completed"' in logs,
    }
    _remove_fixture(name)
    return result


def reset() -> None:
    _remove_fixture(COOPERATIVE)
    _remove_fixture(FORCED)
    _docker("network", "rm", NETWORK, check=False)


def conformance() -> dict[str, object]:
    reset()
    build()
    result: dict[str, object]
    try:
        _docker("network", "create", "--internal", NETWORK)
        network = json.loads(_docker("network", "inspect", NETWORK).stdout)[0]
        cooperative = _run(COOPERATIVE, ignore_term=False)
        forced = _run(FORCED, ignore_term=True)
        result = {
            "network_internal": bool(network["Internal"]),
            "network_disconnected": bool(cooperative["network_disconnected"] and forced["network_disconnected"]),
            "cooperative_stop": cooperative["exit_code"] == 0 and not cooperative["running"],
            "cooperative_cleanup": cooperative["cleanup"],
            "forced_kill": forced["exit_code"] == 137 and not forced["cleanup"],
            "forced_container_not_running": not forced["running"],
            "container_removed": all(_docker("inspect", name, check=False).returncode != 0 for name in (COOPERATIVE, FORCED)),
        }
    finally:
        reset()
    result["network_removed"] = _docker("network", "inspect", NETWORK, check=False).returncode != 0
    return result


if __name__ == "__main__":
    result = conformance()
    print(json.dumps(result, sort_keys=True))
