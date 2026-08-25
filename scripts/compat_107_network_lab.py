"""Build, qualify, and clean the fixed local-only compat_107 network runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".local/redagent/r107-runtime"
LOCK_PATH = ROOT / "config/r107-network-runtime.json"
TARGET_DOCKERFILE = ROOT / "containers/r107-target/Dockerfile"
TARGET_SOURCE = ROOT / "containers/r107-target/fixture_server.py"
GATEWAY_DOCKERFILE = ROOT / "containers/r107-gateway/Dockerfile"
GATEWAY_SOURCE = ROOT / "containers/r107-gateway/gateway_server.py"
WORKER_DOCKERFILE = ROOT / "containers/r107-worker/Dockerfile"
WORKER_SOURCE = ROOT / "containers/r107-worker/worker.py"
TARGET_TAG = "redagent/r107-target:local"
GATEWAY_TAG = "redagent/r107-gateway:local"
WORKER_TAG = "redagent/r107-worker:local"
TARGET = "redagent-r107-target"
GATEWAY = "redagent-r107-gateway"
WORKER = "redagent-r107-worker"
WORKER_NET = "redagent-r107-worker-gateway"
TARGET_NET = "redagent-r107-gateway-target"
OWNER_LABEL = "redagent.owner=r107"
TARGET_IP = "10.107.0.10"


class R107Error(RuntimeError):
    """Stable local qualification denial."""


def build() -> dict[str, object]:
    lock = runtime_lock(require_images=False)
    for dockerfile, tag in (
        (TARGET_DOCKERFILE, TARGET_TAG),
        (GATEWAY_DOCKERFILE, GATEWAY_TAG),
        (WORKER_DOCKERFILE, WORKER_TAG),
    ):
        _run([
            "docker", "build", "--pull=false", "--provenance=false",
            "--tag", tag, "--file", str(dockerfile), str(ROOT),
        ])
    images: dict[str, str] = {}
    for tag in (TARGET_TAG, GATEWAY_TAG, WORKER_TAG):
        inspected = _json(["docker", "image", "inspect", tag])[0]
        if inspected.get("Config", {}).get("User") != "65532:65532":
            raise R107Error("r107_image_user_invalid")
        images[tag] = str(inspected["Id"])
    expected_images = {
        TARGET_TAG: lock["target_image_id"],
        GATEWAY_TAG: lock["gateway_image_id"],
        WORKER_TAG: lock["worker_image_id"],
    }
    if images != expected_images:
        raise R107Error("r107_image_identity_mismatch")
    receipt = {
        "schema": "redagent.r107-build/v1",
        "images": images,
        "sources": {
            "target_dockerfile": _sha(TARGET_DOCKERFILE),
            "target_source": _sha(TARGET_SOURCE),
            "gateway_dockerfile": _sha(GATEWAY_DOCKERFILE),
            "gateway_source": _sha(GATEWAY_SOURCE),
            "worker_dockerfile": _sha(WORKER_DOCKERFILE),
            "worker_source": _sha(WORKER_SOURCE),
        },
        "external_scanner_present": False,
        "production_qualified": False,
    }
    _write("build-receipt.json", receipt)
    return receipt


def qualify() -> dict[str, object]:
    runtime_lock(require_images=True)
    cleanup()
    RUNTIME.mkdir(parents=True, exist_ok=True)
    topology_sha = hashlib.sha256(b"redagent-r107-dual-internal-topology-v1").hexdigest()
    route_sha = hashlib.sha256(b"redagent-r107-gateway-only-route-v1").hexdigest()
    tuples = [
        [f"r107:{hashlib.sha256(f'{TARGET_IP}:{port}/tcp'.encode()).hexdigest()[:24]}", TARGET_IP, port, "tcp"]
        for port in (8080, 8443)
    ]
    material = {
        "schema": "redagent.r107-plan-material/v1",
        "profile_id": "tcp-connect-discovery-v1",
        "topology_sha256": topology_sha,
        "route_sha256": route_sha,
        "target_set_id": "r107-local-fixture",
        "tuples": tuples,
        "limits": [64, 4, 4, 0, 1, 30, 256, 65536],
    }
    plan_sha = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    policy = {
        "schema": "redagent.r107-gateway-policy/v1",
        "plan_sha256": plan_sha,
        "topology_sha256": topology_sha,
        "route_sha256": route_sha,
        "tuples": tuples,
        "attempt_limit": 2,
        "rate_per_second": 4,
        "concurrency": 4,
        "connect_timeout_seconds": 1,
        "run_timeout_seconds": 30,
        "banner_bytes": 256,
        "output_bytes": 65536,
    }
    plan = {
        "schema": "redagent.r107-worker-plan/v1",
        "plan_sha256": plan_sha,
        "topology_sha256": topology_sha,
        "route_sha256": route_sha,
        "run_timeout_seconds": 30,
        "tuples": tuples,
    }
    policy_path = RUNTIME / "policy.json"
    plan_path = RUNTIME / "plan.json"
    result_path = RUNTIME / "result.json"
    _write_path(policy_path, policy)
    _write_path(plan_path, plan)
    result_path.write_text("", encoding="utf-8")
    try:
        _run(["docker", "network", "create", "--internal", "--label", OWNER_LABEL, WORKER_NET])
        _run([
            "docker", "network", "create", "--internal", "--subnet", "10.107.0.0/24",
            "--label", OWNER_LABEL, TARGET_NET,
        ])
        _run(_container(TARGET, TARGET_NET, TARGET_TAG, ip=TARGET_IP))
        _run(_container(GATEWAY, TARGET_NET, GATEWAY_TAG, mounts=((policy_path, "/run/redagent/policy.json", True),)))
        _run(["docker", "network", "connect", WORKER_NET, GATEWAY])
        _assert_topology()
        _run_worker(plan_path, result_path)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        _validate_result(result, plan_sha)
        scope_denial = _negative_worker_result(
            plan | {"tuples": [["r107:forbidden-port", TARGET_IP, 9999, "tcp"]]},
            "negative-scope", "network_gateway_tuple_denied",
        )
        quota_denial = _negative_worker_result(
            plan | {"tuples": [tuples[0]]},
            "negative-quota", "network_gateway_attempt_quota_exceeded",
        )
        cancellation = _live_cancel(plan, policy_path)
        no_direct_route = _no_direct_target_route()
        receipt = {
            "schema": "redagent.r107-qualification/v1",
            "passed": True,
            "profile_id": "tcp-connect-discovery-v1",
            "plan_sha256": plan_sha,
            "topology_sha256": topology_sha,
            "route_sha256": route_sha,
            "literal_tuple_count": len(tuples),
            "completed_count": result["completed_count"],
            "denied_count": result["denied_count"],
            "service_classes": sorted(item["observation"]["service_class"] for item in result["observations"]),
            "raw_banner_persisted": False,
            "external_scanner_present": False,
            "dual_internal_networks": True,
            "published_ports": 0,
            "direct_target_route": not no_direct_route,
            "external_target_contacts": 0,
            "forbidden_tuple_denied": scope_denial,
            "gateway_attempt_quota_denied": quota_denial,
            "gateway_blocked_before_worker_stop": cancellation["gateway_blocked_before_worker_stop"],
            "cooperative_stop_acknowledged": cancellation["cooperative_stop_acknowledged"],
            "forced_termination": cancellation["forced_termination"],
            "production_qualified": False,
        }
        _write("qualification-receipt.json", receipt)
        return receipt
    finally:
        cleanup()


def cleanup() -> None:
    for name in (WORKER, GATEWAY, TARGET):
        subprocess.run(["docker", "rm", "--force", name], cwd=ROOT, check=False, capture_output=True, text=True)
    for name in (WORKER_NET, TARGET_NET):
        subprocess.run(["docker", "network", "rm", name], cwd=ROOT, check=False, capture_output=True, text=True)


def runtime_lock(*, require_images: bool) -> dict[str, object]:
    try:
        value = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise R107Error("r107_runtime_lock_invalid") from exc
    if (
        value.get("schema") != "redagent.r107-runtime-lock/v1"
        or value.get("platform") != "linux/amd64"
        or value.get("profile_id") != "tcp-connect-discovery-v1"
        or value.get("critical_vulnerability_count") != 0
        or value.get("external_scanner_present") is not False
        or value.get("external_target_allowed") is not False
        or value.get("raw_socket_allowed") is not False
        or value.get("runtime_update_allowed") is not False
        or value.get("production_qualified") is not False
    ):
        raise R107Error("r107_runtime_lock_safety_invalid")
    expected_sources = {
        "target_dockerfile_sha256": _sha(TARGET_DOCKERFILE),
        "target_source_sha256": _sha(TARGET_SOURCE),
        "gateway_dockerfile_sha256": _sha(GATEWAY_DOCKERFILE),
        "gateway_source_sha256": _sha(GATEWAY_SOURCE),
        "worker_dockerfile_sha256": _sha(WORKER_DOCKERFILE),
        "worker_source_sha256": _sha(WORKER_SOURCE),
    }
    if any(value.get(name) != digest for name, digest in expected_sources.items()):
        raise R107Error("r107_runtime_source_digest_mismatch")
    if require_images:
        expected_images = {
            TARGET_TAG: value.get("target_image_id"),
            GATEWAY_TAG: value.get("gateway_image_id"),
            WORKER_TAG: value.get("worker_image_id"),
        }
        observed_images = {
            tag: _json(["docker", "image", "inspect", tag])[0]["Id"]
            for tag in expected_images
        }
        if observed_images != expected_images:
            raise R107Error("r107_image_identity_mismatch")
    return value


def _container(
    name: str,
    network: str,
    image: str,
    *,
    detach: bool = True,
    ip: str | None = None,
    mounts: tuple[tuple[Path, str, bool], ...] = (),
) -> list[str]:
    command = [
        "docker", "run", "--name", name, "--label", OWNER_LABEL,
        "--network", network, "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "64",
        "--memory", "128m", "--cpus", "0.5", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
    ]
    if detach:
        command.append("--detach")
    if ip is not None:
        command.extend(["--ip", ip])
    for source, destination, readonly in mounts:
        spec = f"type=bind,source={source},target={destination}"
        if readonly:
            spec += ",readonly"
        command.extend(["--mount", spec])
    command.append(image)
    return command


def _assert_topology() -> None:
    for name, expected_networks in (
        (TARGET, {TARGET_NET}), (WORKER, {WORKER_NET}), (GATEWAY, {WORKER_NET, TARGET_NET}),
    ):
        if name == WORKER:
            continue
        item = _json(["docker", "container", "inspect", name])[0]
        networks = set(item["NetworkSettings"]["Networks"])
        ports = item["NetworkSettings"].get("Ports") or {}
        if networks != expected_networks or any(value for value in ports.values()):
            raise R107Error("r107_topology_invalid")
        host = item["HostConfig"]
        if not item["Config"].get("ReadonlyRootfs", host.get("ReadonlyRootfs")) and not host.get("ReadonlyRootfs"):
            raise R107Error("r107_readonly_rootfs_required")


def _no_direct_target_route() -> bool:
    command = [
        "docker", "run", "--rm", "--network", WORKER_NET,
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--entrypoint", "python", WORKER_TAG, "-I", "-c",
        "import socket; s=socket.socket(); s.settimeout(0.5); print(s.connect_ex(('10.107.0.10',8080)))",
    ]
    completed = _run(command, capture=True)
    return completed.stdout.strip() != "0"


def _run_worker(plan_path: Path, result_path: Path) -> None:
    subprocess.run(["docker", "rm", "--force", WORKER], cwd=ROOT, check=False, capture_output=True, text=True)
    result_path.write_text("", encoding="utf-8")
    _run(_container(
        WORKER, WORKER_NET, WORKER_TAG, detach=False,
        mounts=((plan_path, "/run/redagent/plan.json", True), (result_path, "/run/redagent/result.json", False)),
    ))


def _negative_worker_result(plan: dict[str, object], label: str, expected_reason: str) -> bool:
    plan_path = RUNTIME / f"{label}-plan.json"
    result_path = RUNTIME / f"{label}-result.json"
    _write_path(plan_path, plan)
    _run_worker(plan_path, result_path)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    observations = result.get("observations")
    return bool(
        result.get("denied_count") == 1
        and isinstance(observations, list)
        and len(observations) == 1
        and observations[0].get("reason") == expected_reason
    )


def _live_cancel(plan: dict[str, object], policy_path: Path) -> dict[str, bool]:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["attempt_limit"] = 64
    _write_path(policy_path, policy)
    cancel_plan = plan | {
        "tuples": [plan["tuples"][0] for _ in range(20)],
        "inter_attempt_delay_ms": 500,
    }
    plan_path = RUNTIME / "cancel-plan.json"
    result_path = RUNTIME / "cancel-result.json"
    _write_path(plan_path, cancel_plan)
    result_path.write_text("", encoding="utf-8")
    subprocess.run(["docker", "rm", "--force", WORKER], cwd=ROOT, check=False, capture_output=True, text=True)
    _run(_container(
        WORKER, WORKER_NET, WORKER_TAG,
        mounts=((plan_path, "/run/redagent/plan.json", True), (result_path, "/run/redagent/result.json", False)),
    ))
    time.sleep(0.8)
    # CRITICAL: remove the gateway path before signalling the exact owned worker workload.
    _run(["docker", "network", "disconnect", WORKER_NET, GATEWAY])
    stopped = _run(["docker", "stop", "--time", "5", WORKER], capture=True)
    inspected = _json(["docker", "container", "inspect", WORKER])[0]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    cooperative = bool(result.get("cancelled")) and int(inspected["State"]["ExitCode"]) == 0
    return {
        "gateway_blocked_before_worker_stop": stopped.returncode == 0,
        "cooperative_stop_acknowledged": cooperative,
        "forced_termination": not cooperative,
    }


def _validate_result(result: dict[str, object], plan_sha: str) -> None:
    observations = result.get("observations")
    if (
        result.get("schema") != "redagent.r107-worker-result/v1"
        or result.get("plan_sha256") != plan_sha
        or result.get("completed_count") != 2
        or result.get("denied_count") != 0
        or result.get("partial") is not False
        or not isinstance(observations, list)
        or len(observations) != 2
    ):
        raise R107Error("r107_result_invalid")
    services = {item.get("observation", {}).get("service_class") for item in observations}
    if services != {"http", "ssh"} or "HTTP/" in json.dumps(result) or "SSH-" in json.dumps(result):
        raise R107Error("r107_result_normalization_invalid")


def _run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise R107Error(f"r107_command_failed:{command[1]}:{completed.stderr[-500:]}")
    if not capture and completed.stdout:
        print(completed.stdout.strip())
    return completed


def _json(command: list[str]) -> object:
    return json.loads(_run(command, capture=True).stdout)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(name: str, value: object) -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    _write_path(RUNTIME / name, value)


def _write_path(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "qualify", "cleanup"))
    parser.add_argument("--confirm-r107-local-lab", action="store_true")
    args = parser.parse_args()
    if args.action in {"build", "qualify"} and not args.confirm_r107_local_lab:
        raise R107Error("r107_local_lab_confirmation_required")
    if args.action == "build":
        print(json.dumps(build(), sort_keys=True))
    elif args.action == "qualify":
        print(json.dumps(qualify(), sort_keys=True))
    else:
        cleanup()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except R107Error as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
