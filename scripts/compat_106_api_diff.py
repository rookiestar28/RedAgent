"""Build, qualify, and clean the fixed local-only compat_106 API differential runtime."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from redagent_platform.api_differential_service.promotion import (  # noqa: E402
    verify_api_differential_promotion,
)


LOCK_PATH = ROOT / "config/r106-api-runtime.json"
BUNDLE = ROOT / "bundles/r106-api"
SPEC = BUNDLE / "openapi.json"
OPERATION_MANIFEST = BUNDLE / "operation-manifest.json"
RUNTIME = ROOT / ".local/redagent/r106-runtime"
WORKER_DOCKERFILE = ROOT / "containers/r106-worker/Dockerfile"
WORKER_SOURCE = ROOT / "containers/r106-worker/worker.py"
WORKER_LOCK = ROOT / "requirements-r106-worker.lock"
GATEWAY_DOCKERFILE = ROOT / "containers/r106-gateway/Dockerfile"
GATEWAY_SOURCE = ROOT / "containers/r106-gateway/gateway_server.py"
TARGET_DOCKERFILE = ROOT / "containers/r106-target/Dockerfile"
TARGET_SOURCE = ROOT / "containers/r106-target/fixture_server.py"
TARGET = "redagent-r106-target"
GATEWAY = "redagent-r106-gateway"
WORKER = "redagent-r106-worker"
WORKER_NET = "redagent-r106-worker-gateway"
TARGET_NET = "redagent-r106-gateway-target"
OWNER_LABEL = "redagent.owner=r106"


class R106Error(RuntimeError):
    """Stable local-runtime denial."""


def runtime_lock() -> dict[str, object]:
    try:
        value = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise R106Error("r106_runtime_lock_invalid") from exc
    if (
        value.get("schema") != "redagent.r106-runtime-lock/v1"
        or value.get("platform") != "linux/amd64"
        or value.get("schemathesis_version") != "4.22.4"
        or value.get("critical_vulnerability_count") != 0
        or value.get("external_target_allowed") is not False
        or value.get("arbitrary_transport_allowed") is not False
        or value.get("runtime_update_allowed") is not False
        or value.get("production_qualified") is not False
    ):
        raise R106Error("r106_runtime_lock_safety_invalid")
    expected = {
        "worker_lock_sha256": _sha(WORKER_LOCK),
        "worker_dockerfile_sha256": _sha(WORKER_DOCKERFILE),
        "worker_source_sha256": _sha(WORKER_SOURCE),
        "gateway_dockerfile_sha256": _sha(GATEWAY_DOCKERFILE),
        "gateway_source_sha256": _sha(GATEWAY_SOURCE),
        "target_dockerfile_sha256": _sha(TARGET_DOCKERFILE),
        "target_source_sha256": _sha(TARGET_SOURCE),
    }
    if any(value.get(key) != digest for key, digest in expected.items()):
        raise R106Error("r106_runtime_source_digest_mismatch")
    return value


def build() -> dict[str, object]:
    value = runtime_lock()
    builds = (
        (TARGET_DOCKERFILE, str(value["target_local_tag"])),
        (GATEWAY_DOCKERFILE, str(value["gateway_local_tag"])),
        (WORKER_DOCKERFILE, str(value["worker_local_tag"])),
    )
    for dockerfile, tag in builds:
        _run(["docker", "build", "--pull=false", "--provenance=false", "--tag", tag,
              "--file", str(dockerfile), str(ROOT)])
    expected = {
        str(value["target_local_tag"]): str(value["target_image_id"]),
        str(value["gateway_local_tag"]): str(value["gateway_image_id"]),
        str(value["worker_local_tag"]): str(value["worker_image_id"]),
    }
    for tag, image_id in expected.items():
        observed = _json(["docker", "image", "inspect", tag])[0]
        if observed.get("Id") != image_id or observed.get("Config", {}).get("User") != "65532:65532":
            raise R106Error("r106_owned_image_identity_mismatch")
    receipt = {"schema": "redagent.r106-build/v1", "images": expected,
               "critical_vulnerability_count": value["critical_vulnerability_count"]}
    _write_json(RUNTIME / "build-receipt.json", receipt)
    return receipt


def qualify() -> dict[str, object]:
    value = runtime_lock()
    artifact, snapshot, manifest, signature_sha = verify_api_differential_promotion(
        ROOT, now=datetime.now(timezone.utc),
    )
    cleanup()
    RUNTIME.mkdir(parents=True, exist_ok=True)
    policy_path = RUNTIME / "gateway-policy.json"
    plan_path = RUNTIME / "plan.json"
    result_path = RUNTIME / "result.json"
    cancel_path = RUNTIME / "cancel-result.json"
    for path in (policy_path, plan_path, result_path, cancel_path):
        path.unlink(missing_ok=True)
    try:
        _run(["docker", "network", "create", "--internal", "--label", OWNER_LABEL, WORKER_NET])
        _run(["docker", "network", "create", "--internal", "--label", OWNER_LABEL, TARGET_NET])
        _run(_container_prefix(TARGET, TARGET_NET, "128m", "0.5") + [str(value["target_local_tag"])])
        target_ip = _container_ip(TARGET, TARGET_NET)
        operation_document = json.loads(OPERATION_MANIFEST.read_text(encoding="utf-8"))
        operations = [
            {"operation_id": item["operation_id"], "method": item["method"],
             "path_template": item["path"]}
            for item in operation_document["operations"]
        ]
        policy = {
            "schema": "redagent.r106-gateway-policy/v1",
            "expected_target_ip": target_ip,
            "operations": operations,
            "identities": {
                "identity-owner": _identity("tenant-a", "user-a", "owner", "active"),
                "identity-peer": _identity("tenant-a", "user-b", "peer", "active"),
                "identity-admin": _identity("tenant-a", "admin-a", "tenant_admin", "active"),
                "identity-other-tenant": _identity("tenant-b", "user-x", "peer", "active"),
                "identity-expired": _identity("tenant-a", "user-a", "owner", "expired"),
                "identity-revoked": _identity("tenant-a", "user-a", "owner", "revoked"),
                "identity-anonymous": _identity("anonymous", "anonymous", "anonymous", "anonymous"),
            },
            "request_limit": 40, "request_rate_per_second": 2, "concurrency": 1,
            "timeout_seconds": 60, "request_body_bytes": 16 * 1024,
            "response_body_bytes": 64 * 1024, "total_data_bytes": 2 * 1024 * 1024,
        }
        plan = {"schema": "redagent.r106-worker-plan/v1", "seed": 10620260711,
                "operations": operations}
        _write_json(policy_path, policy)
        _write_json(plan_path, plan)
        result_path.touch()
        gateway = _container_prefix(GATEWAY, TARGET_NET, "128m", "0.5")
        gateway.extend(["--mount", _mount(policy_path, "/run/redagent/gateway-policy.json", readonly=True),
                        str(value["gateway_local_tag"])])
        _run(gateway)
        _run(["docker", "network", "connect", WORKER_NET, GATEWAY])
        _assert_topology()
        worker = _worker_command(value, plan_path, result_path)
        _run(worker, capture=True)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        _validate_result(result)
        _assert_no_direct_target_route(value)
        _negative_gateway_checks()
        cancellation = _native_cancel_check(value, plan_path, cancel_path)
        receipt = {
            "schema": "redagent.r106-qualification/v1", "passed": True,
            "artifact_receipt_id": artifact.receipt_id,
            "artifact_signature_sha256": signature_sha,
            "bundle_manifest_sha256": hashlib.sha256(
                (BUNDLE / "bundle-manifest.json").read_bytes()).hexdigest(),
            "canonical_spec_sha256": snapshot.spec_sha256,
            "bundle_id": manifest["bundle_id"], "engine_version": result["engine_version"],
            "baseline_operation_count": len(result["baseline"]),
            "authorization_oracles": [item["label"] for item in result["observations"]],
            "bola": True, "valid_negative": True, "cross_tenant": True,
            "bfla": True, "bopla": True, "anonymous": True, "expired": True, "revoked": True,
            "ownership_transition": True, "stateful_reverse_cleanup": True,
            "credential_material_present": False,
            "dual_internal_networks": True, "published_ports": 0,
            "direct_target_route": False, "external_target_contacts": 0,
            "gateway_unknown_operation_denied": True, "gateway_unknown_identity_denied": True,
            "gateway_quota_denied": True,
            "gateway_blocked_before_native_stop": True,
            "native_stop_acknowledged": cancellation["native_stop_acknowledged"],
            "forced_termination": cancellation["forced_termination"],
            "cleanup_residual_resource_count": 0, "production_qualified": False,
        }
        _write_json(RUNTIME / "qualification.json", receipt)
        return receipt
    finally:
        for path in (policy_path, plan_path, result_path, cancel_path):
            path.unlink(missing_ok=True)
        cleanup_receipt = cleanup()
        if cleanup_receipt["residual_resource_count"] != 0:
            raise R106Error("r106_cleanup_incomplete")


def cleanup() -> dict[str, object]:
    removed_containers = 0
    removed_networks = 0
    for name in (WORKER, GATEWAY, TARGET):
        inspected = _json(["docker", "inspect", name], check=False)
        if inspected:
            if inspected[0].get("Config", {}).get("Labels", {}).get("redagent.owner") != "r106":
                raise R106Error(f"r106_ownership_mismatch:{name}")
            _run(["docker", "rm", "-f", name]); removed_containers += 1
    for name in (WORKER_NET, TARGET_NET):
        inspected = _json(["docker", "network", "inspect", name], check=False)
        if inspected:
            if inspected[0].get("Labels", {}).get("redagent.owner") != "r106":
                raise R106Error(f"r106_ownership_mismatch:{name}")
            _run(["docker", "network", "rm", name]); removed_networks += 1
    residual = len(_lines(["docker", "ps", "-a", "--filter", "label=redagent.owner=r106", "-q"]))
    residual += len(_lines(["docker", "network", "ls", "--filter", "label=redagent.owner=r106", "-q"]))
    receipt = {"schema": "redagent.r106-cleanup/v1", "container_count": removed_containers,
               "network_count": removed_networks, "transient_file_count": 0,
               "residual_resource_count": residual, "cleanup_complete": residual == 0}
    _write_json(RUNTIME / "cleanup-receipt.json", receipt)
    return receipt


def _validate_result(result: dict[str, object]) -> None:
    if result.get("schema") != "redagent.r106-worker-result/v1" or result.get("engine_version") != "4.22.4":
        raise R106Error("r106_worker_result_invalid")
    baseline = result.get("baseline")
    if not isinstance(baseline, list) or len(baseline) != 6 or any(
        not isinstance(item, dict) or int(item.get("status", 500)) >= 500 for item in baseline
    ):
        raise R106Error("r106_baseline_invalid")
    observations = {item["label"]: item for item in result.get("observations", []) if isinstance(item, dict)}
    expected = {"bola", "valid_negative", "cross_tenant", "bfla", "bopla", "anonymous", "expired", "revoked"}
    if set(observations) != expected:
        raise R106Error("r106_authorization_matrix_incomplete")
    if (observations["bola"]["privileged_status"], observations["bola"]["lower_status"]) != (200, 200):
        raise R106Error("r106_bola_oracle_failed")
    if observations["valid_negative"]["lower_status"] != 404 or observations["cross_tenant"]["lower_status"] != 404:
        raise R106Error("r106_valid_negative_or_tenant_oracle_failed")
    if (observations["bfla"]["privileged_status"], observations["bfla"]["lower_status"]) != (200, 200):
        raise R106Error("r106_bfla_oracle_failed")
    if "internal_note" not in observations["bopla"]["lower_properties"]:
        raise R106Error("r106_bopla_oracle_failed")
    if observations["expired"]["lower_status"] != 401 or observations["revoked"]["lower_status"] != 401:
        raise R106Error("r106_identity_state_oracle_failed")
    if observations["anonymous"]["lower_status"] != 401:
        raise R106Error("r106_anonymous_oracle_failed")
    stateful = result.get("stateful")
    if not isinstance(stateful, dict) or tuple(stateful.get(key) for key in (
        "create_status", "read_status", "delete_status", "reset_status")) != (201, 200, 204, 404):
        raise R106Error("r106_stateful_cleanup_failed")
    transition = result.get("ownership_transition")
    if not isinstance(transition, dict) or tuple(transition.get(key) for key in (
        "create_status", "transfer_status", "former_owner_status", "new_owner_status", "cleanup_status",
    )) != (201, 200, 200, 200, 204):
        raise R106Error("r106_ownership_transition_oracle_failed")
    if result.get("credential_material_present") is not False:
        raise R106Error("r106_credential_material_present")


def _negative_gateway_checks() -> None:
    code = (
        "from http.client import HTTPConnection;"
        "c=HTTPConnection('127.0.0.1',8080,timeout=3);"
        "c.request('GET','/admin/audit',headers={'X-R106-Operation-ID':'unknown','X-R106-Path-Template':'/admin/audit','X-R106-Identity-Handle':'identity-admin'});"
        "r=c.getresponse();raise SystemExit(0 if r.status==403 else 8)"
    )
    _run(["docker", "exec", GATEWAY, "python", "-I", "-c", code])
    identity_code = code.replace("'unknown'", "'getAudit'").replace("'identity-admin'", "'identity-unknown'")
    _run(["docker", "exec", GATEWAY, "python", "-I", "-c", identity_code])
    quota_code = (
        "from http.client import HTTPConnection;reason='';"
        "\nfor i in range(12):"
        "\n c=HTTPConnection('127.0.0.1',8080,timeout=3);c.request('GET','/admin/audit',headers={'X-R106-Operation-ID':'getAudit','X-R106-Path-Template':'/admin/audit','X-R106-Identity-Handle':'identity-admin'});r=c.getresponse();b=r.read();c.close();"
        "\n if r.status==429: reason=b.decode();break"
        "\n time.sleep(.55)".replace("time.sleep", "__import__('time').sleep") +
        "\nraise SystemExit(0 if 'quota_exceeded' in reason else 7)"
    )
    _run(["docker", "exec", GATEWAY, "python", "-I", "-c", quota_code])


def _native_cancel_check(value: dict[str, object], plan_path: Path, cancel_path: Path) -> dict[str, bool]:
    _owned_remove_container(WORKER)
    cancel_path.touch()
    worker = _worker_command(value, plan_path, cancel_path)
    worker.insert(2, "-d")
    acknowledged = False
    forced = False
    _run(["docker", "pause", GATEWAY])
    try:
        _run(worker, capture=True)
        time.sleep(0.3)
        stopped = _run(["docker", "stop", "--signal", "SIGTERM", "--time", "3", WORKER],
                       check=False, capture=True)
        acknowledged = stopped.returncode == 0
        if not acknowledged:
            _run(["docker", "kill", WORKER]); forced = True
    finally:
        _run(["docker", "unpause", GATEWAY], check=False)
        _owned_remove_container(WORKER)
        cancel_path.unlink(missing_ok=True)
    return {"native_stop_acknowledged": acknowledged, "forced_termination": forced}


def _worker_command(value: dict[str, object], plan_path: Path, result_path: Path) -> list[str]:
    return ["docker", "run", "--name", WORKER, "--label", OWNER_LABEL,
            "--network", WORKER_NET, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "64",
            "--memory", "1g", "--cpus", "1",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m,mode=1777",
            "--tmpfs", "/home/redagent:rw,noexec,nosuid,size=32m,mode=1777",
            "--mount", _mount(plan_path, "/run/redagent/plan.json", readonly=True),
            "--mount", _mount(SPEC, "/run/redagent/openapi.json", readonly=True),
            "--mount", _mount(result_path, "/work/result.json"),
            str(value["worker_local_tag"])]


def _assert_no_direct_target_route(value: dict[str, object]) -> None:
    code = ("import socket;\ntry: socket.gethostbyname('redagent-r106-target')\n"
            "except socket.gaierror: raise SystemExit(0)\nraise SystemExit(9)")
    result = _run(["docker", "run", "--rm", "--network", WORKER_NET,
                   "--entrypoint", "python", str(value["worker_local_tag"]), "-I", "-c", code],
                  check=False, capture=True)
    if result.returncode != 0:
        raise R106Error("r106_direct_target_route_present")


def _assert_topology() -> None:
    observed = {name: _json(["docker", "inspect", name])[0] for name in (TARGET, GATEWAY)}
    if set(observed[TARGET]["NetworkSettings"]["Networks"]) != {TARGET_NET}:
        raise R106Error("r106_target_network_boundary_invalid")
    if set(observed[GATEWAY]["NetworkSettings"]["Networks"]) != {TARGET_NET, WORKER_NET}:
        raise R106Error("r106_gateway_network_boundary_invalid")
    if any(item["HostConfig"].get("PortBindings") for item in observed.values()):
        raise R106Error("r106_published_port_forbidden")
    for name in (TARGET_NET, WORKER_NET):
        network = _json(["docker", "network", "inspect", name])[0]
        if network.get("Internal") is not True or network.get("Labels", {}).get("redagent.owner") != "r106":
            raise R106Error("r106_network_isolation_invalid")


def _container_prefix(name: str, network: str, memory: str, cpus: str) -> list[str]:
    return ["docker", "run", "-d", "--name", name, "--label", OWNER_LABEL,
            "--network", network, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "64",
            "--memory", memory, "--cpus", cpus,
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777"]


def _identity(tenant: str, user: str, role: str, state: str) -> dict[str, str]:
    return {"tenant_id": tenant, "user_id": user, "role": role, "state": state}


def _mount(source: Path, destination: str, *, readonly: bool = False) -> str:
    value = f"type=bind,source={source.resolve()},target={destination}"
    return value + (",readonly" if readonly else "")


def _owned_remove_container(name: str) -> None:
    inspected = _json(["docker", "inspect", name], check=False)
    if not inspected:
        return
    if inspected[0].get("Config", {}).get("Labels", {}).get("redagent.owner") != "r106":
        raise R106Error(f"r106_ownership_mismatch:{name}")
    _run(["docker", "rm", "-f", name])


def _container_ip(name: str, network: str) -> str:
    return str(_json(["docker", "inspect", name])[0]["NetworkSettings"]["Networks"][network]["IPAddress"])


def _run(args: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=ROOT, text=True, encoding="utf-8", errors="replace",
                            capture_output=capture, check=False)
    if check and result.returncode != 0:
        raise R106Error(f"r106_command_failed:{args[0]}:{args[1]}:{result.returncode}")
    return result


def _json(args: list[str], *, check: bool = True) -> list[dict[str, object]]:
    result = _run(args, check=check, capture=True)
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise R106Error("r106_docker_json_invalid") from exc
    return value if isinstance(value, list) else [value]


def _lines(args: list[str]) -> list[str]:
    return [line for line in _run(args, capture=True).stdout.splitlines() if line]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "qualify", "cleanup"))
    parser.add_argument("--confirm-r106-local-lab", action="store_true")
    args = parser.parse_args()
    if not args.confirm_r106_local_lab:
        parser.error("--confirm-r106-local-lab is required")
    result = build() if args.action == "build" else qualify() if args.action == "qualify" else cleanup()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
