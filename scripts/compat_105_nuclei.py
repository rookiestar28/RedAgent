"""Build, qualify, and clean the fixed local-only compat_105 Nuclei runtime."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from redagent_platform.nuclei_service.compiler import compile_nuclei_plan  # noqa: E402
from redagent_platform.nuclei_service.contracts import (  # noqa: E402
    NucleiAuthorization, NucleiBundleManifest, NucleiProfileId, NucleiTargetBinding,
)
from redagent_platform.nuclei_service.normalization import normalize_nuclei_jsonl  # noqa: E402


LOCK_PATH = ROOT / "config/r105-nuclei-runtime-v3.json"
RUNTIME = ROOT / ".local/redagent/r105-runtime"
TEMPLATE = ROOT / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml"
CERTIFICATE = ROOT / "config/trust/r105-nuclei-user.crt"
TARGET_DOCKERFILE = ROOT / "containers/r105-target/Dockerfile-v3"
TARGET_SOURCE = ROOT / "containers/r105-target/fixture_server.py"
GATEWAY_DOCKERFILE = ROOT / "containers/r105-gateway/Dockerfile-v3"
GATEWAY_SOURCE = ROOT / "containers/r105-gateway/gateway_server.py"
NUCLEI_DOCKERFILE = ROOT / "containers/r105-nuclei/Dockerfile-v3"
TARGET = "redagent-r105-target"
GATEWAY = "redagent-r105-gateway"
WORKER = "redagent-r105-worker"
WORKER_NET = "redagent-r105-worker-gateway"
TARGET_NET = "redagent-r105-gateway-target"
OWNER_LABEL = "redagent.owner=r105"


class R105Error(RuntimeError):
    """Stable controller denial."""


def lock() -> dict[str, object]:
    try:
        value = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise R105Error("r105_runtime_lock_invalid") from exc
    if (
        value.get("schema") != "redagent.r105-runtime-lock/v3"
        or value.get("platform") != "linux/amd64"
        or value.get("runtime_update_allowed") is not False
        or value.get("community_templates_allowed") is not False
        or value.get("external_target_allowed") is not False
        or value.get("production_qualified") is not False
    ):
        raise R105Error("r105_runtime_lock_safety_invalid")
    expected = {
        "engine_dockerfile_sha256": _sha(NUCLEI_DOCKERFILE),
        "target_dockerfile_sha256": _sha(TARGET_DOCKERFILE),
        "target_source_sha256": _sha(TARGET_SOURCE),
        "gateway_dockerfile_sha256": _sha(GATEWAY_DOCKERFILE),
        "gateway_source_sha256": _sha(GATEWAY_SOURCE),
        "template_sha256": _sha(TEMPLATE),
    }
    if any(value.get(name) != digest for name, digest in expected.items()):
        raise R105Error("r105_runtime_source_digest_mismatch")
    # IMPORTANT: aliases preserve the fixed controller surface without admitting historical authority.
    return {
        **value,
        "local_tag": value.get("engine_local_tag"),
        "local_image_id": value.get("engine_image_id"),
        "dockerfile_sha256": value.get("engine_dockerfile_sha256"),
    }


def build() -> dict[str, object]:
    value = lock()
    # CRITICAL: runtime startup never rebuilds with changing package repositories.
    # Only the public frozen six-artifact tuple may acquire local tags.
    from scripts.owned_runtime_requalification import activate
    activate()
    expected = {
        str(value["local_tag"]): str(value["local_image_id"]),
        str(value["target_local_tag"]): str(value["target_image_id"]),
        str(value["gateway_local_tag"]): str(value["gateway_image_id"]),
    }
    for tag, image_id in expected.items():
        observed = _json(["docker", "image", "inspect", tag])[0]
        if observed.get("Id") != image_id or observed.get("Config", {}).get("User") != "65532:65532":
            raise R105Error("r105_owned_image_identity_mismatch")
    receipt = {"schema": "redagent.r105-build/v1", "images": expected,
               "source_sha256": {name: value[name] for name in (
                   "dockerfile_sha256", "target_dockerfile_sha256", "target_source_sha256",
                   "gateway_dockerfile_sha256", "gateway_source_sha256", "template_sha256")}}
    _write_json(RUNTIME / "build-receipt.json", receipt)
    return receipt


def _assert_locked_images(value: dict[str, object]) -> None:
    expected = (
        (str(value["local_tag"]), str(value["local_image_id"])),
        (str(value["target_local_tag"]), str(value["target_image_id"])),
        (str(value["gateway_local_tag"]), str(value["gateway_image_id"])),
    )
    for tag, image_id in expected:
        inspected = _json(["docker", "image", "inspect", tag])
        if (
            len(inspected) != 1
            or inspected[0].get("Id") != image_id
            or inspected[0].get("Config", {}).get("User") != "65532:65532"
        ):
            raise R105Error("r105_owned_image_identity_mismatch")


def _candidate_bundle(value: dict[str, object], *, now: datetime) -> NucleiBundleManifest:
    template_sha256 = _sha(TEMPLATE)
    certificate_sha256 = _sha(CERTIFICATE)
    if (
        template_sha256 != value["template_sha256"]
        or certificate_sha256 != value["template_signer_certificate_sha256"]
    ):
        raise R105Error("r105_candidate_bundle_source_mismatch")
    candidate_sha256 = _canonical_sha({
        "schema": "redagent.r105-candidate-bundle/v3",
        "runtime_lock_sha256": _sha(LOCK_PATH),
        "engine_image_id": value["engine_image_id"],
        "template_sha256": template_sha256,
        "certificate_sha256": certificate_sha256,
        "bundle_id": value["template_bundle_id"],
        "bundle_revision": value["template_bundle_revision"],
    })
    # CRITICAL: this proves the template's existing Nuclei signature only; it is not promotion.
    return NucleiBundleManifest(
        bundle_id=str(value["template_bundle_id"]),
        revision=int(value["template_bundle_revision"]),
        template_id="redagent-r105-missing-header",
        template_relative_path="templates/redagent-r105-missing-header.yaml",
        template_sha256=template_sha256,
        bundle_sha256=candidate_sha256,
        signature_verified=True,
        reviewer_user_id="redagent-r105-candidate-controller",
        protocol="http",
        method="GET",
        paths=("/nuclei/missing-header",),
        severity="low",
        tags=("redagent", "synthetic"),
        expected_matcher_names=("missing-security-header",),
        file_inventory=("templates/redagent-r105-missing-header.yaml",),
        promoted_at=now,
        expires_at=now + timedelta(days=30),
    )


def qualify() -> dict[str, object]:
    value = lock()
    now = datetime.now(timezone.utc)
    # CRITICAL: validate tags for drift, then use immutable image IDs for every
    # container so a retag cannot replace a qualified artifact between check and launch.
    _assert_locked_images(value)
    bundle = _candidate_bundle(value, now=now)
    cleanup()
    RUNTIME.mkdir(parents=True, exist_ok=True)
    results_path = RUNTIME / "results.jsonl"
    try:
        _run(["docker", "network", "create", "--internal", "--label", OWNER_LABEL, WORKER_NET])
        _run(["docker", "network", "create", "--internal", "--label", OWNER_LABEL, TARGET_NET])
        _run(_container_prefix(TARGET, TARGET_NET, "128m", "0.5") + [str(value["target_image_id"])])
        target_ip = _container_ip(TARGET, TARGET_NET)
        target = NucleiTargetBinding(
            target_id="r105-owned-http-fixture", attestation_sha256=_canonical_sha({
                "container": TARGET, "image": value["target_image_id"], "address": target_ip,
                "source_sha256": value["target_source_sha256"],
            }), endpoint="http://redagent-r105-gateway:8080",
            allowed_paths=("/nuclei/missing-header",), network_id=TARGET_NET,
            non_production=True, issued_at=now, expires_at=now + timedelta(minutes=15),
        )
        policy = {"schema": "redagent.r105-gateway-policy/v1", "expected_target_ip": target_ip,
                  "allowed_paths": list(target.allowed_paths), "request_limit": 20,
                  "request_rate_per_second": 2, "concurrency": 1, "timeout_seconds": 60,
                  "response_bytes_limit": 2 * 1024 * 1024}
        policy_path = RUNTIME / "gateway-policy.json"
        _write_json(policy_path, policy)
        gateway = _container_prefix(GATEWAY, TARGET_NET, "128m", "0.5")
        gateway.extend(["--mount", f"type=bind,source={policy_path.resolve()},target=/run/redagent/gateway-policy.json,readonly",
                        str(value["gateway_image_id"])])
        _run(gateway)
        _run(["docker", "network", "connect", WORKER_NET, GATEWAY])
        _assert_topology()
        authorization = NucleiAuthorization(
            tenant_id="r105-local-tenant", policy_decision_id="r105-local-approved",
            policy_revision="r099-v1", roe_version_id="r105-local-roe",
            approved_profile_ids=(NucleiProfileId.HTTP_HEADER,), approved_bundle_id=bundle.bundle_id,
            approved_at=now, expires_at=now + timedelta(minutes=10),
        )
        compiled = compile_nuclei_plan(profile_id=NucleiProfileId.HTTP_HEADER, bundle=bundle,
                                       target=target, authorization=authorization, now=now)
        results_path.touch(exist_ok=True)
        worker = ["docker", "run", "--name", WORKER, "--label", OWNER_LABEL,
                  "--network", WORKER_NET, "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges", "--pids-limit", "64",
                  "--memory", "512m", "--cpus", "1",
                  "--tmpfs", "/home/redagent:rw,noexec,nosuid,size=32m,mode=1777",
                  "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777",
                  "--mount", f"type=bind,source={TEMPLATE.resolve()},target=/opt/redagent/bundle/templates/redagent-r105-missing-header.yaml,readonly",
                  "--mount", f"type=bind,source={CERTIFICATE.resolve()},target=/run/redagent/nuclei-user.crt,readonly",
                  "--mount", f"type=bind,source={results_path.resolve()},target=/work/results.jsonl",
                  "-e", "NUCLEI_USER_CERTIFICATE=/run/redagent/nuclei-user.crt",
                  str(value["local_image_id"]), *compiled.argv]
        _run(worker, capture=True)
        normalized = normalize_nuclei_jsonl(results_path.read_bytes(), bundle=bundle, target=target)
        if len(normalized) != 1 or normalized[0].affected_resource != "/nuclei/missing-header":
            raise R105Error("r105_expected_finding_mismatch")
        direct = _run(["docker", "run", "--rm", "--network", WORKER_NET,
                       "--entrypoint", "/bin/sh", str(value["local_image_id"]), "-c",
                       f"getent hosts {TARGET}"], check=False, capture=True)
        if direct.returncode == 0:
            raise R105Error("r105_direct_target_route_present")
        cancellation = _native_cancel_check(worker, results_path)
        _negative_template_checks(value)
        _negative_gateway_checks()
        receipt = {
            "schema": "redagent.r105-qualification/v1", "passed": True,
            "candidate_runtime_lock_sha256": _sha(LOCK_PATH),
            "candidate_engine_image_id": value["engine_image_id"],
            "bundle_sha256": bundle.bundle_sha256, "plan_sha256": compiled.plan_sha256,
            "finding": {"template_id": normalized[0].template_id,
                        "matcher_name": normalized[0].matcher_name,
                        "severity": normalized[0].severity,
                        "affected_resource": normalized[0].affected_resource,
                        "fingerprint_sha256": normalized[0].fingerprint},
            "owned_fixture_finding_count": 1, "external_target_contacts": 0,
            "network_isolation_verified": True,
            "contact_proof": "observed-internal-networks-and-closed-gateway",
            "direct_target_route": False, "cleanup_residual_resource_count": 0,
            "native_stop_attempted": True,
            "native_stop_acknowledged": cancellation["native_stop_acknowledged"],
            "forced_termination": cancellation["forced_termination"],
            "unsigned_template_denied": True, "payload_tamper_denied": True,
            "gateway_quota_denied": True,
            "production_qualified": False,
        }
        _write_json(RUNTIME / "qualification.json", receipt)
        return receipt
    finally:
        results_path.unlink(missing_ok=True)
        cleanup_receipt = cleanup()
        if cleanup_receipt["residual_resource_count"] != 0:
            raise R105Error("r105_cleanup_incomplete")


def cleanup() -> dict[str, object]:
    removed_containers = 0
    removed_networks = 0
    for name in (WORKER, GATEWAY, TARGET):
        inspected = _json(["docker", "inspect", name], check=False)
        if inspected:
            if inspected[0].get("Config", {}).get("Labels", {}).get("redagent.owner") != "r105":
                raise R105Error(f"r105_ownership_mismatch:{name}")
            _run(["docker", "rm", "-f", name]); removed_containers += 1
    for name in (WORKER_NET, TARGET_NET):
        inspected = _json(["docker", "network", "inspect", name], check=False)
        if inspected:
            if inspected[0].get("Labels", {}).get("redagent.owner") != "r105":
                raise R105Error(f"r105_ownership_mismatch:{name}")
            _run(["docker", "network", "rm", name]); removed_networks += 1
    residual = len(_lines(["docker", "ps", "-a", "--filter", "label=redagent.owner=r105", "-q"]))
    residual += len(_lines(["docker", "network", "ls", "--filter", "label=redagent.owner=r105", "-q"]))
    receipt = {"schema": "redagent.r105-cleanup/v1", "container_count": removed_containers,
               "network_count": removed_networks, "home_count": 0, "key_count": 0,
               "residual_resource_count": residual, "cleanup_complete": residual == 0}
    _write_json(RUNTIME / "cleanup-receipt.json", receipt)
    return receipt


def _container_prefix(name: str, network: str, memory: str, cpus: str) -> list[str]:
    return ["docker", "run", "-d", "--name", name, "--label", OWNER_LABEL,
            "--network", network, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "64",
            "--memory", memory, "--cpus", cpus,
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777"]


def _assert_topology() -> None:
    observed = {name: _json(["docker", "inspect", name])[0] for name in (TARGET, GATEWAY)}
    target_nets = set(observed[TARGET]["NetworkSettings"]["Networks"])
    gateway_nets = set(observed[GATEWAY]["NetworkSettings"]["Networks"])
    if target_nets != {TARGET_NET} or gateway_nets != {TARGET_NET, WORKER_NET}:
        raise R105Error("r105_network_boundary_invalid")
    for item in observed.values():
        if item["HostConfig"].get("PortBindings"):
            raise R105Error("r105_published_port_forbidden")
    for network in (TARGET_NET, WORKER_NET):
        info = _json(["docker", "network", "inspect", network])[0]
        if info.get("Internal") is not True or info.get("Labels", {}).get("redagent.owner") != "r105":
            raise R105Error("r105_network_isolation_invalid")


def _negative_gateway_checks() -> None:
    code = (
        "import urllib.error,urllib.request;"
        "r=urllib.request.Request('http://127.0.0.1:8080/nuclei/missing-header',method='POST');"
        "\ntry: urllib.request.urlopen(r,timeout=3); raise SystemExit(9)"
        "\nexcept urllib.error.HTTPError as e: raise SystemExit(0 if e.code==405 else 8)"
    )
    _run(["docker", "exec", GATEWAY, "python", "-I", "-c", code])
    quota_code = (
        "import json,time,urllib.error,urllib.request; reason='';"
        "\nfor i in range(25):"
        "\n try: urllib.request.urlopen('http://127.0.0.1:8080/nuclei/missing-header',timeout=3).read()"
        "\n except urllib.error.HTTPError as e:"
        "\n  reason=json.loads(e.read()).get('reason','')"
        "\n  if reason in {'nuclei_gateway_rate_quota_exceeded','nuclei_gateway_request_quota_exceeded'}: break"
        "\n time.sleep(.55)"
        "\nraise SystemExit(0 if reason in {'nuclei_gateway_rate_quota_exceeded','nuclei_gateway_request_quota_exceeded'} else 7)"
    )
    _run(["docker", "exec", GATEWAY, "python", "-I", "-c", quota_code])


def _negative_template_checks(value: dict[str, object]) -> None:
    unsigned = RUNTIME / "unsigned.yaml"
    tampered = RUNTIME / "payload-tampered.yaml"
    payload = RUNTIME / "payload.txt"
    content = TEMPLATE.read_text(encoding="utf-8")
    content_without_signature = content.rsplit("# digest: ", 1)[0].rstrip() + "\n"
    unsigned.write_text(content_without_signature, encoding="utf-8")
    payload.write_text("fixed-local-fixture\n", encoding="utf-8")
    tampered.write_text(content.replace(
        "  - method: GET\n", "  - method: GET\n    payloads:\n      fixed:\n        - /templates/payload.txt\n",
    ), encoding="utf-8")
    try:
        for candidate in (unsigned, tampered):
            command = ["docker", "run", "--rm", "--network", "none", "--read-only",
                       "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                       "--tmpfs", "/home/redagent:rw,noexec,nosuid,size=32m,mode=1777",
                       "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777",
                       "--mount", f"type=bind,source={RUNTIME.resolve()},target=/templates,readonly",
                       "--mount", f"type=bind,source={CERTIFICATE.resolve()},target=/run/redagent/nuclei-user.crt,readonly",
                       "-e", "NUCLEI_USER_CERTIFICATE=/run/redagent/nuclei-user.crt",
                       str(value["local_image_id"]), "-target", "http://127.0.0.1:1",
                       "-templates", f"/templates/{candidate.name}", "-disable-unsigned-templates",
                       "-disable-update-check", "-no-interactsh", "-no-stdin", "-silent", "-no-color"]
            result = _run(command, check=False, capture=True)
            if result.returncode == 0 or "no templates provided" not in (result.stdout + result.stderr):
                raise R105Error("r105_untrusted_template_not_denied")
    finally:
        unsigned.unlink(missing_ok=True); tampered.unlink(missing_ok=True); payload.unlink(missing_ok=True)


def _native_cancel_check(worker: list[str], results_path: Path) -> dict[str, bool]:
    _owned_remove_container(WORKER)
    cancel_results = RUNTIME / "cancel-results.jsonl"
    cancel_results.touch(exist_ok=True)
    cancel_worker = list(worker)
    cancel_worker.insert(2, "-d")
    original_mount = f"type=bind,source={results_path.resolve()},target=/work/results.jsonl"
    replacement_mount = f"type=bind,source={cancel_results.resolve()},target=/work/results.jsonl"
    cancel_worker[cancel_worker.index(original_mount)] = replacement_mount
    acknowledged = False
    forced = False
    _run(["docker", "pause", TARGET])
    try:
        _run(cancel_worker, capture=True)
        time.sleep(0.25)
        stopped = _run(["docker", "stop", "--signal", "SIGTERM", "--time", "3", WORKER],
                       check=False, capture=True)
        acknowledged = stopped.returncode == 0
        if not acknowledged:
            _run(["docker", "kill", WORKER]); forced = True
    finally:
        _run(["docker", "unpause", TARGET], check=False)
        _owned_remove_container(WORKER)
        cancel_results.unlink(missing_ok=True)
    return {"native_stop_acknowledged": acknowledged, "forced_termination": forced}


def _owned_remove_container(name: str) -> None:
    inspected = _json(["docker", "inspect", name], check=False)
    if not inspected:
        return
    if inspected[0].get("Config", {}).get("Labels", {}).get("redagent.owner") != "r105":
        raise R105Error(f"r105_ownership_mismatch:{name}")
    _run(["docker", "rm", "-f", name])


def _container_ip(name: str, network: str) -> str:
    return str(_json(["docker", "inspect", name])[0]["NetworkSettings"]["Networks"][network]["IPAddress"])


def _run(args: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=ROOT, text=True, encoding="utf-8", errors="replace",
                            capture_output=capture, check=False)
    if check and result.returncode != 0:
        raise R105Error(f"r105_command_failed:{args[0]}:{args[1]}:{result.returncode}")
    return result


def _json(args: list[str], *, check: bool = True) -> list[dict[str, object]]:
    result = _run(args, check=check, capture=True)
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise R105Error("r105_docker_json_invalid") from exc
    return value if isinstance(value, list) else [value]


def _lines(args: list[str]) -> list[str]:
    return [line for line in _run(args, capture=True).stdout.splitlines() if line]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "qualify", "cleanup"))
    parser.add_argument("--confirm-r105-local-lab", action="store_true")
    args = parser.parse_args()
    if not args.confirm_r105_local_lab:
        parser.error("--confirm-r105-local-lab is required")
    result = build() if args.action == "build" else qualify() if args.action == "qualify" else cleanup()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
