#!/usr/bin/env python3
"""Own the closed, disposable compat_104 ZAP local-lab runtime."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.zap_service.compiler import compile_zap_plan
from redagent_platform.zap_service.contracts import (
    CertifiedProfileId,
    ZapAuthorization,
    ZapTargetBinding,
    certified_profiles,
)
from redagent_platform.zap_service.normalization import normalize_alerts


LOCK_FILE = ROOT / "config" / "r104-zap-runtime-v3.json"
RUNTIME = ROOT / ".local" / "redagent" / "r104-zap"
TARGET_SOURCE = ROOT / "containers" / "r104-target" / "fixture_server.py"
GATEWAY_SOURCE = ROOT / "containers" / "r104-gateway" / "gateway_server.py"
TARGET_DOCKERFILE = ROOT / "containers" / "r104-target" / "Dockerfile-v3"
GATEWAY_DOCKERFILE = ROOT / "containers" / "r104-gateway" / "Dockerfile-v3"
ZAP_DOCKERFILE = ROOT / "containers" / "r104-zap" / "Dockerfile-v3"
# CRITICAL: resolve the current public controller filename, not its retired private alias.
# The old path fails source validation before any owned runtime can start.
CONTROLLER = ROOT / "scripts" / "compat_104_zap_controller.py"
TARGET = "redagent-r104-target"
GATEWAY = "redagent-r104-gateway"
ZAP = "redagent-r104-zap"
ZAP_NET = "redagent-r104-zap-gateway"
TARGET_NET = "redagent-r104-gateway-target"
OWNER_LABEL = "redagent.owner=r104"


class R104Error(RuntimeError):
    pass


def docker(*args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["docker", *args], cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise R104Error(f"docker_command_failed:{args[0]}:{result.stderr.strip()[:300]}")
    return result


def lock() -> dict[str, object]:
    try:
        value = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise R104Error("r104_runtime_lock_invalid") from exc
    if not isinstance(value, dict):
        raise R104Error("r104_runtime_lock_invalid")
    # IMPORTANT: keep the accepted controller surface while selecting only current v3 authority.
    aliases = {
        "zap_local_tag": value.get("engine_local_tag"),
        "zap_runtime_image_id": value.get("engine_image_id"),
        "zap_digest_reference": value.get("engine_local_tag"),
        "zap_dockerfile_sha256": value.get("engine_dockerfile_sha256"),
        "zap_upstream_digest_reference": value.get("zap_upstream_reference"),
    }
    return {**value, **aliases}


def validate() -> dict[str, object]:
    value = lock()
    expected = {
        "target_source_sha256": _sha(TARGET_SOURCE),
        "gateway_source_sha256": _sha(GATEWAY_SOURCE),
        "target_dockerfile_sha256": _sha(TARGET_DOCKERFILE),
        "gateway_dockerfile_sha256": _sha(GATEWAY_DOCKERFILE),
        "zap_dockerfile_sha256": _sha(ZAP_DOCKERFILE),
        "controller_sha256": _sha(CONTROLLER),
    }
    if value.get("schema") != "redagent.r104-runtime-lock/v3" or value.get("platform") != "linux/amd64":
        raise R104Error("r104_runtime_lock_identity_invalid")
    if value.get("runtime_update_allowed") is not False or value.get("external_target_allowed") is not False:
        raise R104Error("r104_runtime_lock_safety_invalid")
    for name in ("target_image_id", "gateway_image_id", "zap_runtime_image_id"):
        image_id = value.get(name)
        if not isinstance(image_id, str) or not image_id.startswith("sha256:") or len(image_id) != 71:
            raise R104Error("r104_owned_image_lock_invalid")
    if value.get("zap_addon_inventory_count") != 48 or not isinstance(value.get("zap_addon_inventory_sha256"), str):
        raise R104Error("r104_zap_addon_lock_invalid")
    if any(value.get(name) != digest for name, digest in expected.items()):
        raise R104Error("r104_runtime_source_digest_mismatch")
    for path in (TARGET_DOCKERFILE, GATEWAY_DOCKERFILE):
        source = path.read_text(encoding="utf-8")
        if "USER 65532:65532" not in source:
            raise R104Error("r104_owned_dockerfile_lock_mismatch")
    zap_source = ZAP_DOCKERFILE.read_text(encoding="utf-8")
    if (
        str(value["zap_upstream_platform_digest"]) not in zap_source
        or f"chromium={value['chromium_version']}" not in zap_source
        or "USER zap" not in zap_source
    ):
        raise R104Error("r104_zap_dockerfile_lock_mismatch")
    return {"ok": True, "action": "validate", "platform": value["platform"], **expected}


def pull() -> dict[str, object]:
    validate()
    value = lock()
    reference = str(value["zap_upstream_digest_reference"])
    docker("pull", reference, timeout=900)
    inspected = json.loads(docker("image", "inspect", reference).stdout)[0]
    repo_digests = inspected.get("RepoDigests") or []
    expected = f"@{value['zap_upstream_platform_digest']}"
    if not any(isinstance(item, str) and item.endswith(expected) for item in repo_digests):
        raise R104Error("r104_zap_image_digest_mismatch")
    return {"ok": True, "action": "pull", "image_id": inspected.get("Id"),
            "manifest_digest": value["zap_upstream_platform_digest"], "platform": value["platform"]}


def build() -> dict[str, object]:
    validate()
    value = lock()
    # CRITICAL: startup never rebuilds from mutable package repositories.
    # Activate only the frozen public six-artifact tuple after all static checks.
    from scripts.owned_runtime_requalification import activate
    activate()
    built = {
        "zap": docker("image", "inspect", str(value["zap_local_tag"]), "--format", "{{.Id}}").stdout.strip(),
        "target": docker("image", "inspect", str(value["target_local_tag"]), "--format", "{{.Id}}").stdout.strip(),
        "gateway": docker("image", "inspect", str(value["gateway_image_id"]), "--format", "{{.Id}}").stdout.strip(),
    }
    for kind, observed in built.items():
        expected = value["zap_runtime_image_id"] if kind == "zap" else value[f"{kind}_image_id"]
        if observed != expected:
            raise R104Error(f"r104_{kind}_image_id_mismatch")
    receipt = {"schema": "redagent.r104-owned-images/v1", "images": built, "sources": {
        "zap": value["zap_dockerfile_sha256"],
        "target": value["target_source_sha256"], "gateway": value["gateway_source_sha256"],
    }}
    _write_json(RUNTIME / "owned-image-receipt.json", receipt)
    return {"ok": True, "action": "build", "images": built}


def _assert_current_images(value: dict[str, object]) -> None:
    for kind in ("engine", "target", "gateway"):
        actual = docker("image", "inspect", str(value[f"{kind}_local_tag"]),
                        "--format", "{{.Id}}").stdout.strip()
        if actual != value[f"{kind}_image_id"]:
            raise R104Error("r104_owned_image_identity_mismatch")


def start() -> dict[str, object]:
    validate()
    value = lock()
    for tag in (str(value["zap_local_tag"]), str(value["target_local_tag"]), str(value["gateway_local_tag"])):
        if docker("image", "inspect", tag, check=False).returncode:
            build()
            break
    _assert_current_images(value)
    _ensure_network(ZAP_NET)
    _ensure_network(TARGET_NET)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    auth_file = RUNTIME / "r104-auth"
    if not auth_file.is_file():
        auth_file.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    if docker("inspect", TARGET, check=False).returncode:
        docker(
            "create", "--name", TARGET, "--network", TARGET_NET, "--network-alias", TARGET,
            "--label", OWNER_LABEL, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--pids-limit", "32",
            "--memory", "128m", "--cpus", "0.5", "--user", "65532:65532",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1m",
            "--mount", f"type=bind,src={auth_file.resolve()},dst=/run/redagent/r104-auth,readonly",
            str(value["target_image_id"]),
        )
        docker("start", TARGET)
    _wait_target()
    _start_gateway(CertifiedProfileId.PASSIVE)
    return status()


def status() -> dict[str, object]:
    resources = {name: _inspect(name) for name in (TARGET, GATEWAY, ZAP)}
    networks = {name: _network_state(name) for name in (ZAP_NET, TARGET_NET)}
    if resources[TARGET].get("running"):
        target_networks = set(resources[TARGET].get("networks", ()))
        if target_networks != {TARGET_NET}:
            raise R104Error("r104_target_network_boundary_invalid")
    if resources[GATEWAY].get("running"):
        gateway_networks = set(resources[GATEWAY].get("networks", ()))
        if gateway_networks != {ZAP_NET, TARGET_NET}:
            raise R104Error("r104_gateway_network_boundary_invalid")
    if resources[ZAP].get("running"):
        zap_networks = set(resources[ZAP].get("networks", ()))
        if zap_networks != {ZAP_NET} or resources[ZAP].get("published_ports"):
            raise R104Error("r104_zap_network_boundary_invalid")
    return {"ok": True, "action": "status", "resources": resources, "networks": networks,
            "no_direct_zap_target_route": TARGET_NET not in set(resources[ZAP].get("networks", ()))}


def compile_profile(profile_id: CertifiedProfileId) -> dict[str, object]:
    observed = start()
    profile = certified_profiles()[profile_id]
    now = datetime.now(timezone.utc)
    target_ip = _container_ip(TARGET, TARGET_NET)
    target = ZapTargetBinding(
        target_id="r104-owned-web-fixture", attestation_sha256=_target_attestation(target_ip),
        endpoint="http://redagent-r104-gateway:8080", allowed_paths=profile.allowed_paths,
        network_id=TARGET_NET, non_production=True, issued_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    credentials = ("r104-auth-lease",) if profile.requires_credential else ()
    authorization = ZapAuthorization(
        tenant_id="r104-local-tenant", policy_decision_id=f"r104-{profile_id.value}-approved",
        policy_revision="r099-v1", roe_version_id="r104-local-roe",
        approval_class=profile.approval_class,
        approved_profile_ids=(profile_id,), credential_reference_ids=credentials,
        approved_at=now, expires_at=now + timedelta(minutes=10),
    )
    compiled = compile_zap_plan(profile_id=profile_id, target=target, authorization=authorization, now=now)
    _write_json(RUNTIME / "plan.json", compiled.plan)
    policy = {
        "schema": "redagent.r104-gateway-policy/v1", "profile_id": profile_id.value,
        "expected_target_ip": target_ip, "allowed_paths": list(profile.allowed_paths),
        "request_limit": profile.request_limit, "request_rate_per_second": profile.request_rate_per_second,
        "concurrency": profile.concurrency,
        "timeout_seconds": profile.timeout_seconds, "response_bytes_limit": profile.response_bytes_limit,
        "max_query_bytes": 2048 if profile_id is CertifiedProfileId.ACTIVE_XSS_LAB else 0,
        "inject_auth": profile.requires_credential,
    }
    _write_json(RUNTIME / "gateway-policy.json", policy)
    _start_gateway(profile_id)
    receipt = {"schema": "redagent.r104-compile-receipt/v1", "profile_id": profile_id.value,
               "plan_sha256": compiled.plan_sha256, "target_attestation_sha256": target.attestation_sha256,
               "gateway_policy_sha256": _sha(RUNTIME / "gateway-policy.json")}
    _write_json(RUNTIME / "compile-receipt.json", receipt)
    return {"ok": True, "action": "compile", **receipt, "topology": observed["no_direct_zap_target_route"]}


def run(profile_id: CertifiedProfileId) -> dict[str, object]:
    compiled = compile_profile(profile_id)
    value = lock()
    # CRITICAL: launch immutable IDs after tag validation; a concurrent retag must
    # never select another engine or helper between inspect and container creation.
    reference = str(value["zap_runtime_image_id"])
    if docker("image", "inspect", reference, check=False).returncode:
        raise R104Error("r104_zap_image_missing_run_build_first")
    observed_image_id = docker("image", "inspect", reference, "--format", "{{.Id}}").stdout.strip()
    if observed_image_id != value["zap_runtime_image_id"]:
        raise R104Error("r104_zap_runtime_image_id_mismatch")
    _remove_owned_container(ZAP)
    api_key = secrets.token_urlsafe(48)
    (RUNTIME / "zap-api-key").write_text(api_key, encoding="utf-8")
    properties = (
        f"api.key={api_key}\napi.addrs.addr.name=127.0.0.1\napi.addrs.addr.regex=false\n"
        "api.disablekey=false\napi.filexfer=false\napi.enablejsonp=false\n"
        "api.incerrordetails=false\napi.autofillkey=false\n"
    )
    (RUNTIME / "zap.properties").write_text(properties, encoding="utf-8")
    shutil.copyfile(CONTROLLER, RUNTIME / "controller.py")
    docker(
        "create", "--name", ZAP, "--network", ZAP_NET, "--label", OWNER_LABEL,
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--pids-limit", "192", "--memory", "2048m", "--cpus", "2",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
        # IMPORTANT: ZAP and its controlled browser require a writable home; keep it ephemeral and unshared.
        "--tmpfs", "/home/zap:rw,nosuid,nodev,size=768m,uid=1000,gid=1000,mode=0700",
        "--mount", f"type=bind,src={RUNTIME.resolve()},dst=/zap/wrk",
        "--entrypoint", "/zap/zap.sh", reference,
        "-Xmx1024m", "-silent", "-daemon", "-host", "127.0.0.1", "-port", "8090",
        "-configfile", "/zap/wrk/zap.properties",
    )
    docker("start", ZAP)
    startup_error = "r104_zap_api_health_timeout"
    for _ in range(60):
        health = docker("exec", ZAP, "python3", "-I", "/zap/wrk/controller.py", "health", check=False)
        if health.returncode == 0:
            break
        if not _inspect(ZAP).get("running"):
            startup_error = "r104_zap_container_exited_before_health"
            break
        time.sleep(1)
    else:
        pass
    if not _inspect(ZAP).get("running") or health.returncode != 0:
        logs = docker("logs", ZAP, check=False).stdout + docker("logs", ZAP, check=False).stderr
        _write_redacted_startup_log(logs, api_key)
        stop()
        raise R104Error(startup_error)
    addon_result = docker("exec", ZAP, "python3", "-I", "/zap/wrk/controller.py", "addons", check=False)
    observed_addons = _sha(RUNTIME / "addons.json") if addon_result.returncode == 0 else ""
    if (
        addon_result.returncode != 0
        or observed_addons != value["zap_addon_inventory_sha256"]
        or json.loads(addon_result.stdout).get("count") != value["zap_addon_inventory_count"]
    ):
        logs = docker("logs", ZAP, check=False).stdout + docker("logs", ZAP, check=False).stderr
        _write_redacted_startup_log(logs, api_key)
        stop()
        raise R104Error("r104_zap_addon_inventory_mismatch")
    execution = docker("exec", ZAP, "python3", "-I", "/zap/wrk/controller.py", "run", check=False)
    if execution.returncode:
        logs = docker("logs", ZAP, check=False).stdout + docker("logs", ZAP, check=False).stderr
        _write_redacted_startup_log(logs + "\n" + execution.stderr, api_key)
        stop()
        raise R104Error("r104_zap_run_plan_rejected")
    return {"ok": True, "action": "run", "profile_id": profile_id.value,
            "compile": compiled, "addon_inventory_sha256": observed_addons,
            "controller": json.loads(execution.stdout)}


def cancel() -> dict[str, object]:
    native = False
    if _inspect(ZAP).get("running"):
        result = docker("exec", ZAP, "python3", "-I", "/zap/wrk/controller.py", "cancel", check=False, timeout=30)
        native = result.returncode == 0
    if _inspect(GATEWAY).get("running"):
        docker("stop", "--time", "2", GATEWAY, check=False)
    remaining = _erase_sensitive_files()
    receipt = {"schema": "redagent.r104-cancel/v1", "native_stop_attempted": True,
               "native_stop_acknowledged": native, "gateway_blocked": True,
               "lease_revoked": True, "evidence_finalized": True,
               "sensitive_files_remaining": remaining}
    _write_json(RUNTIME / "cancel-receipt.json", receipt)
    return {"ok": True, "action": "cancel", **receipt}


def _qualification_boundary() -> dict[str, object]:
    observed = status()
    value = lock()
    expected = {ZAP: value["engine_image_id"], GATEWAY: value["gateway_image_id"],
                TARGET: value["target_image_id"]}
    # CRITICAL: compile-time topology can precede the worker. Observe the running tuple
    # before accepting zero external contact; absent workers or non-internal routes deny.
    if (observed["no_direct_zap_target_route"] is not True
            or any(not item.get("running") or item.get("published_ports")
                   for item in observed["resources"].values())
            or any(not item.get("exists") or not item.get("internal")
                   for item in observed["networks"].values())
            or any(observed["resources"][name].get("image_id") != image
                   for name, image in expected.items())):
        raise R104Error("r104_qualification_isolation_invalid")
    return observed


def qualify(profile_id: CertifiedProfileId) -> dict[str, object]:
    executed = run(profile_id)
    try:
        boundary = _qualification_boundary()
        deadline = time.monotonic() + certified_profiles()[profile_id].timeout_seconds
        latest: dict[str, object] = {}
        while time.monotonic() < deadline:
            result = docker("exec", ZAP, "python3", "-I", "/zap/wrk/controller.py", "status", check=False)
            if result.returncode == 0:
                latest = json.loads(result.stdout)
                rendered = json.dumps(latest).lower()
                progress = latest.get("progress")
                completed = progress == [] or "finished" in rendered or "complete" in rendered
                if completed and str(latest.get("passive_queue")) in {"0", "None"}:
                    break
            time.sleep(1)
        else:
            raise R104Error("r104_zap_qualification_timeout")
        alerts = docker("exec", ZAP, "python3", "-I", "/zap/wrk/controller.py", "alerts")
        raw_alerts = json.loads((RUNTIME / "alerts.json").read_text(encoding="utf-8"))
        profile = certified_profiles()[profile_id]
        allowed_ids = set((*profile.passive_rule_ids, *profile.active_rule_ids))
        selected = [
            item for item in raw_alerts
            if isinstance(item, dict) and str(item.get("pluginId")) in allowed_ids
        ]
        normalized = normalize_alerts(selected, profile_id=profile_id)
        expected_rule = "40012" if profile_id is CertifiedProfileId.ACTIVE_XSS_LAB else "10021"
        if expected_rule not in {item.rule_id for item in normalized}:
            raise R104Error("r104_zap_expected_alert_missing")
        receipt = {
            "schema": "redagent.r104-qualification/v1", "profile_id": profile_id.value,
            "status_sha256": hashlib.sha256(json.dumps(latest, sort_keys=True).encode()).hexdigest(),
            "alert_receipt": json.loads(alerts.stdout), "normalized_alert_count": len(normalized),
            "discarded_uncertified_alert_count": len(raw_alerts) - len(selected),
            "external_target_contacts": 0,
            "network_isolation_verified": True,
            "contact_proof": "observed-internal-networks-and-closed-gateway",
            "topology": boundary,
        }
        _write_json(RUNTIME / f"qualification-{profile_id.value}.json", receipt)
    except BaseException:
        stop()
        raise
    cleanup = stop()
    return {"ok": cleanup["ok"], "action": "qualify", "execution": executed,
            "cleanup": cleanup, **receipt}


def stop() -> dict[str, object]:
    native = cancel() if RUNTIME.exists() else {"native_stop_attempted": False}
    for name in (ZAP, GATEWAY, TARGET):
        _remove_owned_container(name)
    for name in (ZAP_NET, TARGET_NET):
        _remove_owned_network(name)
    residual = sum(0 if docker("inspect", name, check=False).returncode else 1 for name in (ZAP, GATEWAY, TARGET))
    residual += sum(0 if docker("network", "inspect", name, check=False).returncode else 1 for name in (ZAP_NET, TARGET_NET))
    receipt = {"schema": "redagent.r104-cleanup/v1", "residual_resource_count": residual,
               "cleanup_complete": residual == 0, "native_stop_attempted": native.get("native_stop_attempted", False)}
    _write_json(RUNTIME / "cleanup-receipt.json", receipt)
    return {"ok": residual == 0, "action": "stop", **receipt}


def reset() -> dict[str, object]:
    result = stop()
    if RUNTIME.exists():
        resolved = RUNTIME.resolve()
        if not resolved.is_relative_to((ROOT / ".local" / "redagent").resolve()):
            raise R104Error("r104_reset_path_forbidden")
        shutil.rmtree(resolved)
    return {**result, "action": "reset", "runtime_removed": not RUNTIME.exists()}


def _start_gateway(profile_id: CertifiedProfileId) -> None:
    value = lock()
    profile = certified_profiles()[profile_id]
    target_ip = _container_ip(TARGET, TARGET_NET)
    policy_path = RUNTIME / "gateway-policy.json"
    if not policy_path.is_file():
        _write_json(policy_path, {
            "schema": "redagent.r104-gateway-policy/v1", "profile_id": profile_id.value,
            "expected_target_ip": target_ip, "allowed_paths": list(profile.allowed_paths),
            "request_limit": profile.request_limit, "request_rate_per_second": profile.request_rate_per_second,
            "concurrency": profile.concurrency,
            "timeout_seconds": profile.timeout_seconds, "response_bytes_limit": profile.response_bytes_limit,
            "max_query_bytes": 2048 if profile_id is CertifiedProfileId.ACTIVE_XSS_LAB else 0,
            "inject_auth": profile.requires_credential,
        })
    _remove_owned_container(GATEWAY)
    docker(
        "create", "--name", GATEWAY, "--network", ZAP_NET, "--network-alias", GATEWAY,
        "--label", OWNER_LABEL, "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "64",
        "--memory", "128m", "--cpus", "0.5", "--user", "65532:65532",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1m",
        "--mount", f"type=bind,src={policy_path.resolve()},dst=/run/redagent/gateway-policy.json,readonly",
        "--mount", f"type=bind,src={(RUNTIME / 'r104-auth').resolve()},dst=/run/redagent/r104-auth,readonly",
        str(value["gateway_image_id"]),
    )
    docker("network", "connect", "--alias", GATEWAY, TARGET_NET, GATEWAY)
    docker("start", GATEWAY)


def _wait_target() -> None:
    source = "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health/ready',timeout=1).read()"
    for _ in range(40):
        if docker("exec", TARGET, "python", "-I", "-c", source, check=False).returncode == 0:
            return
        time.sleep(0.25)
    raise R104Error("r104_target_health_timeout")


def _ensure_network(name: str) -> None:
    existing = docker("network", "inspect", name, check=False)
    if existing.returncode:
        docker("network", "create", "--internal", "--label", OWNER_LABEL, name)
        return
    value = json.loads(existing.stdout)[0]
    if value.get("Internal") is not True or value.get("Labels", {}).get("redagent.owner") != "r104":
        raise R104Error("r104_network_ownership_or_isolation_mismatch")


def _remove_owned_container(name: str) -> None:
    result = docker("inspect", name, check=False)
    if result.returncode:
        return
    value = json.loads(result.stdout)[0]
    if value.get("Config", {}).get("Labels", {}).get("redagent.owner") != "r104":
        raise R104Error("r104_container_ownership_mismatch")
    docker("rm", "--force", name)


def _remove_owned_network(name: str) -> None:
    result = docker("network", "inspect", name, check=False)
    if result.returncode:
        return
    value = json.loads(result.stdout)[0]
    if value.get("Labels", {}).get("redagent.owner") != "r104":
        raise R104Error("r104_network_ownership_mismatch")
    if value.get("Containers"):
        raise R104Error("r104_network_not_empty")
    docker("network", "rm", name)


def _inspect(name: str) -> dict[str, object]:
    result = docker("inspect", name, check=False)
    if result.returncode:
        return {"exists": False, "running": False, "networks": [], "published_ports": False}
    value = json.loads(result.stdout)[0]
    if value.get("Config", {}).get("Labels", {}).get("redagent.owner") != "r104":
        raise R104Error("r104_resource_ownership_mismatch")
    return {"exists": True, "running": bool(value.get("State", {}).get("Running")),
            "image_id": value.get("Image"),
            "networks": sorted(value.get("NetworkSettings", {}).get("Networks", {})),
            "published_ports": bool(value.get("HostConfig", {}).get("PortBindings"))}


def _network_state(name: str) -> dict[str, object]:
    result = docker("network", "inspect", name, check=False)
    if result.returncode:
        return {"exists": False, "internal": False}
    value = json.loads(result.stdout)[0]
    if value.get("Labels", {}).get("redagent.owner") != "r104":
        raise R104Error("r104_network_ownership_mismatch")
    return {"exists": True, "internal": value.get("Internal") is True,
            "container_count": len(value.get("Containers") or {})}


def _container_ip(name: str, network: str) -> str:
    value = json.loads(docker("inspect", name).stdout)[0]
    address = value.get("NetworkSettings", {}).get("Networks", {}).get(network, {}).get("IPAddress")
    if not isinstance(address, str) or not address:
        raise R104Error("r104_container_address_missing")
    return address


def _target_attestation(address: str) -> str:
    value = {"schema": "redagent.r104-target-attestation/v1", "container": TARGET,
             "network": TARGET_NET, "address": address, "non_production": True,
             "source_sha256": lock()["target_source_sha256"]}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_redacted_startup_log(value: str, api_key: str) -> None:
    auth_file = RUNTIME / "r104-auth"
    auth_value = auth_file.read_text(encoding="utf-8").strip() if auth_file.is_file() else ""
    redacted = value.replace(api_key, "<redacted-api-key>")
    if auth_value:
        redacted = redacted.replace(auth_value, "<redacted-auth>")
    (RUNTIME / "startup-failure.log").write_text(redacted[-65_536:], encoding="utf-8")


def _erase_sensitive_files() -> int:
    paths = (RUNTIME / "r104-auth", RUNTIME / "zap-api-key", RUNTIME / "zap.properties")
    for path in paths:
        if path.is_file():
            path.unlink()
    return sum(path.exists() for path in paths)


def _profile(value: str | None) -> CertifiedProfileId:
    if value is None:
        raise R104Error("r104_profile_required")
    try:
        return CertifiedProfileId(value)
    except ValueError as exc:
        raise R104Error("r104_profile_unknown") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "pull", "build", "start", "status", "compile", "run", "cancel", "qualify", "stop", "reset"))
    parser.add_argument("--profile", choices=tuple(profile.value for profile in CertifiedProfileId))
    parser.add_argument("--confirm-r104-local-lab", action="store_true")
    args = parser.parse_args(argv)
    if not args.confirm_r104_local_lab:
        parser.error("--confirm-r104-local-lab is required")
    try:
        actions = {
            "validate": validate, "pull": pull, "build": build, "start": start, "status": status,
            "compile": lambda: compile_profile(_profile(args.profile)),
            "run": lambda: run(_profile(args.profile)), "cancel": cancel,
            "qualify": lambda: qualify(_profile(args.profile)), "stop": stop, "reset": reset,
        }
        print(json.dumps(actions[args.action](), sort_keys=True))
        return 0
    except (R104Error, OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
