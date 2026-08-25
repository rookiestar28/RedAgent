#!/usr/bin/env python3
"""Own and qualify the fixed, benign compat_103 disposable local lab."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config" / "lab-conformance-image.json"
DOCKERFILE = ROOT / "containers" / "lab-synthetic" / "Dockerfile"
SERVER = ROOT / "containers" / "lab-synthetic" / "fixture_server.py"
GOLDEN = ROOT / "config" / "r103-golden-findings.json"
RUNTIME = ROOT / ".local" / "redagent" / "r103-lab"
CONTAINER = "redagent-r103-lab-fixture"
NETWORK = "redagent-r103-lab"
FIXTURE_PORT = 8080


class LabError(RuntimeError):
    pass


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args], cwd=ROOT, text=True, capture_output=True,
        timeout=180, check=False,
    )
    if check and result.returncode:
        raise LabError(f"docker_command_failed:{args[0]}:{result.stderr.strip()[:240]}")
    return result


def lock() -> dict[str, object]:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def validate(*, require_derived: bool = True) -> dict[str, object]:
    value = lock()
    source = DOCKERFILE.read_text(encoding="utf-8")
    required = (
        str(value["base_linux_amd64_digest"]), "USER 65532:65532",
        'ENTRYPOINT ["python", "-I", "/app/fixture_server.py"]',
    )
    if any(item not in source for item in required):
        raise LabError("lab_dockerfile_lock_mismatch")
    image_id = value.get("derived_image_id")
    if require_derived and (
        not isinstance(image_id, str) or not image_id.startswith("sha256:") or len(image_id) != 71
    ):
        raise LabError("lab_derived_image_lock_invalid")
    return {"ok": True, "action": "validate", "network": NETWORK, "fixture_port": FIXTURE_PORT}


def build() -> dict[str, object]:
    validate(require_derived=False)
    value = lock()
    docker(
        "build", "--provenance=false", "--build-arg", "SOURCE_DATE_EPOCH=1760544000",
        "--file", str(DOCKERFILE), "--tag", str(value["local_tag"]),
        "--label", "org.opencontainers.image.source=redagent:r103-safe-lab", str(ROOT),
    )
    observed = docker("image", "inspect", str(value["local_tag"]), "--format", "{{.Id}}").stdout.strip()
    expected = value.get("derived_image_id")
    if isinstance(expected, str) and expected.startswith("sha256:") and observed != expected:
        raise LabError(f"lab_derived_image_mismatch:{observed}")
    provision = _provision(observed)
    return {"ok": True, "action": "build", "image_id": observed, **provision}


def start() -> dict[str, object]:
    validate()
    value = lock()
    image = docker("image", "inspect", str(value["local_tag"]), "--format", "{{.Id}}", check=False)
    if image.returncode != 0:
        build()
        image = docker("image", "inspect", str(value["local_tag"]), "--format", "{{.Id}}")
    observed_image = image.stdout.strip()
    if observed_image != value["derived_image_id"]:
        raise LabError("lab_start_image_mismatch")
    if not (RUNTIME / "attestation.json").is_file():
        _provision(observed_image)
    _verify_supply_chain()
    status = docker("inspect", CONTAINER, check=False)
    if status.returncode == 0:
        return inspect_lab()
    if docker("network", "inspect", NETWORK, check=False).returncode != 0:
        docker("network", "create", "--internal", "--label", "redagent.owner=r103", NETWORK)
    try:
        docker(
            "create", "--name", CONTAINER, "--network", NETWORK,
            "--label", "redagent.owner=r103",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "32", "--memory", "128m", "--cpus", "0.5",
            "--user", "65532:65532", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1m",
            str(lock()["local_tag"]),
        )
        docker("start", CONTAINER)
        for _ in range(40):
            try:
                if _fixture_get("/health/ready").get("ok") is True:
                    return inspect_lab()
            except (LabError, json.JSONDecodeError):
                time.sleep(0.25)
        raise LabError("lab_fixture_health_timeout")
    except BaseException:
        stop()
        raise


def inspect_lab() -> dict[str, object]:
    inspected = docker("inspect", CONTAINER, check=False)
    if inspected.returncode != 0:
        return {
            "ok": True, "action": "status", "container": CONTAINER, "network": NETWORK,
            "running": False, "container_absent": True,
            "network_absent": docker("network", "inspect", NETWORK, check=False).returncode != 0,
        }
    payload = json.loads(inspected.stdout)[0]
    host = payload["HostConfig"]
    config = payload["Config"]
    network = json.loads(docker("network", "inspect", NETWORK).stdout)[0]
    address = payload["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
    if (
        payload.get("Name") != f"/{CONTAINER}"
        or config.get("Labels", {}).get("redagent.owner") != "r103"
        or network.get("Internal") is not True
        or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False
        or host.get("CapDrop") != ["ALL"]
        or host.get("SecurityOpt") != ["no-new-privileges:true"]
        or host.get("PidsLimit") != 32
        or host.get("Memory") != 134_217_728
        or config.get("User") != "65532:65532"
        or host.get("PortBindings", {}).get("8080/tcp") not in (None, [])
        or not address.startswith(("172.", "10.", "192.168."))
    ):
        raise LabError("lab_runtime_security_observation_mismatch")
    return {
        "ok": True, "action": "status", "container": CONTAINER, "network": NETWORK,
        "internal_network": True, "endpoint": f"http://{address}:{FIXTURE_PORT}",
        "running": bool(payload["State"]["Running"]), "image_id": payload["Image"],
    }


def qualify() -> dict[str, object]:
    observed = start()
    routes: dict[str, object] = {}
    for route in ("/health/ready", "/api/v1/profile", "/api/v1/expected-findings", "/artifact/manifest"):
        routes[route] = _fixture_get(route)
    if routes["/artifact/manifest"]["non_production"] is not True:
        raise LabError("lab_fixture_production_marker_invalid")
    expected_manifest = json.loads(GOLDEN.read_text(encoding="utf-8"))
    if routes["/artifact/manifest"]["expected_findings_sha256"] != hashlib.sha256(_canonical(expected_manifest)).hexdigest():
        raise LabError("lab_fixture_golden_manifest_mismatch")
    return {
        **observed, "action": "qualify", "route_count": len(routes),
        "expected_finding_count": len(routes["/api/v1/expected-findings"]["findings"]),
        "response_sha256": hashlib.sha256(_canonical(routes)).hexdigest(),
    }


def stop() -> dict[str, object]:
    container = docker("inspect", CONTAINER, check=False)
    if container.returncode == 0:
        payload = json.loads(container.stdout)[0]
        if payload.get("Config", {}).get("Labels", {}).get("redagent.owner") != "r103":
            raise LabError("lab_teardown_container_ownership_mismatch")
        docker("rm", "--force", CONTAINER)
    net = docker("network", "inspect", NETWORK, check=False)
    if net.returncode == 0:
        payload = json.loads(net.stdout)[0]
        if payload.get("Labels", {}).get("redagent.owner") != "r103":
            raise LabError("lab_teardown_network_ownership_mismatch")
        if payload.get("Containers"):
            raise LabError("lab_teardown_network_not_empty")
        docker("network", "rm", NETWORK)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": "redagent.local-lab-teardown/v1", "container": CONTAINER,
        "network": NETWORK, "container_absent": docker("inspect", CONTAINER, check=False).returncode != 0,
        "network_absent": docker("network", "inspect", NETWORK, check=False).returncode != 0,
    }
    (RUNTIME / "teardown-receipt.json").write_bytes(_canonical(receipt) + b"\n")
    return {"ok": all((receipt["container_absent"], receipt["network_absent"])), "action": "stop", **receipt}


def reset() -> dict[str, object]:
    result = stop()
    if RUNTIME.exists():
        resolved = RUNTIME.resolve()
        if not resolved.is_relative_to((ROOT / ".local" / "redagent").resolve()):
            raise LabError("lab_reset_path_forbidden")
        shutil.rmtree(resolved)
    return {**result, "action": "reset", "runtime_removed": not RUNTIME.exists()}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _provision(image_id: str) -> dict[str, object]:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    sbom = {
        "schema": "redagent-r103-sbom/v1", "image_id": image_id,
        "base_manifest": lock()["base_linux_amd64_digest"],
        "files": {
            "fixture_server.py": hashlib.sha256(SERVER.read_bytes()).hexdigest(),
            "r103-golden-findings.json": hashlib.sha256(GOLDEN.read_bytes()).hexdigest(),
        },
    }
    provenance = {
        "schema": "redagent-r103-provenance/v1", "builder": "scripts/compat_103_lab.py",
        "image_id": image_id, "dockerfile_sha256": hashlib.sha256(DOCKERFILE.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(SERVER.read_bytes()).hexdigest(),
        "network_behavior": "fixed_internal_network_only",
    }
    (RUNTIME / "sbom.json").write_bytes(_canonical(sbom) + b"\n")
    (RUNTIME / "provenance.json").write_bytes(_canonical(provenance) + b"\n")
    statement = {
        "schema": "redagent-r103-attestation/v1", "image_id": image_id,
        "sbom_sha256": hashlib.sha256(_canonical(sbom)).hexdigest(),
        "provenance_sha256": hashlib.sha256(_canonical(provenance)).hexdigest(),
        "non_production": True,
    }
    (RUNTIME / "attestation.json").write_bytes(_canonical(statement) + b"\n")
    return {"sbom_sha256": statement["sbom_sha256"], "provenance_sha256": statement["provenance_sha256"]}


def _verify_supply_chain() -> None:
    try:
        sbom = json.loads((RUNTIME / "sbom.json").read_text(encoding="utf-8"))
        provenance = json.loads((RUNTIME / "provenance.json").read_text(encoding="utf-8"))
        statement = json.loads((RUNTIME / "attestation.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LabError("lab_supply_chain_attestation_missing") from exc
    if (
        statement.get("image_id") != lock()["derived_image_id"]
        or statement.get("non_production") is not True
        or statement.get("sbom_sha256") != hashlib.sha256(_canonical(sbom)).hexdigest()
        or statement.get("provenance_sha256") != hashlib.sha256(_canonical(provenance)).hexdigest()
        or sbom.get("files", {}).get("fixture_server.py") != hashlib.sha256(SERVER.read_bytes()).hexdigest()
        or sbom.get("files", {}).get("r103-golden-findings.json") != hashlib.sha256(GOLDEN.read_bytes()).hexdigest()
        or provenance.get("dockerfile_sha256") != hashlib.sha256(DOCKERFILE.read_bytes()).hexdigest()
    ):
        raise LabError("lab_supply_chain_attestation_mismatch")


def _fixture_get(route: str) -> dict[str, object]:
    if route not in {"/health/ready", "/api/v1/profile", "/api/v1/expected-findings", "/artifact/manifest"}:
        raise LabError("lab_fixture_route_forbidden")
    # IMPORTANT: keep this closed command fixed; it reaches only loopback inside the owned fixture.
    source = (
        "import json,urllib.request;"
        f"r=urllib.request.urlopen('http://127.0.0.1:{FIXTURE_PORT}{route}',timeout=2);"
        "print(json.dumps(json.load(r),sort_keys=True))"
    )
    result = docker("exec", CONTAINER, "python", "-I", "-c", source)
    return json.loads(result.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "build", "start", "status", "qualify", "stop", "reset"))
    parser.add_argument("--confirm-local-lab", action="store_true")
    args = parser.parse_args(argv)
    if not args.confirm_local_lab:
        parser.error("--confirm-local-lab is required")
    try:
        action = {
            "validate": validate, "build": build, "start": start, "status": inspect_lab,
            "qualify": qualify, "stop": stop, "reset": reset,
        }[args.action]
        print(json.dumps(action(), sort_keys=True))
        return 0
    except (LabError, OSError, json.JSONDecodeError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
