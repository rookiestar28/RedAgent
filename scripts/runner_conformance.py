#!/usr/bin/env python3
"""Build, attest, run, inspect, and clean the fixed benign compat_100 runner image."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config" / "runner-conformance-image.json"
DOCKERFILE = ROOT / "containers" / "runner-synthetic" / "Dockerfile"
ENTRYPOINT = ROOT / "containers" / "runner-synthetic" / "synthetic_entry.py"
RUNTIME = ROOT / ".local" / "redagent" / "runner"
CONTAINER = "redagent-r100-synthetic"


class ConformanceError(RuntimeError):
    pass


def _lock() -> dict[str, object]:
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def _docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["docker", *arguments], cwd=ROOT, text=True, capture_output=True, timeout=120, check=False,
    )
    if check and completed.returncode != 0:
        raise ConformanceError(f"docker_command_failed:{arguments[0]}:{completed.stderr.strip()[:200]}")
    return completed


def validate() -> dict[str, object]:
    lock = _lock()
    for name in ("base_index_digest", "base_linux_amd64_digest", "derived_image_id"):
        value = lock.get(name)
        if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
            raise ConformanceError(f"runner_image_lock_{name}_invalid")
    if lock.get("source_date_epoch") != 1760544000:
        raise ConformanceError("runner_image_lock_source_date_epoch_invalid")
    if lock.get("buildkit_compatibility_version") != "20":
        raise ConformanceError("runner_image_lock_buildkit_compatibility_invalid")
    source = DOCKERFILE.read_text(encoding="utf-8")
    if str(lock["base_linux_amd64_digest"]) not in source or "USER 65532:65532" not in source:
        raise ConformanceError("runner_dockerfile_lock_mismatch")
    return {"ok": True, "action": "validate"}


def build() -> dict[str, object]:
    validate()
    lock = _lock()
    source_date_epoch = int(lock["source_date_epoch"])
    compatibility_version = str(lock["buildkit_compatibility_version"])
    output = ",".join((
        "type=image",
        f"name={lock['local_tag']}",
        "rewrite-timestamp=true",
        "unpack=false",
        f"compatibility-version={compatibility_version}",
    ))
    # CRITICAL: ordinary `docker build` preserves checkout mtimes in COPY
    # layers, so a tracked image ID drifts across otherwise identical builds.
    _docker(
        "buildx", "build", "--no-cache", "--network", "none", "--provenance=false",
        "--build-arg", f"SOURCE_DATE_EPOCH={source_date_epoch}", "--output", output,
        "--file", str(DOCKERFILE),
        "--label", "org.opencontainers.image.source=redagent:r100-synthetic", str(ROOT),
    )
    observed = _docker("image", "inspect", str(lock["local_tag"]), "--format", "{{.Id}}").stdout.strip()
    if observed != lock["derived_image_id"]:
        raise ConformanceError(f"runner_derived_image_mismatch:{observed}")
    return {"ok": True, "action": "build", "image_id": observed}


def provision() -> dict[str, object]:
    lock = _lock()
    observed = _docker("image", "inspect", str(lock["local_tag"]), "--format", "{{.Id}}").stdout.strip()
    if observed != lock["derived_image_id"]:
        raise ConformanceError("runner_provision_image_mismatch")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_path = RUNTIME / "attestation-private.pem"
    public_path = RUNTIME / "attestation-public.pem"
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    sbom = {
        "schema": "redagent-runner-sbom/v1", "image_id": observed,
        "base_manifest": lock["base_linux_amd64_digest"],
        "files": {"synthetic_entry.py": _sha256(ENTRYPOINT.read_bytes())},
    }
    provenance = {
        "schema": "redagent-runner-provenance/v1", "builder": "scripts/runner_conformance.py",
        "image_id": observed, "dockerfile_sha256": _sha256(DOCKERFILE.read_bytes()),
        "source_entry_sha256": _sha256(ENTRYPOINT.read_bytes()), "network_behavior": "none",
    }
    _write_json(RUNTIME / "sbom.json", sbom)
    _write_json(RUNTIME / "provenance.json", provenance)
    statement = {
        "schema": "redagent-runner-attestation/v1", "image_id": observed,
        "sbom_sha256": _sha256(_canonical(sbom)),
        "provenance_sha256": _sha256(_canonical(provenance)),
        "signer_identity": "redagent-r100-local-conformance",
    }
    signature = key.sign(_canonical(statement))
    attestation = {"statement": statement, "signature": base64.b64encode(signature).decode("ascii")}
    _write_json(RUNTIME / "attestation.json", attestation)
    return {"ok": True, "action": "provision", "image_id": observed}


def verify(attestation: dict[str, object] | None = None) -> dict[str, object]:
    payload = attestation or json.loads((RUNTIME / "attestation.json").read_text(encoding="utf-8"))
    statement = payload.get("statement")
    signature = payload.get("signature")
    if not isinstance(statement, dict) or not isinstance(signature, str):
        raise ConformanceError("runner_attestation_schema_invalid")
    if statement.get("image_id") != _lock()["derived_image_id"]:
        raise ConformanceError("runner_attestation_image_mismatch")
    sbom = json.loads((RUNTIME / "sbom.json").read_text(encoding="utf-8"))
    provenance = json.loads((RUNTIME / "provenance.json").read_text(encoding="utf-8"))
    if statement.get("sbom_sha256") != _sha256(_canonical(sbom)):
        raise ConformanceError("runner_attestation_sbom_mismatch")
    if statement.get("provenance_sha256") != _sha256(_canonical(provenance)):
        raise ConformanceError("runner_attestation_provenance_mismatch")
    public = serialization.load_pem_public_key((RUNTIME / "attestation-public.pem").read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        raise ConformanceError("runner_attestation_key_invalid")
    try:
        public.verify(base64.b64decode(signature), _canonical(statement))
    except (InvalidSignature, ValueError) as exc:
        raise ConformanceError("runner_attestation_signature_invalid") from exc
    return {"ok": True, "action": "verify", "signature_verified": True}


def tamper_rejected() -> bool:
    payload = json.loads((RUNTIME / "attestation.json").read_text(encoding="utf-8"))
    payload["statement"]["image_id"] = "sha256:" + "f" * 64
    try:
        verify(payload)
    except ConformanceError:
        return True
    return False


def run() -> dict[str, object]:
    verify()
    stop()
    tag = str(_lock()["local_tag"])
    _docker(
        "create", "--name", CONTAINER,
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "32",
        "--memory", "128m", "--cpus", "0.5", "--user", "65532:65532",
        "--runtime", "runc", "--tmpfs", "/work:rw,noexec,nosuid,nodev,size=1m", tag,
    )
    observed = inspect()
    output = _docker("start", "--attach", CONTAINER).stdout.strip().splitlines()
    if not output:
        raise ConformanceError("runner_synthetic_output_missing")
    synthetic = json.loads(output[-1])
    state = json.loads(_docker("inspect", CONTAINER).stdout)[0]["State"]
    if state.get("ExitCode") != 0:
        raise ConformanceError("runner_synthetic_exit_nonzero")
    stop()
    removed = _docker("inspect", CONTAINER, check=False).returncode != 0
    return {**observed, "synthetic_output": synthetic, "container_removed": removed}


def inspect() -> dict[str, object]:
    payload = json.loads(_docker("inspect", CONTAINER).stdout)[0]
    host = payload["HostConfig"]
    config = payload["Config"]
    expected = {
        "runtime": "runc-local-conformance", "network_mode": host["NetworkMode"],
        "read_only_root": bool(host["ReadonlyRootfs"]), "privileged": bool(host["Privileged"]),
        "cap_drop": host.get("CapDrop") or [], "user": config["User"],
        "pids_limit": host["PidsLimit"], "memory_bytes": host["Memory"],
    }
    if expected != {
        "runtime": "runc-local-conformance", "network_mode": "none", "read_only_root": True,
        "privileged": False, "cap_drop": ["ALL"], "user": "65532:65532",
        "pids_limit": 32, "memory_bytes": 134_217_728,
    }:
        raise ConformanceError("runner_container_observation_mismatch")
    if host.get("Runtime") != "runc" or host.get("SecurityOpt") != ["no-new-privileges:true"]:
        raise ConformanceError("runner_container_security_option_mismatch")
    if host.get("Tmpfs") != {"/work": "rw,noexec,nosuid,nodev,size=1m"}:
        raise ConformanceError("runner_container_tmpfs_mismatch")
    return expected


def stop() -> dict[str, object]:
    _docker("rm", "--force", CONTAINER, check=False)
    return {"ok": True, "action": "stop"}


def reset() -> dict[str, object]:
    stop()
    if RUNTIME.exists() and RUNTIME.resolve().is_relative_to((ROOT / ".local").resolve()):
        shutil.rmtree(RUNTIME)
    return {"ok": True, "action": "reset"}


def conformance() -> dict[str, object]:
    stop()
    build()
    provision()
    verified = verify()
    tampered = tamper_rejected()
    observed = run()
    return {"ok": True, "signature_verified": verified["signature_verified"], "tamper_rejected": tampered, **observed}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    try:
        if values == ["conformance"]:
            result = conformance()
        else:
            parser = argparse.ArgumentParser(description=__doc__)
            parser.add_argument("action", choices=("validate", "build", "provision", "run", "inspect", "stop", "reset"))
            action = parser.parse_args(values).action
            result = {
                "validate": validate, "build": build, "provision": provision, "run": run,
                "inspect": inspect, "stop": stop, "reset": reset,
            }[action]()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ConformanceError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
