"""Assemble the six closed owned runtime artifacts from normalized public inputs."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DATE_EPOCH = 1787529600
STATE = ROOT / ".tmp/runtime-requalification-v3"
TRIVY_SHA256 = "4c532e1f28f53282dc364671e87381cd77760fa9cafab143f576449c2207cdd5"
SPECS = {
    "zap-engine": ("r104-zap", "redagent/r104-zap:2.17.0-r104.3", "r104"),
    "zap-target": ("r104-target", "redagent/r104-target:1.0.2", "r104"),
    "zap-gateway": ("r104-gateway", "redagent/r104-gateway:1.0.2", "r104"),
    "nuclei-engine": ("r105-nuclei", "redagent/r105-nuclei:3.11.1-r105.3", "r105"),
    "nuclei-target": ("r105-target", "redagent/r105-target:1.0.2", "r105"),
    "nuclei-gateway": ("r105-gateway", "redagent/r105-gateway:1.0.2", "r105"),
}


class RequalificationError(RuntimeError):
    """Stable denial for a drifted or incomplete local artifact."""


def normalized_context(paths: tuple[Path, ...]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(paths):
            # CRITICAL: normalize public bytes only; importing private history metadata
            # would violate clean-room materialization and still fail reproducibility.
            try:
                name = path.resolve().relative_to(ROOT.resolve()).as_posix()
            except ValueError as exc:
                raise RequalificationError("context_outside_public_root") from exc
            if path.is_symlink() or not path.is_file():
                raise RequalificationError("context_not_regular_public_file")
            content = path.read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            entry.mode = 0o644
            entry.mtime = SOURCE_DATE_EPOCH
            entry.uid = entry.gid = 0
            archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


def freeze_pair(first: str, second: str, expected: str, tag: str,
                run: Callable[[list[str]], object]) -> None:
    if first != second:
        raise RequalificationError("not_reproducible")
    if second != expected:
        raise RequalificationError("locked_image_mismatch")
    run(["docker", "tag", second, tag])


def validate_database(metadata: dict[str, object], now: datetime) -> None:
    updated = datetime.fromisoformat(str(metadata["UpdatedAt"]).replace("Z", "+00:00"))
    if (metadata.get("Version") != 2 or updated.tzinfo is None
            or not timedelta(0) <= now - updated <= timedelta(days=2)):
        raise RequalificationError("database_not_current")


def validate_report(report: dict[str, object], image: str) -> None:
    if report.get("Metadata", {}).get("ImageID") != image:
        raise RequalificationError("scan_image_identity_mismatch")
    if not isinstance(report.get("Results"), list) or not report["Results"]:
        raise RequalificationError("scan_result_missing")
    if any(v.get("Severity") == "CRITICAL" for result in report["Results"]
           for v in result.get("Vulnerabilities", [])):
        raise RequalificationError("critical_image_rejected")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def helper_package_inputs(manifest: dict[str, object]) -> tuple[Path, ...]:
    inputs = []
    names = set()
    for item in manifest["packages"]:
        name = item["name"]
        if name not in {"libcrypto3", "libssl3"} or item["version"] != "3.5.9-r0" or name in names:
            raise RequalificationError("helper_package_binding_invalid")
        path = ROOT / f".tmp/runtime-requalification-v3/packages/{name}-3.5.9-r0.apk"
        if (item["path"] != path.relative_to(ROOT).as_posix() or path.is_symlink()
                or not path.resolve().is_relative_to(ROOT.resolve())):
            raise RequalificationError("helper_package_path_invalid")
        # CRITICAL: exact signed package bytes are frozen before the network-none build.
        # APK also verifies its trusted upstream signature; never use allow-untrusted.
        if _file_sha256(path) != item["sha256"]:
            raise RequalificationError("helper_package_digest_mismatch")
        names.add(name)
        inputs.append(path)
    if names != {"libcrypto3", "libssl3"}:
        raise RequalificationError("helper_package_set_incomplete")
    return tuple(inputs)


def public_evidence_text(content: str) -> str:
    def redact(value):
        if isinstance(value, str):
            redacted = value.replace(str(ROOT), "<repo>").replace(ROOT.as_posix(), "<repo>")
            return redacted.replace("\\", "/") if redacted.startswith("<repo>") else redacted
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value
    # Keep one field per line for secret inspection without duplicating large SPDX indentation.
    return json.dumps(redact(json.loads(content)), indent=0, separators=(",", ":"), sort_keys=True) + "\n"


def validate_archive_report(archive_path: Path, report: dict[str, object], image: str) -> str:
    # CRITICAL: Docker's containerd image ID is a manifest digest while Trivy reports
    # its config digest. Prove the archive's manifest/config/layers chain; do not alias IDs.
    with tarfile.open(archive_path) as archive:
        def verified_blob(digest: str) -> bytes:
            member = archive.extractfile("blobs/sha256/" + digest.removeprefix("sha256:"))
            if member is None:
                raise RequalificationError("archive_blob_missing")
            data = member.read()
            if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
                raise RequalificationError("archive_blob_digest_mismatch")
            return data
        index = json.load(archive.extractfile("index.json"))
        if [entry["digest"] for entry in index["manifests"]] != [image]:
            raise RequalificationError("archive_manifest_identity_mismatch")
        manifest = json.loads(verified_blob(image))
        config_id = manifest["config"]["digest"]
        config = json.loads(verified_blob(config_id))
        for layer in manifest["layers"]:
            verified_blob(layer["digest"])
        if (config.get("architecture") != "amd64"
                or len(manifest["layers"]) != len(config["rootfs"]["diff_ids"])
                or report.get("Metadata", {}).get("DiffIDs") != config["rootfs"]["diff_ids"]):
            raise RequalificationError("scan_layer_identity_mismatch")
    validate_report(report, config_id)
    return config_id


def scan(name: str) -> dict[str, object]:
    receipt = json.loads((STATE / f"{name}-build.json").read_text(encoding="utf-8"))
    image = receipt["image_id"]
    if receipt["build_image_ids"] != [image, image]:
        raise RequalificationError("unreproduced_image")
    tool = ROOT / ".tmp/tools/trivy-0.74.0/trivy.exe"
    if _file_sha256(tool) != TRIVY_SHA256:
        raise RequalificationError("official_tool_identity_mismatch")
    cache = ROOT / ".tmp/trivy-cache-owned-v3"
    metadata = json.loads((cache / "db/metadata.json").read_text(encoding="utf-8"))
    validate_database(metadata, datetime.now(timezone.utc))
    if not (cache / "java-db/metadata.json").is_file():
        raise RequalificationError("java_database_not_provisioned")
    for key in ("TEMP", "TMP", "TMPDIR"):
        os.environ[key] = str(STATE)
    archive = ROOT / f".local/redagent/runtime-artifacts-v3/{name}.tar"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _run(["docker", "image", "save", image, "--output", str(archive)])
    # CRITICAL: supply-chain scanning reads an exact image archive; never run its entrypoint.
    # Provision both databases first, then deny external metadata/update/version contacts.
    arguments = [str(tool), "--cache-dir", str(cache), "image", "--skip-version-check",
                 "--input", str(archive), "--skip-db-update", "--skip-java-db-update",
                 "--offline-scan", "--scanners", "vuln", "--timeout", "10m"]
    sbom = STATE / f"{name}.spdx.json"
    critical = STATE / f"{name}.critical.json"
    _run([*arguments, "--format", "spdx-json", "--output", str(sbom)])
    _run([*arguments, "--format", "json", "--severity", "CRITICAL", "--exit-code", "1",
          "--output", str(critical)])
    report = json.loads(critical.read_text(encoding="utf-8"))
    config_id = validate_archive_report(archive, report, image)
    public_root = ROOT / "runtime-assets/supply-chain/owned-runtime-v3"
    public_root.mkdir(parents=True, exist_ok=True)
    for path in (sbom, critical):
        # Canonical public evidence keeps artifact identity, never a local workstation path.
        content = public_evidence_text(path.read_text(encoding="utf-8"))
        (public_root / path.name).write_text(content, encoding="utf-8")
    proof = {"schema": "redagent.owned-artifact-supply-chain/v3", "artifact": name,
             "image_id": image, "image_config_digest": config_id,
             "archive_sha256": _file_sha256(archive),
             "sbom_sha256": _file_sha256(public_root / sbom.name),
             "critical_report_sha256": _file_sha256(public_root / critical.name),
             "critical_vulnerability_count": 0, "scan_at": datetime.now(timezone.utc).isoformat(),
             "database_metadata": metadata, "scanner": "trivy-0.74.0",
             "scanner_executable_sha256": TRIVY_SHA256,
             "sbom_package_count": len(json.loads(sbom.read_text(encoding="utf-8"))["packages"])}
    (STATE / f"{name}-supply-chain.json").write_text(
        json.dumps(proof, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return proof


def _run(arguments: list[str], *, content: bytes | None = None) -> str:
    result = subprocess.run(arguments, cwd=ROOT, input=content, capture_output=True,
                            timeout=1800, check=False)
    if result.returncode:
        raise RequalificationError(
            "artifact_command_failed:" + result.stderr.decode(errors="replace")[-1800:]
        )
    return result.stdout.decode().strip()


def build(name: str) -> dict[str, object]:
    directory, tag, owner = SPECS[name]
    dockerfile = ROOT / "containers" / directory / "Dockerfile-v3"
    inputs = [dockerfile]
    if name.endswith("engine"):
        inputs.append(dockerfile.parent / "packages-v3.txt")
    else:
        inputs.append(dockerfile.parent / (
            "fixture_server.py" if name.endswith("target") else "gateway_server.py"
        ))
        inputs.append(dockerfile.parent / "packages-v3.txt")
        dependency_manifest = ROOT / "config/owned-helper-dependencies-v3.json"
        inputs.append(dependency_manifest)
        inputs.extend(helper_package_inputs(json.loads(dependency_manifest.read_text(encoding="utf-8"))))
    context = normalized_context(tuple(inputs))
    STATE.mkdir(parents=True, exist_ok=True)
    context_sha = hashlib.sha256(context).hexdigest()
    pairs = []
    for suffix in ("a", "b"):
        output = (f"type=image,name={tag}-repro-{suffix},rewrite-timestamp=true,"
                  "unpack=false,compatibility-version=20")
        arguments = ["docker", "buildx", "build", "--no-cache", "--provenance=false",
                     "--build-arg", f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}",
                     "--output", output, "--file", dockerfile.relative_to(ROOT).as_posix(),
                     "--label", f"redagent.owner={owner}"]
        if not name.endswith("engine"):
            arguments.extend(("--network", "none"))
        _run([*arguments, "-"], content=context)
        pairs.append(_run(["docker", "image", "inspect", f"{tag}-repro-{suffix}",
                           "--format", "{{.Id}}"] ))
    if pairs[0] != pairs[1]:
        raise RequalificationError(f"not_reproducible:{name}")
    receipt = {"schema": "redagent.owned-artifact-build/v3", "artifact": name,
               "image_id": pairs[1], "build_image_ids": pairs, "local_tag": tag,
               "context_sha256": context_sha, "source_date_epoch": SOURCE_DATE_EPOCH,
               "compatibility_version": "20", "runtime_qualified": False,
               "sources": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in inputs}}
    path = STATE / f"{name}-build.json"
    if path.exists():
        previous = json.loads(path.read_text(encoding="utf-8"))
        if previous != receipt:
            raise RequalificationError(f"frozen_build_receipt_drift:{name}")
    # No operational tag or authority is created before fresh supply-chain/profile proof.
    path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return receipt


def verified_artifact_tuple() -> list[tuple[dict[str, object], str, str]]:
    """Read and verify all static bindings without runtime effects or signing."""
    canonical = ROOT / "runtime-assets/supply-chain/owned-runtime-v3"
    checked = []
    for name, (_, tag, _) in SPECS.items():
        prefix, kind = name.split("-")
        item = "r104-zap" if prefix == "zap" else "r105-nuclei"
        lock = json.loads((ROOT / f"config/{item}-runtime-v3.json").read_text())
        binding = lock["owned_artifact_proofs"][kind]
        for label in ("build", "supply_chain"):
            path = ROOT / binding[f"{label}_path"]
            if (not path.resolve().is_relative_to(canonical.resolve()) or path.is_symlink()
                    or _file_sha256(path) != binding[f"{label}_sha256"]):
                raise RequalificationError("frozen_static_proof_drift")
        receipt = json.loads((ROOT / binding["build_path"]).read_text())
        proof = json.loads((ROOT / binding["supply_chain_path"]).read_text())
        expected = lock[f"{kind}_image_id"]
        if (receipt["image_id"] != expected or receipt["build_image_ids"] != [expected, expected]
                or receipt["local_tag"] != tag or lock[f"{kind}_local_tag"] != tag
                or proof["image_id"] != expected or proof["critical_vulnerability_count"] != 0):
            raise RequalificationError("locked_static_identity_mismatch")
        validate_database(proof["database_metadata"], datetime.now(timezone.utc))
        for path, digest in receipt["sources"].items():
            source = ROOT / path
            if (source.is_symlink() or not source.resolve().is_relative_to(ROOT.resolve())
                    or _file_sha256(source) != digest):
                raise RequalificationError("frozen_build_source_drift")
        for suffix, digest in (("spdx", proof["sbom_sha256"]),
                               ("critical", proof["critical_report_sha256"])):
            if _file_sha256(canonical / f"{name}.{suffix}.json") != digest:
                raise RequalificationError("frozen_static_report_drift")
        validate_report(json.loads((canonical / f"{name}.critical.json").read_text()),
                        proof["image_config_digest"])
        checked.append((receipt, expected, tag))
    return checked


def activate() -> dict[str, object]:
    """Materialize fixed local tags only after every frozen static proof passes."""
    checked = verified_artifact_tuple()
    # CRITICAL: validate the entire closed tuple before creating any operational tag.
    # A missing/stale/tampered helper proof must deny both engines, not partially activate them.
    for receipt, expected, tag in checked:
        freeze_pair(*receipt["build_image_ids"], expected, tag, _run)
    return {"schema": "redagent.owned-artifact-activation/v3",
            "images": {tag: image for _, image, tag in checked}, "signed_authority_issued": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", choices=tuple(SPECS))
    parser.add_argument("--action", choices=("build", "scan", "activate"), default="build")
    parser.add_argument("--confirm-owned-local-artifacts", action="store_true", required=True)
    args = parser.parse_args()
    result = activate() if args.action == "activate" else (build if args.action == "build" else scan)(args.artifact)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
