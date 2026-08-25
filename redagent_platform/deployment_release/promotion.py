"""Verify the signed, fixture-only compat_116 deployment release promotion."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import gzip
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True, kw_only=True)
class DeploymentReleasePromotionReceipt:
    manifest_sha256: str
    runtime_lock_sha256: str
    source_tree_sha256: str
    scenario_sha256: str
    profile_count: int
    bundled_image_count: int
    signature_verified: bool
    production_qualified: bool


def verify_deployment_release_promotion(
    workspace: Path,
    *,
    now: datetime,
) -> DeploymentReleasePromotionReceipt:
    planning = workspace / "runtime-assets" / "attestations"
    manifest_path = planning / "260712-R116_DEPLOYMENT_RELEASE_PROMOTION.json"
    signature_path = planning / "260712-R116_DEPLOYMENT_RELEASE_PROMOTION.signature.json"
    public_path = planning / "260712-R116_DEPLOYMENT_RELEASE_PROMOTION.pub"
    qualification_path = planning / "260712-R116_DEPLOYMENT_RELEASE_QUALIFICATION.json"
    lock_path = workspace / "config" / "r116-deployment-release-runtime.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature = json.loads(signature_path.read_text(encoding="utf-8"))
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        public_bytes = public_path.read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("deployment_release_promotion_input_invalid") from exc
    qualification_assertion = dict(qualification)
    qualification_assertion.pop("ok", None)
    asserted_sha = qualification_assertion.pop("receipt_sha256", None)
    computed_assertion_sha = _digest(qualification_assertion)
    lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    qualification_sha = hashlib.sha256(qualification_path.read_bytes()).hexdigest()
    bundled_images = lock.get("bundled_images")
    false_fields = (
        "production_qualified",
        "real_environment_qualified",
        "network_enabled",
        "external_execution_enabled",
        "registry_fallback_enabled",
        "automatic_apply_enabled",
        "destructive_restore_enabled",
        "destructive_downgrade_enabled",
    )
    if (
        manifest.get("schema") != "redagent.r116-promotion/v1"
        or manifest.get("runtime_lock_sha256") != lock_sha
        or manifest.get("qualification_receipt_sha256") != qualification_sha
        or manifest.get("source_tree_sha256") != lock.get("source_tree_sha256")
        or lock.get("qualification_assertion_sha256") != asserted_sha
        or asserted_sha != computed_assertion_sha
        or qualification.get("status") != "passed"
        or qualification.get("adversarial_case_count") != qualification.get("denied_case_count")
        or qualification.get("drill_case_count") != qualification.get("passed_drill_count")
        or qualification.get("qualification_case_count") != (
            qualification.get("adversarial_case_count", 0) + qualification.get("drill_case_count", 0)
        )
        or any(qualification.get(field) != 0 for field in ("network_contact_count", "external_execution_count", "real_cluster_contact_count"))
        or lock.get("enabled_profiles") != ["single_node", "kubernetes_enterprise"]
        or lock.get("qualification_level") != "structurally_conformant"
        or not isinstance(bundled_images, list)
        or len(bundled_images) != 1
        or not isinstance(bundled_images[0], dict)
        or any(lock.get(field) is not False for field in false_fields)
        or any(manifest.get(field) is not False for field in false_fields)
        or manifest.get("author") == manifest.get("reviewer")
    ):
        raise ValueError("deployment_release_promotion_safety_invalid")
    profile_hashes = lock.get("profile_sha256s")
    source_hashes = lock.get("source_sha256s")
    if (
        not isinstance(profile_hashes, list)
        or len(profile_hashes) != 2
        or not all(isinstance(item, dict) for item in profile_hashes)
        or not isinstance(source_hashes, list)
        or not all(isinstance(item, dict) for item in source_hashes)
    ):
        raise ValueError("deployment_release_promotion_evidence_invalid")
    profiles: list[dict[str, object]] = []
    for descriptor in profile_hashes:
        path = _workspace_file(workspace, f"deploy/profiles/{descriptor.get('path', '')}")
        try:
            content = path.read_bytes()
            profiles.append(json.loads(content))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("deployment_release_promotion_evidence_invalid") from exc
        if descriptor.get("sha256") != hashlib.sha256(content).hexdigest():
            raise ValueError("deployment_release_promotion_evidence_invalid")
    observed_sources: list[dict[str, str]] = []
    for descriptor in source_hashes:
        relative = descriptor.get("path")
        path = _workspace_file(workspace, relative)
        try:
            digest = _verified_source_sha256(workspace, str(relative), path, str(descriptor.get("sha256")))
        except OSError as exc:
            raise ValueError("deployment_release_promotion_evidence_invalid") from exc
        if descriptor.get("sha256") != digest:
            raise ValueError("deployment_release_promotion_evidence_invalid")
        observed_sources.append({"path": str(relative), "sha256": digest})
    if _digest(observed_sources) != lock.get("source_tree_sha256"):
        raise ValueError("deployment_release_promotion_evidence_invalid")
    image = bundled_images[0]
    sbom_path = _workspace_file(workspace, image.get("sbom_path"))
    try:
        sbom_bytes = sbom_path.read_bytes()
        sbom = json.loads(gzip.decompress(sbom_bytes))
    except (OSError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
        raise ValueError("deployment_release_promotion_sbom_invalid") from exc
    if (
        image.get("components") != ["api", "worker"]
        or not str(image.get("reference", "")).startswith("redagent/r116-app@sha256:")
        or image.get("sbom_sha256") != hashlib.sha256(sbom_bytes).hexdigest()
        or sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("name") != "redagent/r116-app"
        or not sbom.get("packages")
    ):
        raise ValueError("deployment_release_promotion_sbom_invalid")
    cyclonedx_path = _workspace_file(workspace, image.get("cyclonedx_sbom_path"))
    try:
        cyclonedx_bytes = cyclonedx_path.read_bytes()
        cyclonedx = json.loads(gzip.decompress(cyclonedx_bytes))
    except (OSError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
        raise ValueError("deployment_release_promotion_sbom_invalid") from exc
    if (
        image.get("cyclonedx_sbom_sha256") != hashlib.sha256(cyclonedx_bytes).hexdigest()
        or cyclonedx.get("bomFormat") != "CycloneDX"
        or not cyclonedx.get("specVersion")
        or not cyclonedx.get("components")
    ):
        raise ValueError("deployment_release_promotion_sbom_invalid")
    profile_images = {
        component.get("image")
        for profile in profiles
        for component in profile.get("components", [])
        if component.get("deployment_mode") == "bundled"
    }
    if profile_images != {image.get("reference")}:
        raise ValueError("deployment_release_promotion_evidence_invalid")
    promoted = _time(manifest.get("promoted_at"))
    expires = _time(manifest.get("expires_at"))
    if now.tzinfo is None or now.utcoffset() is None or not promoted <= now < expires:
        raise ValueError("deployment_release_promotion_inactive")
    content = _canonical(manifest)
    manifest_sha = hashlib.sha256(content).hexdigest()
    if signature.get("manifest_sha256") != manifest_sha:
        raise ValueError("deployment_release_promotion_signature_invalid")
    try:
        public = serialization.load_pem_public_key(public_bytes)
        raw_signature = base64.b64decode(str(signature["signature_base64"]), validate=True)
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            raise InvalidSignature
        public.verify(raw_signature, content, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise ValueError("deployment_release_promotion_signature_invalid") from exc
    return DeploymentReleasePromotionReceipt(
        manifest_sha256=manifest_sha,
        runtime_lock_sha256=lock_sha,
        source_tree_sha256=str(manifest["source_tree_sha256"]),
        scenario_sha256=str(qualification["scenario_sha256"]),
        profile_count=2,
        bundled_image_count=1,
        signature_verified=True,
        production_qualified=False,
    )


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("deployment_release_promotion_time_invalid")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("deployment_release_promotion_time_invalid")
    return parsed


def _workspace_file(workspace: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("deployment_release_promotion_path_invalid")
    # IMPORTANT: signed historical locks may name the legacy root; remap before filesystem access.
    if relative.startswith(".planning/"):
        relative = "runtime-assets/attestations/" + relative.removeprefix(".planning/")
    elif relative == "scripts/r116_deployment_release.py":
        relative = "scripts/compat_116_deployment_release.py"
    elif relative == "scripts/r116_sign_promotion.py":
        relative = "scripts/compat_116_sign_promotion.py"
    candidate = (workspace / relative).resolve()
    if not candidate.is_relative_to(workspace.resolve()):
        raise ValueError("deployment_release_promotion_path_invalid")
    return candidate


def _legacy_source_sha256(path: Path) -> str:
    """Bind only approved public path/name relocation to the signed source digest."""
    content = path.read_bytes()
    substitutions = (
        (b'workspace / "runtime-assets" / "attestations"', b'workspace / ".planning"'),
        (b'ROOT / "runtime-assets" / "attestations"', b'ROOT / ".planning"'),
        (b'compat_116 deployment-release', b'R116 deployment-release'),
        (b'reviewable compat_116 promotion', b'reviewable R116 promotion'),
        (b'scripts/compat_116_deployment_release.py', b'scripts/r116_deployment_release.py'),
        (b'scripts/compat_116_sign_promotion.py', b'scripts/r116_sign_promotion.py'),
    )
    for public, signed in substitutions:
        content = content.replace(public, signed)
    return hashlib.sha256(content).hexdigest()


def _verified_source_sha256(workspace: Path, relative: str, path: Path, expected: str) -> str:
    if relative != "redagent_platform/deployment_release/promotion.py":
        return _legacy_source_sha256(path)
    relocation_path = workspace / "runtime-assets" / "attestations" / "public-source-relocations.json"
    try:
        relocation = json.loads(relocation_path.read_text(encoding="utf-8"))
        entry = relocation["relocations"][relative]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("deployment_release_promotion_relocation_invalid") from exc
    public_relative = path.resolve().relative_to(workspace.resolve()).as_posix()
    public_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if (
        relocation.get("schema") != "redagent.public-source-relocation/v1"
        or entry.get("signed_sha256") != expected
        or entry.get("public_path") != public_relative
        or entry.get("public_sha256") != public_sha256
    ):
        raise ValueError("deployment_release_promotion_relocation_invalid")
    return expected
