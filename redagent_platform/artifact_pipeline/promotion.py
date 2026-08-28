"""Verify signed compat_110 source, runtime lock, and zero-execution qualification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from redagent_platform.runner_service.contracts import ArtifactVerificationReceipt


@dataclass(frozen=True, kw_only=True)
class ArtifactPromotionReceipt:
    receipt: ArtifactVerificationReceipt; manifest_sha256: str; signature_sha256: str; runtime_lock_sha256: str


_CURRENT_ATTESTATIONS = "runtime-assets/attestations"
_CURRENT_QUALIFICATION = "260828-ARTIFACT_POSTURE_QUALIFICATION_V2.json"
_CURRENT_MANIFEST = "260828-ARTIFACT_POSTURE_PROMOTION_V2.json"
_CURRENT_PUBLIC_KEY = "260828-ARTIFACT_POSTURE_PROMOTION_V2.pub"
_CURRENT_SIGNATURE = "260828-ARTIFACT_POSTURE_PROMOTION_V2.signature.json"
# CRITICAL: this digest is verifier-owned trust, not a value learned from mutable artifacts.
_CURRENT_PUBLIC_KEY_SHA256 = "15f9610dcb38e20ea24d0f0dbe968d881c69a91e585e63a0410ac826ef906ac5"


def verify_artifact_promotion(workspace: Path, *, now: datetime) -> ArtifactPromotionReceipt:
    planning = workspace / "runtime-assets" / "attestations"; manifest_path = planning / "260711-R110_ARTIFACT_PROMOTION.json"; signature_path = planning / "260711-R110_ARTIFACT_PROMOTION.signature.json"
    public_path = planning / "260711-R110_ARTIFACT_PROMOTION.pub"; lock_path = workspace / "config/r110-artifact-runtime.json"; qualification_path = planning / "260711-R110_ARTIFACT_PIPELINE_QUALIFICATION.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")); signature = json.loads(signature_path.read_text(encoding="utf-8")); public_bytes = public_path.read_bytes()
        lock = json.loads(lock_path.read_text(encoding="utf-8")); qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise ValueError("artifact_promotion_input_invalid") from exc
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(); manifest_sha = hashlib.sha256(content).hexdigest(); lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest(); qualification_sha = hashlib.sha256(qualification_path.read_bytes()).hexdigest()
    assertion = dict(qualification); asserted_sha = assertion.pop("receipt_sha256", None); computed_sha = hashlib.sha256(json.dumps(assertion, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    safety = qualification.get("safety", {})
    if (manifest.get("schema") != "redagent.r110-promotion/v1" or manifest.get("runtime_lock_sha256") != lock_sha or manifest.get("source_sha256") != lock.get("source_sha256")
        or manifest.get("qualification_receipt_sha256") != qualification_sha or lock.get("qualification_assertion_sha256") != asserted_sha or asserted_sha != computed_sha
        or qualification.get("status") != "passed" or any(safety.get(key) != 0 for key in ("untrusted_execution_count", "external_contact_count", "real_repository_contact_count", "real_mobile_contact_count", "external_reference_execution_count"))
        or manifest.get("enabled_profiles") != ["r110-mobile-static-v1", "r110-packaged-artifact-v1", "r110-repository-snapshot-v1"]
        or manifest.get("external_adapter_execution") is not False or manifest.get("production_qualified") is not False or manifest.get("critical_vulnerability_count") != 0
        or manifest.get("author") == manifest.get("reviewer") or signature.get("schema") != "redagent.ecdsa-p256-signature/v1" or signature.get("algorithm") != "ECDSA_P256_SHA256" or signature.get("manifest_sha256") != manifest_sha): raise ValueError("artifact_promotion_safety_invalid")
    promoted_at = _time(manifest.get("promoted_at")); expires_at = _time(manifest.get("expires_at"))
    if now.tzinfo is None or now.utcoffset() is None or not promoted_at <= now < expires_at: raise ValueError("artifact_promotion_inactive")
    try:
        public = serialization.load_pem_public_key(public_bytes); values = signature["signature_bytes"]
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1) or not isinstance(values, list) or any(not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 255 for item in values): raise ValueError
        public.verify(bytes(values), content, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc: raise ValueError("artifact_promotion_signature_invalid") from exc
    receipt = ArtifactVerificationReceipt(receipt_id=f"r110-artifact-{manifest_sha[:24]}", image_digest=f"sha256:{manifest['source_sha256']}", signature_verified=True,
        signer_identity=f"ecdsa-p256:{hashlib.sha256(public_bytes).hexdigest()[:32]}", provenance_sha256=manifest_sha, sbom_sha256=lock_sha,
        vulnerability_review="accepted_no_critical", verifier="redagent-r110-promotion-verifier", verified_at=promoted_at, expires_at=expires_at)
    return ArtifactPromotionReceipt(receipt=receipt, manifest_sha256=manifest_sha, signature_sha256=hashlib.sha256(signature_path.read_bytes()).hexdigest(), runtime_lock_sha256=lock_sha)


def artifact_source_sha256(workspace: Path) -> str:
    """Hash the exact maintained artifact-pipeline source inventory."""
    root = workspace.resolve() / "redagent_platform" / "artifact_pipeline"
    paths = sorted(root.glob("*.py"))
    if not paths:
        raise ValueError("artifact_promotion_source_invalid")
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def verify_current_artifact_promotion(
    workspace: Path, *, now: datetime
) -> ArtifactPromotionReceipt:
    """Verify the additive current-source v2 promotion without trusting embedded key material."""
    root = workspace.resolve()
    attestations = root / _CURRENT_ATTESTATIONS
    qualification_path = attestations / _CURRENT_QUALIFICATION
    manifest_path = attestations / _CURRENT_MANIFEST
    public_path = attestations / _CURRENT_PUBLIC_KEY
    signature_path = attestations / _CURRENT_SIGNATURE
    lock_path = root / "config" / "artifact-posture-runtime-v2.json"
    anchor_path = root / "config" / "artifact-posture-promotion-anchor-v2.json"
    try:
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature = json.loads(signature_path.read_text(encoding="utf-8"))
        runtime_lock = json.loads(lock_path.read_text(encoding="utf-8"))
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
        public_bytes = public_path.read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("artifact_promotion_input_invalid") from exc

    public_sha256 = hashlib.sha256(public_bytes).hexdigest()
    if (
        public_sha256 != _CURRENT_PUBLIC_KEY_SHA256
        or
        anchor
        != {
            "schema": "redagent.artifact-posture-promotion-anchor/v1",
            "algorithm": "ECDSA_P256_SHA256",
            "public_key_sha256": _CURRENT_PUBLIC_KEY_SHA256,
        }
        or manifest.get("public_key_sha256") != _CURRENT_PUBLIC_KEY_SHA256
    ):
        # CRITICAL: reject coherent workspace key/anchor replacement before signature trust.
        raise ValueError("artifact_promotion_anchor_invalid")

    qualification_body = dict(qualification)
    qualification_receipt_sha256 = qualification_body.pop("receipt_sha256", None)
    safety = qualification.get("safety", {})
    source_sha256 = artifact_source_sha256(root)
    if (
        qualification.get("schema") != "redagent.artifact-posture-qualification/v2"
        or qualification.get("status") != "passed"
        or qualification.get("scope") != "repo-owned-canonical-data-only-fixtures"
        or qualification.get("profiles") != ["r110-repository-snapshot-v1"]
        or qualification.get("source_sha256") != source_sha256
        or qualification_receipt_sha256
        != hashlib.sha256(
            json.dumps(
                qualification_body, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        or not isinstance(safety, dict)
        or any(
            safety.get(key) != 0
            for key in (
                "untrusted_execution_count",
                "external_contact_count",
                "real_repository_contact_count",
                "real_mobile_contact_count",
                "external_reference_execution_count",
            )
        )
        or safety.get("production_qualified") is not False
    ):
        raise ValueError("artifact_promotion_qualification_invalid")

    qualification_file_sha256 = hashlib.sha256(qualification_path.read_bytes()).hexdigest()
    runtime_lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    expected_lock = {
        "schema": "redagent.artifact-posture-runtime-lock/v2",
        "source_sha256": source_sha256,
        "qualification_file_sha256": qualification_file_sha256,
        "qualification_receipt_sha256": qualification_receipt_sha256,
        "profile_id": "r110-repository-snapshot-v1",
        "network_allowed": False,
        "subprocess_allowed": False,
        "credential_allowed": False,
        "package_lifecycle_allowed": False,
        "project_config_allowed": False,
        "external_adapter_execution": False,
        "archive_extraction_allowed": False,
        "production_qualified": False,
    }
    if runtime_lock != expected_lock:
        raise ValueError("artifact_promotion_runtime_lock_invalid")

    if (
        manifest.get("schema") != "redagent.artifact-posture-promotion/v2"
        or manifest.get("source_sha256") != source_sha256
        or manifest.get("qualification_file_sha256") != qualification_file_sha256
        or manifest.get("qualification_receipt_sha256") != qualification_receipt_sha256
        or manifest.get("runtime_lock_sha256") != runtime_lock_sha256
        or manifest.get("profile_id") != "r110-repository-snapshot-v1"
        or any(
            manifest.get(key) is not False
            for key in (
                "network_allowed",
                "subprocess_allowed",
                "credential_allowed",
                "external_adapter_execution",
                "production_qualified",
            )
        )
        or manifest.get("author") == manifest.get("reviewer")
    ):
        raise ValueError("artifact_promotion_safety_invalid")

    promoted_at = _time(manifest.get("promoted_at"))
    expires_at = _time(manifest.get("expires_at"))
    if (
        now.tzinfo is None
        or now.utcoffset() is None
        or not promoted_at <= now < expires_at
        or (expires_at - promoted_at).total_seconds() > 30 * 86_400
    ):
        raise ValueError("artifact_promotion_inactive")

    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_sha256 = hashlib.sha256(content).hexdigest()
    try:
        public = serialization.load_pem_public_key(public_bytes)
        values = signature["signature_bytes"]
        if (
            not isinstance(public, ec.EllipticCurvePublicKey)
            or not isinstance(public.curve, ec.SECP256R1)
            or signature.get("schema") != "redagent.ecdsa-p256-signature/v1"
            or signature.get("algorithm") != "ECDSA_P256_SHA256"
            or signature.get("manifest_sha256") != manifest_sha256
            or not isinstance(values, list)
            or any(
                not isinstance(item, int)
                or isinstance(item, bool)
                or not 0 <= item <= 255
                for item in values
            )
        ):
            raise ValueError
        public.verify(bytes(values), content, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise ValueError("artifact_promotion_signature_invalid") from exc

    receipt = ArtifactVerificationReceipt(
        receipt_id=f"artifact-posture-{manifest_sha256[:24]}",
        image_digest=f"sha256:{source_sha256}",
        signature_verified=True,
        signer_identity=f"ecdsa-p256:{public_sha256[:32]}",
        provenance_sha256=manifest_sha256,
        sbom_sha256=runtime_lock_sha256,
        vulnerability_review="accepted_no_critical",
        verifier="artifact-posture-promotion-verifier-v2",
        verified_at=promoted_at,
        expires_at=expires_at,
    )
    return ArtifactPromotionReceipt(
        receipt=receipt,
        manifest_sha256=manifest_sha256,
        signature_sha256=hashlib.sha256(signature_path.read_bytes()).hexdigest(),
        runtime_lock_sha256=runtime_lock_sha256,
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str): raise ValueError("artifact_promotion_time_invalid")
    try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc: raise ValueError("artifact_promotion_time_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None: raise ValueError("artifact_promotion_time_invalid")
    return parsed
