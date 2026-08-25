"""Verify the signed compat_108 source, profile, offline-artifact, and qualification promotion."""

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
class CloudPromotionReceipt:
    receipt: ArtifactVerificationReceipt
    manifest_sha256: str
    signature_sha256: str
    runtime_lock_sha256: str


def verify_cloud_promotion(workspace: Path, *, now: datetime) -> CloudPromotionReceipt:
    planning = workspace / "runtime-assets" / "attestations"
    manifest_path = planning / "260711-R108_CLOUD_PROMOTION.json"
    signature_path = planning / "260711-R108_CLOUD_PROMOTION.signature.json"
    public_path = planning / "260711-R108_CLOUD_PROMOTION.pub"
    lock_path = workspace / "config/r108-cloud-runtime.json"
    qualification_path = planning / "260711-R108_CLOUD_CONNECTOR_QUALIFICATION.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature_bundle = json.loads(signature_path.read_text(encoding="utf-8"))
        public_bytes = public_path.read_bytes()
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("cloud_promotion_input_invalid") from exc
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_sha = hashlib.sha256(content).hexdigest()
    lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    qualification_sha = hashlib.sha256(qualification_path.read_bytes()).hexdigest()
    qualification_assertion = dict(qualification)
    asserted_sha = qualification_assertion.pop("receipt_sha256", None)
    computed_assertion = hashlib.sha256(json.dumps(qualification_assertion, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (
        manifest.get("schema") != "redagent.r108-promotion/v1"
        or manifest.get("runtime_lock_sha256") != lock_sha
        or manifest.get("source_sha256") != lock.get("source_sha256")
        or manifest.get("qualification_receipt_sha256") != qualification_sha
        or lock.get("qualification_assertion_sha256") != asserted_sha
        or asserted_sha != computed_assertion
        or qualification.get("status") != "passed"
        or qualification.get("safety", {}).get("external_contact_count") != 0
        or qualification.get("safety", {}).get("real_cloud_contact_count") != 0
        or qualification.get("safety", {}).get("real_cluster_contact_count") != 0
        or manifest.get("enabled_profiles") != ["aws", "azure", "gcp", "kubernetes"]
        or manifest.get("external_adapter_execution") is not False
        or manifest.get("production_qualified") is not False
        or manifest.get("critical_vulnerability_count") != 0
        or manifest.get("author") == manifest.get("reviewer")
        or signature_bundle.get("schema") != "redagent.ecdsa-p256-signature/v1"
        or signature_bundle.get("algorithm") != "ECDSA_P256_SHA256"
        or signature_bundle.get("manifest_sha256") != manifest_sha
    ):
        raise ValueError("cloud_promotion_safety_invalid")
    promoted_at = _time(manifest.get("promoted_at"))
    expires_at = _time(manifest.get("expires_at"))
    if now.tzinfo is None or now.utcoffset() is None or not promoted_at <= now < expires_at:
        raise ValueError("cloud_promotion_inactive")
    try:
        public = serialization.load_pem_public_key(public_bytes)
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            raise ValueError("cloud_promotion_key_invalid")
        signature_values = signature_bundle["signature_bytes"]
        if not isinstance(signature_values, list) or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 255 for value in signature_values):
            raise ValueError("cloud_promotion_signature_invalid")
        public.verify(bytes(signature_values), content, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise ValueError("cloud_promotion_signature_invalid") from exc
    source_digest = f"sha256:{manifest['source_sha256']}"
    receipt = ArtifactVerificationReceipt(
        receipt_id=f"r108-cloud-{manifest_sha[:24]}", image_digest=source_digest,
        signature_verified=True, signer_identity=f"ecdsa-p256:{hashlib.sha256(public_bytes).hexdigest()[:32]}",
        provenance_sha256=manifest_sha, sbom_sha256=lock_sha,
        vulnerability_review="accepted_no_critical", verifier="redagent-r108-promotion-verifier",
        verified_at=promoted_at, expires_at=expires_at,
    )
    return CloudPromotionReceipt(
        receipt=receipt, manifest_sha256=manifest_sha,
        signature_sha256=hashlib.sha256(signature_path.read_bytes()).hexdigest(),
        runtime_lock_sha256=lock_sha,
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("cloud_promotion_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("cloud_promotion_time_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("cloud_promotion_time_invalid")
    return parsed
