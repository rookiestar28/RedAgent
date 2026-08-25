"""Verify the complete signed compat_107 runtime promotion and derive compat_100 truth."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from redagent_platform.network_service.capability import WORKER_IMAGE_DIGEST
from redagent_platform.runner_service.contracts import ArtifactVerificationReceipt


@dataclass(frozen=True, kw_only=True)
class NetworkPromotionReceipt:
    receipt: ArtifactVerificationReceipt
    manifest_sha256: str
    signature_sha256: str
    runtime_lock_sha256: str


def verify_network_promotion(workspace: Path, *, now: datetime) -> NetworkPromotionReceipt:
    planning = workspace / "runtime-assets" / "attestations"
    manifest_path = planning / "260711-R107_NETWORK_PROMOTION.json"
    signature_path = planning / "260711-R107_NETWORK_PROMOTION.signature.json"
    public_path = planning / "260711-R107_NETWORK_PROMOTION.pub"
    lock_path = workspace / "config/r107-network-runtime.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature_bundle = json.loads(signature_path.read_text(encoding="utf-8"))
        public_bytes = public_path.read_bytes()
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("network_promotion_input_invalid") from exc
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_sha = hashlib.sha256(content).hexdigest()
    lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    if (
        manifest.get("schema") != "redagent.r107-promotion/v1"
        or manifest.get("profile_id") != "tcp-connect-discovery-v1"
        or manifest.get("runtime_lock_sha256") != lock_sha
        or manifest.get("worker_image_digest") != WORKER_IMAGE_DIGEST
        or manifest.get("gateway_image_digest") != lock.get("gateway_image_id")
        or manifest.get("target_image_digest") != lock.get("target_image_id")
        or manifest.get("critical_vulnerability_count") != 0
        or manifest.get("external_scanner_present") is not False
        or manifest.get("external_target_allowed") is not False
        or manifest.get("production_qualified") is not False
        or manifest.get("author") == manifest.get("reviewer")
        or signature_bundle.get("schema") != "redagent.ecdsa-p256-signature/v1"
        or signature_bundle.get("algorithm") != "ECDSA_P256_SHA256"
        or signature_bundle.get("manifest_sha256") != manifest_sha
    ):
        raise ValueError("network_promotion_safety_invalid")
    promoted_at = _time(manifest.get("promoted_at"))
    expires_at = _time(manifest.get("expires_at"))
    if now.tzinfo is None or now.utcoffset() is None or not promoted_at <= now < expires_at:
        raise ValueError("network_promotion_inactive")
    try:
        public = serialization.load_pem_public_key(public_bytes)
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            raise ValueError("network_promotion_key_invalid")
        signature_values = signature_bundle["signature_bytes"]
        if not isinstance(signature_values, list) or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 255
            for value in signature_values
        ):
            raise ValueError("network_promotion_signature_invalid")
        public.verify(bytes(signature_values), content, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise ValueError("network_promotion_signature_invalid") from exc
    signature_sha = hashlib.sha256(signature_path.read_bytes()).hexdigest()
    receipt = ArtifactVerificationReceipt(
        receipt_id=f"r107-network-{manifest_sha[:24]}",
        image_digest=WORKER_IMAGE_DIGEST,
        signature_verified=True,
        signer_identity=f"ecdsa-p256:{hashlib.sha256(public_bytes).hexdigest()[:32]}",
        provenance_sha256=manifest_sha,
        sbom_sha256=lock_sha,
        vulnerability_review="accepted_no_critical",
        verifier="redagent-r107-promotion-verifier",
        verified_at=promoted_at,
        expires_at=expires_at,
    )
    return NetworkPromotionReceipt(
        receipt=receipt, manifest_sha256=manifest_sha,
        signature_sha256=signature_sha, runtime_lock_sha256=lock_sha,
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("network_promotion_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("network_promotion_time_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("network_promotion_time_invalid")
    return parsed
