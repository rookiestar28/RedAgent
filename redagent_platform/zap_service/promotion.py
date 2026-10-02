"""Closed verification for the signed compat_104 local artifact promotion."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from redagent_platform.zap_service.authority import CURRENT_ZAP_PUBLIC_KEY_SHA256
from redagent_platform.runner_service.runtime_qualification import verify_owned_profile_qualification
from redagent_platform.runner_service.contracts import ArtifactVerificationReceipt
from redagent_platform.zap_service.contracts import (
    CURRENT_ZAP_CRITICAL_REPORT_SHA256,
    CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM,
    CURRENT_ZAP_SBOM_SHA256,
    ZAP_ADDON_INVENTORY_SHA256,
    ZAP_IMAGE_DIGEST_BY_PLATFORM,
    ZAP_UPSTREAM_BARE_DIGEST,
    ZAP_VERSION,
)


class ZapPromotionError(ValueError):
    """Stable failure for an untrusted or stale compat_104 promotion."""


def verify_current_zap_promotion(
    *,
    promotion_bytes: bytes,
    bundle_bytes: bytes,
    public_key_bytes: bytes,
    runtime_lock_bytes: bytes,
    qualification_bytes: bytes,
    now: datetime,
) -> tuple[ArtifactVerificationReceipt, str]:
    """Verify only the additive compat_104 revision-3 authority and its source receipts."""
    if hashlib.sha256(public_key_bytes).hexdigest() != CURRENT_ZAP_PUBLIC_KEY_SHA256:
        raise ZapPromotionError("zap_promotion_anchor_invalid")
    promotion = _verified_zap_document(
        document_bytes=promotion_bytes,
        bundle_bytes=bundle_bytes,
        public_key_bytes=public_key_bytes,
        now=now,
    )
    try:
        lock = json.loads(runtime_lock_bytes)
        qualification_receipt = json.loads(qualification_bytes)
        artifact = promotion["artifact"]
        helpers = promotion["owned_helpers"]
        review = promotion["vulnerability_review"]
        qualification = promotion["qualification"]
        created_at = datetime.fromisoformat(promotion["created_at"])
        expires_at = datetime.fromisoformat(promotion["expires_at"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ZapPromotionError("zap_current_promotion_claim_invalid") from exc
    expected_profiles = {
        "zap-passive-v1",
        "zap-auth-crawl-v1",
        "zap-client-spider-v1",
        "zap-active-xss-lab-v1",
    }
    lock_sha256 = hashlib.sha256(runtime_lock_bytes).hexdigest()
    qualification_sha256 = hashlib.sha256(qualification_bytes).hexdigest()
    expected_helpers = {
        "target_local_tag": lock.get("target_local_tag"),
        "target_image_id": lock.get("target_image_id"),
        "target_source_sha256": lock.get("target_source_sha256"),
        "target_dockerfile_sha256": lock.get("target_dockerfile_sha256"),
        "gateway_local_tag": lock.get("gateway_local_tag"),
        "gateway_image_id": lock.get("gateway_image_id"),
        "gateway_source_sha256": lock.get("gateway_source_sha256"),
        "gateway_dockerfile_sha256": lock.get("gateway_dockerfile_sha256"),
    }
    if (
        promotion.get("schema") != "redagent.r104-artifact-promotion/v3"
        or promotion.get("production_qualified") is not False
        or promotion.get("runtime_lock", {}).get("sha256") != lock_sha256
        or promotion.get("runtime_lock", {}).get("path")
        != "config/r104-zap-runtime-v3.json"
        or lock.get("schema") != "redagent.r104-runtime-lock/v3"
        or lock.get("engine_image_id")
        != CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"]
        or lock.get("sbom_sha256") != CURRENT_ZAP_SBOM_SHA256
        or lock.get("critical_report_sha256") != CURRENT_ZAP_CRITICAL_REPORT_SHA256
        or lock.get("critical_vulnerability_count") != 0
        or lock.get("runtime_update_allowed") is not False
        or lock.get("external_target_allowed") is not False
        or artifact.get("image_digest") != lock.get("engine_image_id")
        or artifact.get("local_tag") != lock.get("engine_local_tag")
        or artifact.get("dockerfile_sha256") != lock.get("engine_dockerfile_sha256")
        or artifact.get("configured_user") != lock.get("runtime_user")
        or helpers != expected_helpers
        or artifact.get("upstream_image_digest") != ZAP_UPSTREAM_BARE_DIGEST
        or artifact.get("zap_version") != ZAP_VERSION
        or artifact.get("addon_inventory_sha256") != ZAP_ADDON_INVENTORY_SHA256
        or promotion.get("sbom", {}).get("sha256") != lock.get("sbom_sha256")
        or review.get("report_sha256") != lock.get("critical_report_sha256")
        or review.get("critical_vulnerability_count") != 0
        or review.get("result") != "accepted_no_critical"
        or qualification.get("receipt_sha256") != qualification_sha256
        or qualification_receipt.get("schema")
        != "redagent.r104-runtime-qualification/v3"
        or qualification_receipt.get("runtime_lock_sha256") != lock_sha256
        or qualification_receipt.get("engine_image_id") != lock.get("engine_image_id")
        or qualification_receipt.get("all_profiles_passed") is not True
        or {item.get("profile_id") for item in qualification_receipt.get("profiles", ())}
        != expected_profiles
        or set(qualification.get("profiles", ())) != expected_profiles
        or qualification.get("all_profiles_passed") is not True
        or qualification.get("external_target_contacts") != 0
        or qualification.get("direct_target_route") is not False
        or qualification.get("cleanup_residual_resource_count") != 0
    ):
        raise ZapPromotionError("zap_current_promotion_claim_invalid")
    if (
        created_at.tzinfo is None
        or expires_at.tzinfo is None
        or not created_at <= now < expires_at
        or expires_at > created_at + timedelta(days=30)
    ):
        raise ZapPromotionError("zap_current_promotion_expired")
    try:
        verify_owned_profile_qualification(qualification_receipt, profiles=frozenset(expected_profiles), issued_at=created_at)
    except ValueError as exc:
        raise ZapPromotionError("zap_current_qualification_invalid") from exc
    digest = hashlib.sha256(promotion_bytes).hexdigest()
    return ArtifactVerificationReceipt(
        receipt_id="artifact-r104-zap-2170-r104-3",
        image_digest=artifact["image_digest"],
        signature_verified=True,
        signer_identity="redagent-r104-local-promotion-key-v3",
        provenance_sha256=digest,
        sbom_sha256=CURRENT_ZAP_SBOM_SHA256,
        vulnerability_review="accepted_no_critical",
        verifier="redagent-r104-promotion-v3",
        verified_at=created_at,
        expires_at=expires_at,
    ), hashlib.sha256(bundle_bytes).hexdigest()


def _verified_zap_document(
    *,
    document_bytes: bytes,
    bundle_bytes: bytes,
    public_key_bytes: bytes,
    now: datetime,
) -> dict[str, object]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ZapPromotionError("zap_promotion_time_invalid")
    digest = hashlib.sha256(document_bytes).digest()
    try:
        document = json.loads(document_bytes)
        bundle = json.loads(bundle_bytes)
        encoded_digest = bundle["messageSignature"]["messageDigest"]["digest"]
        signature = base64.b64decode(
            bundle["messageSignature"]["signature"], validate=True
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ZapPromotionError("zap_promotion_document_invalid") from exc
    if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ZapPromotionError("zap_promotion_bundle_type_invalid")
    if base64.b64decode(encoded_digest, validate=True) != digest:
        raise ZapPromotionError("zap_promotion_digest_mismatch")
    try:
        key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("not_ec")
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ZapPromotionError("zap_promotion_signature_invalid") from exc
    if not isinstance(document, dict):
        raise ZapPromotionError("zap_promotion_document_invalid")
    return document


def verify_zap_promotion(
    *, promotion_bytes: bytes, bundle_bytes: bytes, public_key_bytes: bytes, now: datetime,
) -> tuple[ArtifactVerificationReceipt, str]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ZapPromotionError("zap_promotion_time_invalid")
    digest = hashlib.sha256(promotion_bytes).digest()
    try:
        promotion = json.loads(promotion_bytes)
        bundle = json.loads(bundle_bytes)
        encoded_digest = bundle["messageSignature"]["messageDigest"]["digest"]
        signature = base64.b64decode(bundle["messageSignature"]["signature"], validate=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ZapPromotionError("zap_promotion_document_invalid") from exc
    if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ZapPromotionError("zap_promotion_bundle_type_invalid")
    if base64.b64decode(encoded_digest, validate=True) != digest:
        raise ZapPromotionError("zap_promotion_digest_mismatch")
    try:
        key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("not_ec")
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ZapPromotionError("zap_promotion_signature_invalid") from exc

    artifact = promotion.get("artifact", {})
    review = promotion.get("vulnerability_review", {})
    qualification = promotion.get("qualification", {})
    expected_profiles = {
        "zap-passive-v1", "zap-auth-crawl-v1", "zap-client-spider-v1", "zap-active-xss-lab-v1",
    }
    if (
        promotion.get("schema") != "redagent.r104-artifact-promotion/v1"
        or promotion.get("production_qualified") is not False
        or artifact.get("image_digest") != ZAP_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"]
        or artifact.get("upstream_image_digest") != ZAP_UPSTREAM_BARE_DIGEST
        or artifact.get("zap_version") != ZAP_VERSION
        or artifact.get("addon_inventory_sha256") != ZAP_ADDON_INVENTORY_SHA256
        or review.get("critical_vulnerability_count") != 0
        or review.get("result") != "accepted_no_critical"
        or review.get("scanner_release_signature_verified") is not True
        or qualification.get("all_profiles_passed") is not True
        or set(qualification.get("profiles", ())) != expected_profiles
        or qualification.get("external_target_contacts") != 0
        or qualification.get("cleanup_residual_resource_count") != 0
    ):
        raise ZapPromotionError("zap_promotion_claim_invalid")
    try:
        verified_at = datetime.fromisoformat(promotion["created_at"])
        sbom_sha256 = promotion["sbom"]["sha256"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ZapPromotionError("zap_promotion_claim_invalid") from exc
    if verified_at.tzinfo is None or verified_at > now or now >= verified_at + timedelta(days=30):
        raise ZapPromotionError("zap_promotion_expired")
    return ArtifactVerificationReceipt(
        receipt_id="artifact-r104-zap-2170-r104-1",
        image_digest=artifact["image_digest"], signature_verified=True,
        signer_identity="redagent-r104-local-promotion-key",
        provenance_sha256=digest.hex(), sbom_sha256=sbom_sha256,
        vulnerability_review="accepted_no_critical", verifier="redagent-r104-promotion-v1",
        verified_at=verified_at, expires_at=verified_at + timedelta(days=30),
    ), hashlib.sha256(bundle_bytes).hexdigest()
