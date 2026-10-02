"""Signed compat_105 Nuclei engine artifact promotion verification."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from redagent_platform.nuclei_service.authority import CURRENT_NUCLEI_ARTIFACT_PUBLIC_KEY_SHA256
from redagent_platform.runner_service.runtime_qualification import verify_owned_profile_qualification
from redagent_platform.nuclei_service.contracts import (
    CURRENT_NUCLEI_CRITICAL_REPORT_SHA256,
    CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
    CURRENT_NUCLEI_SBOM_SHA256,
    CURRENT_NUCLEI_VERSION,
    NUCLEI_CRITICAL_REPORT_SHA256,
    NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
    NUCLEI_SBOM_SHA256,
    NUCLEI_VERSION,
)
from redagent_platform.runner_service.contracts import ArtifactVerificationReceipt


class NucleiArtifactPromotionError(ValueError):
    """Stable denial for invalid engine artifact evidence."""


def verify_current_nuclei_artifact_promotion(
    *,
    promotion_bytes: bytes,
    signature_bundle_bytes: bytes,
    public_key_bytes: bytes,
    runtime_lock_bytes: bytes,
    qualification_bytes: bytes,
    now: datetime,
) -> tuple[ArtifactVerificationReceipt, str]:
    if hashlib.sha256(public_key_bytes).hexdigest() != CURRENT_NUCLEI_ARTIFACT_PUBLIC_KEY_SHA256:
        raise NucleiArtifactPromotionError("nuclei_artifact_anchor_invalid")
    if now.tzinfo is None or now.utcoffset() is None:
        raise NucleiArtifactPromotionError("nuclei_artifact_time_invalid")
    digest = hashlib.sha256(promotion_bytes).digest()
    try:
        promotion = json.loads(promotion_bytes)
        bundle = json.loads(signature_bundle_bytes)
        lock = json.loads(runtime_lock_bytes)
        qualification_receipt = json.loads(qualification_bytes)
        encoded_digest = bundle["messageSignature"]["messageDigest"]["digest"]
        signature = base64.b64decode(
            bundle["messageSignature"]["signature"], validate=True
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NucleiArtifactPromotionError("nuclei_artifact_document_invalid") from exc
    if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise NucleiArtifactPromotionError("nuclei_artifact_bundle_type_invalid")
    if base64.b64decode(encoded_digest, validate=True) != digest:
        raise NucleiArtifactPromotionError("nuclei_artifact_digest_mismatch")
    try:
        key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("not_ec")
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise NucleiArtifactPromotionError("nuclei_artifact_signature_invalid") from exc
    try:
        artifact = promotion["artifact"]
        helpers = promotion["owned_helpers"]
        review = promotion["vulnerability_review"]
        qualification = promotion["qualification"]
        created_at = datetime.fromisoformat(promotion["created_at"])
        expires_at = datetime.fromisoformat(promotion["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise NucleiArtifactPromotionError("nuclei_current_artifact_claim_invalid") from exc
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
        promotion.get("schema") != "redagent.r105-artifact-promotion/v3"
        or promotion.get("production_qualified") is not False
        or promotion.get("runtime_lock", {}).get("sha256") != lock_sha256
        or promotion.get("runtime_lock", {}).get("path")
        != "config/r105-nuclei-runtime-v3.json"
        or lock.get("schema") != "redagent.r105-runtime-lock/v3"
        or lock.get("nuclei_version") != CURRENT_NUCLEI_VERSION
        or lock.get("engine_image_id")
        != CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"]
        or lock.get("sbom_sha256") != CURRENT_NUCLEI_SBOM_SHA256
        or lock.get("critical_report_sha256") != CURRENT_NUCLEI_CRITICAL_REPORT_SHA256
        or lock.get("critical_vulnerability_count") != 0
        or lock.get("runtime_update_allowed") is not False
        or lock.get("community_templates_allowed") is not False
        or lock.get("external_target_allowed") is not False
        or artifact.get("nuclei_version") != CURRENT_NUCLEI_VERSION
        or artifact.get("image_digest") != lock.get("engine_image_id")
        or artifact.get("local_tag") != lock.get("engine_local_tag")
        or artifact.get("dockerfile_sha256") != lock.get("engine_dockerfile_sha256")
        or artifact.get("configured_user") != lock.get("runtime_user")
        or helpers != expected_helpers
        or promotion.get("sbom", {}).get("sha256") != lock.get("sbom_sha256")
        or review.get("report_sha256") != lock.get("critical_report_sha256")
        or review.get("critical_vulnerability_count") != 0
        or review.get("result") != "accepted_no_critical"
        or review.get("upstream_direct_execution_rejected") is not True
        or qualification.get("receipt_sha256") != qualification_sha256
        or qualification_receipt.get("schema")
        != "redagent.r105-runtime-qualification/v3"
        or qualification_receipt.get("runtime_lock_sha256") != lock_sha256
        or qualification_receipt.get("engine_image_id") != lock.get("engine_image_id")
        or qualification_receipt.get("signed_bundle_verified") is not True
        or qualification_receipt.get("owned_fixture_finding_count") != 1
        or qualification_receipt.get("external_target_contacts") != 0
        or qualification_receipt.get("direct_target_route") is not False
        or qualification_receipt.get("cleanup_residual_resource_count") != 0
        or qualification.get("signed_bundle_verified") is not True
        or qualification.get("owned_fixture_finding_count") != 1
        or qualification.get("external_target_contacts") != 0
        or qualification.get("direct_target_route") is not False
        or qualification.get("cleanup_residual_resource_count") != 0
    ):
        raise NucleiArtifactPromotionError("nuclei_current_artifact_claim_invalid")
    if (
        created_at.tzinfo is None
        or expires_at.tzinfo is None
        or not created_at <= now < expires_at
        or expires_at > created_at + timedelta(days=30)
    ):
        raise NucleiArtifactPromotionError("nuclei_current_artifact_expired")
    try:
        verify_owned_profile_qualification(qualification_receipt, profiles=frozenset({"nuclei-http-header-v1"}), issued_at=created_at)
    except ValueError as exc:
        raise NucleiArtifactPromotionError("nuclei_current_qualification_invalid") from exc
    return ArtifactVerificationReceipt(
        receipt_id="artifact-r105-nuclei-3111-r105-3",
        image_digest=artifact["image_digest"],
        signature_verified=True,
        signer_identity="redagent-r105-engine-promotion-key-v3",
        provenance_sha256=digest.hex(),
        sbom_sha256=CURRENT_NUCLEI_SBOM_SHA256,
        vulnerability_review="accepted_no_critical",
        verifier="redagent-r105-artifact-promotion-v3",
        verified_at=created_at,
        expires_at=expires_at,
    ), hashlib.sha256(signature_bundle_bytes).hexdigest()


def verify_nuclei_artifact_promotion(
    *, promotion_bytes: bytes, signature_bundle_bytes: bytes,
    public_key_bytes: bytes, now: datetime,
) -> tuple[ArtifactVerificationReceipt, str]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise NucleiArtifactPromotionError("nuclei_artifact_time_invalid")
    digest = hashlib.sha256(promotion_bytes).digest()
    try:
        promotion = json.loads(promotion_bytes)
        bundle = json.loads(signature_bundle_bytes)
        encoded_digest = bundle["messageSignature"]["messageDigest"]["digest"]
        signature = base64.b64decode(bundle["messageSignature"]["signature"], validate=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NucleiArtifactPromotionError("nuclei_artifact_document_invalid") from exc
    if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise NucleiArtifactPromotionError("nuclei_artifact_bundle_type_invalid")
    if base64.b64decode(encoded_digest, validate=True) != digest:
        raise NucleiArtifactPromotionError("nuclei_artifact_digest_mismatch")
    try:
        key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("not_ec")
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise NucleiArtifactPromotionError("nuclei_artifact_signature_invalid") from exc
    try:
        artifact = promotion["artifact"]
        review = promotion["vulnerability_review"]
        qualification = promotion["qualification"]
        created_at = datetime.fromisoformat(promotion["created_at"])
        expires_at = datetime.fromisoformat(promotion["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise NucleiArtifactPromotionError("nuclei_artifact_claim_invalid") from exc
    if (
        promotion.get("schema") != "redagent.r105-artifact-promotion/v1"
        or promotion.get("production_qualified") is not False
        or artifact.get("nuclei_version") != NUCLEI_VERSION
        or artifact.get("platform") != "linux/amd64"
        or artifact.get("image_digest") != NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"]
        or artifact.get("configured_user") != "65532:65532"
        or promotion.get("sbom", {}).get("sha256") != NUCLEI_SBOM_SHA256
        or review.get("report_sha256") != NUCLEI_CRITICAL_REPORT_SHA256
        or review.get("critical_vulnerability_count") != 0
        or review.get("result") != "accepted_no_critical"
        or review.get("upstream_direct_execution_rejected") is not True
        or qualification.get("signed_bundle_verified") is not True
        or qualification.get("owned_fixture_finding_count") != 1
        or qualification.get("external_target_contacts") != 0
        or qualification.get("direct_target_route") is not False
        or qualification.get("cleanup_residual_resource_count") != 0
    ):
        raise NucleiArtifactPromotionError("nuclei_artifact_claim_invalid")
    if created_at.tzinfo is None or expires_at.tzinfo is None or not created_at <= now < expires_at:
        raise NucleiArtifactPromotionError("nuclei_artifact_expired")
    return ArtifactVerificationReceipt(
        receipt_id="artifact-r105-nuclei-380-r105-1",
        image_digest=artifact["image_digest"], signature_verified=True,
        signer_identity="redagent-r105-engine-promotion-key",
        provenance_sha256=digest.hex(), sbom_sha256=NUCLEI_SBOM_SHA256,
        vulnerability_review="accepted_no_critical", verifier="redagent-r105-artifact-promotion-v1",
        verified_at=created_at, expires_at=expires_at,
    ), hashlib.sha256(signature_bundle_bytes).hexdigest()
