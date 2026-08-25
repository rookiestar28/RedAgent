"""Independent signed bundle promotion verification for R105."""

from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import yaml

from redagent_platform.nuclei_service.contracts import (
    CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
    CURRENT_NUCLEI_VERSION,
    NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
    NUCLEI_VERSION,
    NucleiBundleManifest,
    validate_template_document,
)


class NucleiPromotionError(ValueError):
    """Stable denial for invalid compat_105 bundle promotion evidence."""


def verify_current_nuclei_bundle_promotion(
    *,
    manifest_bytes: bytes,
    signature_bundle_bytes: bytes,
    public_key_bytes: bytes,
    template_bytes: bytes,
    certificate_bytes: bytes,
    qualification_bytes: bytes,
    now: datetime,
) -> NucleiBundleManifest:
    if now.tzinfo is None or now.utcoffset() is None:
        raise NucleiPromotionError("nuclei_promotion_time_invalid")
    digest = hashlib.sha256(manifest_bytes).digest()
    try:
        manifest = json.loads(manifest_bytes)
        signature_bundle = json.loads(signature_bundle_bytes)
        qualification_receipt = json.loads(qualification_bytes)
        encoded_digest = signature_bundle["messageSignature"]["messageDigest"]["digest"]
        signature = base64.b64decode(
            signature_bundle["messageSignature"]["signature"], validate=True
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NucleiPromotionError("nuclei_promotion_document_invalid") from exc
    if signature_bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise NucleiPromotionError("nuclei_promotion_bundle_type_invalid")
    if base64.b64decode(encoded_digest, validate=True) != digest:
        raise NucleiPromotionError("nuclei_promotion_digest_mismatch")
    try:
        key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("not_ec")
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise NucleiPromotionError("nuclei_promotion_signature_invalid") from exc
    try:
        engine = manifest["engine"]
        signer = manifest["signer"]
        file = manifest["files"][0]
        template = manifest["template"]
        review = manifest["review"]
        qualification = manifest["qualification"]
        promoted_at = datetime.fromisoformat(manifest["promoted_at"])
        expires_at = datetime.fromisoformat(manifest["expires_at"])
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise NucleiPromotionError("nuclei_current_promotion_claim_invalid") from exc
    template_sha = hashlib.sha256(template_bytes).hexdigest()
    certificate_sha = hashlib.sha256(certificate_bytes).hexdigest()
    qualification_sha = hashlib.sha256(qualification_bytes).hexdigest()
    try:
        certificate = x509.load_pem_x509_certificate(certificate_bytes)
        certificate_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        common_names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        document = yaml.safe_load(template_bytes)
        if not isinstance(document, dict):
            raise ValueError("template_not_mapping")
        validate_template_document(document)
    except (ValueError, x509.ExtensionNotFound, yaml.YAMLError) as exc:
        raise NucleiPromotionError("nuclei_promotion_template_or_certificate_invalid") from exc
    if (
        manifest.get("schema") != "redagent.r105-template-bundle/v2"
        or manifest.get("bundle_id") != "r105-http-header-bundle"
        or manifest.get("bundle_revision") != 2
        or manifest.get("deprecated") is not False
        or manifest.get("production_qualified") is not False
        or engine
        != {
            "version": CURRENT_NUCLEI_VERSION,
            "image_digest": CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
        }
        or len(manifest.get("files", ())) != 1
        or file.get("path") != "templates/redagent-r105-missing-header.yaml"
        or file.get("sha256") != template_sha
        or file.get("size_bytes") != len(template_bytes)
        or file.get("kind") != "nuclei-template"
        or signer.get("certificate_sha256") != certificate_sha
        or signer.get("certificate_fingerprint_sha256") != certificate_fingerprint
        or len(common_names) != 1
        or common_names[0].value != "RedAgent-R105-Template-Authority"
        or signer.get("nuclei_signature_verified") is not True
        or template.get("id") != "redagent-r105-missing-header"
        or template.get("protocol") != "http"
        or template.get("methods") != ["GET"]
        or template.get("paths") != ["/nuclei/missing-header"]
        or template.get("payload_files") != []
        or template.get("elevated_features") != []
        or review.get("author") == review.get("reviewer")
        or review.get("separation_of_duties") is not True
        or review.get("result") != "approved-local-lab-only"
        or qualification.get("receipt_sha256") != qualification_sha
        or qualification_receipt.get("schema")
        != "redagent.r105-runtime-qualification/v2"
        or qualification_receipt.get("candidate_bundle_sha256")
        != qualification.get("candidate_bundle_sha256")
        or qualification_receipt.get("owned_fixture_finding_count") != 1
        or qualification_receipt.get("external_target_contacts") != 0
        or qualification_receipt.get("direct_target_route") is not False
        or qualification_receipt.get("cleanup_residual_resource_count") != 0
        or qualification.get("owned_fixture_finding_count") != 1
        or qualification.get("external_target_contacts") != 0
        or qualification.get("direct_target_route") is not False
        or qualification.get("cleanup_residual_resource_count") != 0
        or qualification.get("false_positive_regression_passed") is not True
    ):
        raise NucleiPromotionError("nuclei_current_promotion_claim_invalid")
    if (
        promoted_at.tzinfo is None
        or expires_at.tzinfo is None
        or not promoted_at <= now < expires_at
    ):
        raise NucleiPromotionError("nuclei_current_promotion_expired")
    return NucleiBundleManifest(
        bundle_id=manifest["bundle_id"],
        revision=manifest["bundle_revision"],
        template_id=template["id"],
        template_relative_path=file["path"],
        template_sha256=template_sha,
        bundle_sha256=digest.hex(),
        signature_verified=True,
        reviewer_user_id=review["reviewer"],
        protocol=template["protocol"],
        method=template["methods"][0],
        paths=tuple(template["paths"]),
        severity=template["risk_class"],
        tags=tuple(template["tags"]),
        expected_matcher_names=tuple(template["expected_evidence"]),
        file_inventory=(file["path"],),
        promoted_at=promoted_at,
        expires_at=expires_at,
    )


def verify_nuclei_bundle_promotion(
    *, manifest_bytes: bytes, signature_bundle_bytes: bytes, public_key_bytes: bytes,
    template_bytes: bytes, certificate_bytes: bytes, now: datetime,
) -> NucleiBundleManifest:
    if now.tzinfo is None or now.utcoffset() is None:
        raise NucleiPromotionError("nuclei_promotion_time_invalid")
    digest = hashlib.sha256(manifest_bytes).digest()
    try:
        manifest = json.loads(manifest_bytes)
        signature_bundle = json.loads(signature_bundle_bytes)
        encoded_digest = signature_bundle["messageSignature"]["messageDigest"]["digest"]
        signature = base64.b64decode(signature_bundle["messageSignature"]["signature"], validate=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NucleiPromotionError("nuclei_promotion_document_invalid") from exc
    if signature_bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise NucleiPromotionError("nuclei_promotion_bundle_type_invalid")
    if base64.b64decode(encoded_digest, validate=True) != digest:
        raise NucleiPromotionError("nuclei_promotion_digest_mismatch")
    try:
        key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("not_ec")
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise NucleiPromotionError("nuclei_promotion_signature_invalid") from exc

    try:
        engine = manifest["engine"]
        signer = manifest["signer"]
        file = manifest["files"][0]
        template = manifest["template"]
        review = manifest["review"]
        qualification = manifest["qualification"]
        promoted_at = datetime.fromisoformat(manifest["promoted_at"])
        expires_at = datetime.fromisoformat(manifest["expires_at"])
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise NucleiPromotionError("nuclei_promotion_claim_invalid") from exc
    template_sha = hashlib.sha256(template_bytes).hexdigest()
    certificate_sha = hashlib.sha256(certificate_bytes).hexdigest()
    try:
        certificate = x509.load_pem_x509_certificate(certificate_bytes)
        certificate_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        common_names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        document = yaml.safe_load(template_bytes)
        if not isinstance(document, dict):
            raise ValueError("template_not_mapping")
        validate_template_document(document)
    except (ValueError, x509.ExtensionNotFound, yaml.YAMLError) as exc:
        raise NucleiPromotionError("nuclei_promotion_template_or_certificate_invalid") from exc
    if (
        manifest.get("schema") != "redagent.r105-template-bundle/v1"
        or manifest.get("bundle_id") != "r105-http-header-bundle"
        or manifest.get("bundle_revision") != 1
        or manifest.get("deprecated") is not False
        or manifest.get("production_qualified") is not False
        or engine != {"version": NUCLEI_VERSION, "image_digest": NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"]}
        or len(manifest.get("files", ())) != 1
        or file.get("path") != "templates/redagent-r105-missing-header.yaml"
        or file.get("sha256") != template_sha or file.get("size_bytes") != len(template_bytes)
        or file.get("kind") != "nuclei-template"
        or signer.get("certificate_sha256") != certificate_sha
        or signer.get("certificate_fingerprint_sha256") != certificate_fingerprint
        or len(common_names) != 1 or common_names[0].value != "RedAgent-R105-Template-Authority"
        or signer.get("nuclei_signature_verified") is not True
        or template.get("id") != "redagent-r105-missing-header"
        or template.get("protocol") != "http" or template.get("methods") != ["GET"]
        or template.get("paths") != ["/nuclei/missing-header"]
        or template.get("payload_files") != [] or template.get("elevated_features") != []
        or review.get("author") == review.get("reviewer")
        or review.get("separation_of_duties") is not True
        or review.get("result") != "approved-local-lab-only"
        or qualification.get("owned_fixture_finding_count") != 1
        or qualification.get("external_target_contacts") != 0
        or qualification.get("direct_target_route") is not False
        or qualification.get("cleanup_residual_resource_count") != 0
        or qualification.get("false_positive_regression_passed") is not True
    ):
        raise NucleiPromotionError("nuclei_promotion_claim_invalid")
    if promoted_at.tzinfo is None or expires_at.tzinfo is None or not promoted_at <= now < expires_at:
        raise NucleiPromotionError("nuclei_promotion_expired")
    return NucleiBundleManifest(
        bundle_id=manifest["bundle_id"], revision=manifest["bundle_revision"],
        template_id=template["id"], template_relative_path=file["path"],
        template_sha256=template_sha, bundle_sha256=digest.hex(), signature_verified=True,
        reviewer_user_id=review["reviewer"], protocol=template["protocol"],
        method=template["methods"][0], paths=tuple(template["paths"]),
        severity=template["risk_class"], tags=tuple(template["tags"]),
        expected_matcher_names=tuple(template["expected_evidence"]),
        file_inventory=(file["path"],), promoted_at=promoted_at, expires_at=expires_at,
    )
