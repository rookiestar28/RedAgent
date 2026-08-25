"""Independent signed promotion verification for the complete compat_106 API bundle."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from redagent_platform.api_differential_service.artifact import EXPECTED_WHEEL_SHA256, verify_schemathesis_artifact
from redagent_platform.api_differential_service.specification import OpenApiSnapshot, validate_and_snapshot_spec
from redagent_platform.runner_service.contracts import ArtifactVerificationReceipt


class ApiDifferentialPromotionError(ValueError):
    """Stable signed-bundle promotion denial."""


def verify_api_differential_promotion(
    workspace: Path, *, now: datetime,
) -> tuple[ArtifactVerificationReceipt, OpenApiSnapshot, dict[str, object], str]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ApiDifferentialPromotionError("api_promotion_time_invalid")
    bundle_dir = workspace / "bundles/r106-api"
    planning = workspace / "runtime-assets" / "attestations"
    try:
        manifest_bytes = (bundle_dir / "bundle-manifest.json").read_bytes()
        signature_bundle_bytes = (planning / "260711-R106_API_DIFFERENTIAL_PROMOTION.sigstore.json").read_bytes()
        public_key_bytes = (planning / "260711-R106_API_DIFFERENTIAL_PROMOTION.pub").read_bytes()
        names = {path.name for path in bundle_dir.iterdir() if path.is_file()}
    except OSError as exc:
        raise ApiDifferentialPromotionError("api_promotion_input_unavailable") from exc
    expected_names = {
        "bundle-manifest.json", "identity-matrix.json", "openapi.json",
        "operation-manifest.json", "sequence-grammar.json",
    }
    if names != expected_names or any(path.is_symlink() for path in bundle_dir.iterdir()):
        raise ApiDifferentialPromotionError("api_promotion_inventory_invalid")
    digest = hashlib.sha256(manifest_bytes).digest()
    try:
        manifest = json.loads(manifest_bytes)
        signature_bundle = json.loads(signature_bundle_bytes)
        encoded_digest = signature_bundle["messageSignature"]["messageDigest"]["digest"]
        signature = base64.b64decode(signature_bundle["messageSignature"]["signature"], validate=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ApiDifferentialPromotionError("api_promotion_document_invalid") from exc
    if signature_bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ApiDifferentialPromotionError("api_promotion_signature_bundle_invalid")
    try:
        if base64.b64decode(encoded_digest, validate=True) != digest:
            raise ValueError("digest")
        key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("not_ec")
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ApiDifferentialPromotionError("api_promotion_signature_invalid") from exc
    if manifest.get("schema") != "redagent.r106-bundle-manifest/v1":
        raise ApiDifferentialPromotionError("api_promotion_claim_invalid")
    try:
        promoted_at = datetime.fromisoformat(str(manifest["promoted_at"]).replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(str(manifest["expires_at"]).replace("Z", "+00:00"))
        files = manifest["files"]
        review = manifest["review"]
        qualification = manifest["qualification"]
        engine = manifest["engine"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ApiDifferentialPromotionError("api_promotion_claim_invalid") from exc
    if (
        not promoted_at <= now < expires_at
        or expires_at > promoted_at + timedelta(days=30)
        or manifest.get("bundle_id") != "r106-owned-api-differential"
        or manifest.get("revision") != 1
        or manifest.get("author_user_id") == manifest.get("reviewer_user_id")
        or engine != {"name": "schemathesis", "version": "4.22.4", "wheel_sha256": EXPECTED_WHEEL_SHA256}
        or review != {
            "state": "approved-local-lab", "callbacks": False, "webhooks": False,
            "external_references": False, "unexpected_methods": False,
            "arbitrary_credentials": False, "restler_execution": False, "cleanup_required": True,
        }
        or qualification != {
            "owned_fixture_only": True, "external_target_contacts": 0, "production_qualified": False,
        }
    ):
        raise ApiDifferentialPromotionError("api_promotion_claim_invalid")
    expected_files = {
        "identity-matrix.json", "openapi.json", "operation-manifest.json", "sequence-grammar.json",
    }
    if not isinstance(files, list) or {item.get("path") for item in files if isinstance(item, dict)} != expected_files:
        raise ApiDifferentialPromotionError("api_promotion_inventory_invalid")
    content: dict[str, object] = {}
    for item in files:
        if not isinstance(item, dict):
            raise ApiDifferentialPromotionError("api_promotion_inventory_invalid")
        path = bundle_dir / str(item.get("path"))
        try:
            payload = path.read_bytes()
            content[path.name] = json.loads(payload)
        except (OSError, json.JSONDecodeError) as exc:
            raise ApiDifferentialPromotionError("api_promotion_file_invalid") from exc
        if item.get("sha256") != hashlib.sha256(payload).hexdigest() or item.get("size_bytes") != len(payload):
            raise ApiDifferentialPromotionError("api_promotion_file_mismatch")
    openapi = content["openapi.json"]
    if not isinstance(openapi, dict):
        raise ApiDifferentialPromotionError("api_promotion_spec_invalid")
    snapshot = validate_and_snapshot_spec(openapi)
    operation = content["operation-manifest.json"]
    matrix = content["identity-matrix.json"]
    grammar = content["sequence-grammar.json"]
    if (
        manifest.get("canonical_spec_sha256") != snapshot.spec_sha256
        or not isinstance(operation, dict) or operation.get("schema") != "redagent.r106-operation-manifest/v1"
        or operation.get("callbacks") is not False or operation.get("webhooks") is not False
        or operation.get("external_references") is not False or operation.get("unexpected_methods") is not False
        or operation.get("production_qualified") is not False
        or not isinstance(matrix, dict) or matrix.get("schema") != "redagent.r106-identity-matrix/v1"
        or matrix.get("credentials_in_generator") is not False or matrix.get("credentials_in_replay") is not False
        or matrix.get("production_qualified") is not False
        or not isinstance(grammar, dict) or grammar.get("schema") != "redagent.r106-sequence-grammar/v1"
        or grammar.get("cleanup_order") != "reverse_dependency"
        or grammar.get("aggressive_resource_grammar") is not False
        or grammar.get("restler_execution") is not False
        or grammar.get("production_qualified") is not False
    ):
        raise ApiDifferentialPromotionError("api_promotion_semantics_invalid")
    engine_receipt = verify_schemathesis_artifact(workspace)
    receipt = ArtifactVerificationReceipt(
        receipt_id="artifact-r106-schemathesis-4224-r106-1",
        image_digest=f"sha256:{EXPECTED_WHEEL_SHA256}", signature_verified=True,
        signer_identity="redagent-r106-api-promotion-key",
        provenance_sha256=digest.hex(), sbom_sha256=str(engine_receipt["generated_sbom_sha256"]),
        vulnerability_review="accepted_no_critical", verifier="redagent-r106-promotion-v1",
        verified_at=promoted_at, expires_at=expires_at,
    )
    return receipt, snapshot, manifest, hashlib.sha256(signature_bundle_bytes).hexdigest()
