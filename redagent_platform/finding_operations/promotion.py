"""Verify signed compat_115 fixture-only finding operations promotion."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True, kw_only=True)
class FindingOperationsPromotionReceipt:
    manifest_sha256: str
    runtime_lock_sha256: str
    scenario_sha256: str
    fixture_connector_count: int


def verify_finding_operations_promotion(workspace: Path, *, now: datetime) -> FindingOperationsPromotionReceipt:
    planning = workspace / "runtime-assets" / "attestations"
    manifest_path = planning / "260712-R115_FINDING_OPERATIONS_PROMOTION.json"
    signature_path = planning / "260712-R115_FINDING_OPERATIONS_PROMOTION.signature.json"
    public_path = planning / "260712-R115_FINDING_OPERATIONS_PROMOTION.pub"
    qualification_path = planning / "260712-R115_FINDING_OPERATIONS_QUALIFICATION.json"
    lock_path = workspace / "config/r115-finding-operations-runtime.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature = json.loads(signature_path.read_text(encoding="utf-8"))
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        public_bytes = public_path.read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("finding_promotion_input_invalid") from exc
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_sha = hashlib.sha256(content).hexdigest()
    assertion = dict(qualification); asserted_sha = assertion.pop("receipt_sha256", None)
    computed_sha = hashlib.sha256(json.dumps(assertion, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    false_fields = (
        "external_connectors", "arbitrary_destination", "arbitrary_payload", "ai_approval",
        "generator_publication", "unreviewed_publication", "unredacted_publication", "network_enabled",
    )
    zero_fields = (
        "network_contact_count", "credential_access_count", "sensitive_retention_count",
        "ai_approval_count", "generator_publication_count", "external_delivery_count",
    )
    if (
        manifest.get("schema") != "redagent.r115-promotion/v1"
        or manifest.get("runtime_lock_sha256") != hashlib.sha256(lock_path.read_bytes()).hexdigest()
        or manifest.get("qualification_receipt_sha256") != hashlib.sha256(qualification_path.read_bytes()).hexdigest()
        or asserted_sha != computed_sha or lock.get("qualification_assertion_sha256") != asserted_sha
        or qualification.get("status") != "passed"
        or qualification.get("adversarial_case_count") != qualification.get("denied_case_count")
        or any(qualification.get(field) != 0 for field in zero_fields)
        or lock.get("enabled_connectors") != ["fixture-ticket"]
        or any(lock.get(field) is not False for field in false_fields)
        or any(manifest.get(field) is not False for field in false_fields)
        or manifest.get("production_qualified") is not False
        or manifest.get("author") == manifest.get("reviewer")
        or signature.get("manifest_sha256") != manifest_sha
    ):
        raise ValueError("finding_promotion_safety_invalid")
    promoted = _time(manifest.get("promoted_at")); expires = _time(manifest.get("expires_at"))
    if now.tzinfo is None or not promoted <= now < expires:
        raise ValueError("finding_promotion_inactive")
    try:
        public = serialization.load_pem_public_key(public_bytes)
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            raise ValueError
        public.verify(bytes(signature["signature_bytes"]), content, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise ValueError("finding_promotion_signature_invalid") from exc
    return FindingOperationsPromotionReceipt(
        manifest_sha256=manifest_sha, runtime_lock_sha256=str(manifest["runtime_lock_sha256"]),
        scenario_sha256=str(qualification["scenario_sha256"]), fixture_connector_count=1,
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("finding_promotion_time_invalid")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("finding_promotion_time_invalid")
    return parsed
