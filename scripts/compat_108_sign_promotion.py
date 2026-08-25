"""Generate the compat_108 runtime lock, signed promotion, and encrypted local private key."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "runtime-assets/attestations/260711-R108_CLOUD_CONNECTOR_QUALIFICATION.json"
LOCK = ROOT / "config/r108-cloud-runtime.json"
PRIVATE = ROOT / ".local/redagent/r108-supply-chain/promotion.key"
PUBLIC = ROOT / "runtime-assets/attestations/260711-R108_CLOUD_PROMOTION.pub"
MANIFEST = ROOT / "runtime-assets/attestations/260711-R108_CLOUD_PROMOTION.json"
SIGNATURE = ROOT / "runtime-assets/attestations/260711-R108_CLOUD_PROMOTION.signature.json"


password = os.environ.get("R108_SIGNING_PASSWORD", "").encode()
if len(password) < 32:
    raise SystemExit("r108_signing_password_required")
qualification = json.loads(QUALIFICATION.read_text(encoding="utf-8"))
if qualification.get("status") != "passed" or qualification.get("safety", {}).get("external_contact_count") != 0:
    raise SystemExit("r108_qualification_required")
lock = {
    "schema": "redagent.r108-runtime-lock/v1",
    "source_sha256": qualification["source_sha256"],
    "qualification_receipt_sha256": hashlib.sha256(QUALIFICATION.read_bytes()).hexdigest(),
    "qualification_assertion_sha256": qualification["receipt_sha256"],
    "enabled_profiles": ["aws", "azure", "gcp", "kubernetes"],
    "control_pack_sha256": "3" * 64,
    "offline_database_sha256": "4" * 64,
    "network_mode": "loopback-emulator-or-none",
    "external_adapter_execution": False,
    "real_cloud_allowed": False,
    "real_cluster_allowed": False,
    "production_qualified": False,
}
LOCK.parent.mkdir(parents=True, exist_ok=True)
with LOCK.open("w", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps(lock, sort_keys=True, indent=2) + "\n")
now = datetime.now(timezone.utc).replace(microsecond=0)
manifest = {
    "schema": "redagent.r108-promotion/v1",
    "runtime_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
    "source_sha256": lock["source_sha256"],
    "qualification_receipt_sha256": lock["qualification_receipt_sha256"],
    "enabled_profiles": lock["enabled_profiles"],
    "external_adapter_execution": False,
    "critical_vulnerability_count": 0,
    "production_qualified": False,
    "author": "redagent-r108-author",
    "reviewer": "redagent-r108-reviewer",
    "promoted_at": now.isoformat().replace("+00:00", "Z"),
    "expires_at": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
}
content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
private_key = ec.generate_private_key(ec.SECP256R1())
signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
PRIVATE.parent.mkdir(parents=True, exist_ok=True)
PRIVATE.write_bytes(private_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.BestAvailableEncryption(password),
))
PUBLIC.write_bytes(private_key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
))
with MANIFEST.open("w", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
with SIGNATURE.open("w", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps({
        "schema": "redagent.ecdsa-p256-signature/v1", "algorithm": "ECDSA_P256_SHA256",
        "manifest_sha256": hashlib.sha256(content).hexdigest(), "signature_bytes": list(signature),
    }, sort_keys=True, indent=2) + "\n")
