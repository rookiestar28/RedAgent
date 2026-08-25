"""Generate the local compat_107 promotion manifest and encrypted signing material."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/r107-network-runtime.json"
PRIVATE = ROOT / ".local/redagent/r107-supply-chain/promotion.key"
PUBLIC = ROOT / "runtime-assets/attestations/260711-R107_NETWORK_PROMOTION.pub"
MANIFEST = ROOT / "runtime-assets/attestations/260711-R107_NETWORK_PROMOTION.json"
SIGNATURE = ROOT / "runtime-assets/attestations/260711-R107_NETWORK_PROMOTION.signature.json"


password = os.environ.get("R107_SIGNING_PASSWORD", "").encode()
if len(password) < 32:
    raise SystemExit("r107_signing_password_required")
lock = json.loads(LOCK.read_text(encoding="utf-8"))
now = datetime.now(timezone.utc).replace(microsecond=0)
manifest = {
    "schema": "redagent.r107-promotion/v1",
    "profile_id": "tcp-connect-discovery-v1",
    "runtime_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
    "worker_image_digest": lock["worker_image_id"],
    "gateway_image_digest": lock["gateway_image_id"],
    "target_image_digest": lock["target_image_id"],
    "critical_vulnerability_count": 0,
    "external_scanner_present": False,
    "external_target_allowed": False,
    "production_qualified": False,
    "author": "redagent-r107-author",
    "reviewer": "redagent-r107-reviewer",
    "promoted_at": now.isoformat().replace("+00:00", "Z"),
    "expires_at": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
}
content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
private_key = ec.generate_private_key(ec.SECP256R1())
signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
PRIVATE.parent.mkdir(parents=True, exist_ok=True)
PRIVATE.write_bytes(private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.BestAvailableEncryption(password),
))
PUBLIC.write_bytes(private_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
))
with MANIFEST.open("w", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
with SIGNATURE.open("w", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps({
    "schema": "redagent.ecdsa-p256-signature/v1",
    "algorithm": "ECDSA_P256_SHA256",
    "manifest_sha256": hashlib.sha256(content).hexdigest(),
    "signature_bytes": list(signature),
    }, sort_keys=True, indent=2) + "\n")
