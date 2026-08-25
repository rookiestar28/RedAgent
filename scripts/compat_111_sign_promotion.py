"""Generate the compat_111 runtime lock and ECDSA P-256 signed promotion."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "runtime-assets/attestations/260711-R111_PURPLE_RUNTIME_QUALIFICATION.json"
LOCK = ROOT / "config/r111-purple-runtime.json"
PRIVATE = ROOT / ".local/redagent/r111-purple/promotion.key"
PUBLIC = ROOT / "runtime-assets/attestations/260711-R111_PURPLE_PROMOTION.pub"
MANIFEST = ROOT / "runtime-assets/attestations/260711-R111_PURPLE_PROMOTION.json"
SIGNATURE = ROOT / "runtime-assets/attestations/260711-R111_PURPLE_PROMOTION.signature.json"
password = os.environ.get("R111_SIGNING_PASSWORD", "").encode()
if len(password) < 32:
    raise SystemExit("r111_signing_password_required")
qualification = json.loads(QUALIFICATION.read_text(encoding="utf-8")); safety = qualification.get("safety", {})
if qualification.get("status") != "passed" or any(safety.values()) or qualification.get("detection", {}).get("observed") is not True:
    raise SystemExit("r111_qualification_required")
abilities = ["r111-file-stage-marker-v1"]
lock = {"schema": "redagent.r111-runtime-lock/v1", "source_sha256": qualification["source_sha256"],
    "qualification_receipt_sha256": hashlib.sha256(QUALIFICATION.read_bytes()).hexdigest(),
    "qualification_assertion_sha256": qualification["receipt_sha256"], "enabled_abilities": abilities,
    "ability_sha256": qualification["ability_sha256"], "adapter_sha256": qualification["adapter_sha256"],
    "network_allowed": False, "subprocess_allowed": False, "privilege_allowed": False,
    "external_adapter_execution": False, "production_qualified": False, "telemetry_required": True,
    "cleanup_required": True, "teardown_required": True}
LOCK.parent.mkdir(parents=True, exist_ok=True); LOCK.write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
now = datetime.now(timezone.utc).replace(microsecond=0)
manifest = {"schema": "redagent.r111-promotion/v1", "runtime_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
    "source_sha256": lock["source_sha256"], "qualification_receipt_sha256": lock["qualification_receipt_sha256"],
    "enabled_abilities": abilities, "telemetry_required": True, "cleanup_required": True,
    "external_adapter_execution": False, "critical_vulnerability_count": 0, "production_qualified": False,
    "author": "redagent-r111-author", "reviewer": "redagent-r111-reviewer",
    "promoted_at": now.isoformat().replace("+00:00", "Z"), "expires_at": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z")}
content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(); private_key = ec.generate_private_key(ec.SECP256R1())
signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
PRIVATE.parent.mkdir(parents=True, exist_ok=True); PRIVATE.write_bytes(private_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password)))
PUBLIC.write_bytes(private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
MANIFEST.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
SIGNATURE.write_text(json.dumps({"schema": "redagent.ecdsa-p256-signature/v1", "algorithm": "ECDSA_P256_SHA256",
    "manifest_sha256": hashlib.sha256(content).hexdigest(), "signature_bytes": list(signature)}, sort_keys=True, indent=2) + "\n",
    encoding="utf-8", newline="\n")
