"""Generate the compat_112 runtime lock and ECDSA P-256 signed promotion."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]; QUALIFICATION = ROOT / "runtime-assets/attestations/260711-R112_HUMAN_SIMULATION_QUALIFICATION.json"
LOCK = ROOT / "config/r112-human-simulation-runtime.json"; PRIVATE = ROOT / ".local/redagent/r112-human/promotion.key"
PUBLIC = ROOT / "runtime-assets/attestations/260711-R112_HUMAN_SIMULATION_PROMOTION.pub"; MANIFEST = ROOT / "runtime-assets/attestations/260711-R112_HUMAN_SIMULATION_PROMOTION.json"
SIGNATURE = ROOT / "runtime-assets/attestations/260711-R112_HUMAN_SIMULATION_PROMOTION.signature.json"
password = os.environ.get("R112_SIGNING_PASSWORD", "").encode()
if len(password) < 32:
    raise SystemExit("r112_signing_password_required")
qualification = json.loads(QUALIFICATION.read_text(encoding="utf-8")); safety = qualification.get("safety", {})
if qualification.get("status") != "passed" or any(safety.values()) or qualification.get("deletion", {}).get("zero_residual") is not True:
    raise SystemExit("r112_qualification_required")
campaigns = ["r112-sink-email-canary-v1"]
lock = {"schema": "redagent.r112-runtime-lock/v1", "source_sha256": qualification["source_sha256"],
    "qualification_receipt_sha256": hashlib.sha256(QUALIFICATION.read_bytes()).hexdigest(),
    "qualification_assertion_sha256": qualification["receipt_sha256"], "enabled_campaigns": campaigns,
    "campaign_sha256": qualification["campaign_sha256"], "sink_only": True, "network_allowed": False,
    "credential_allowed": False, "human_delivery": False, "external_delivery": False, "relay_allowed": False,
    "forward_allowed": False, "tracking_allowed": False, "raw_submission_retention": False,
    "deletion_required": True, "production_qualified": False}
LOCK.parent.mkdir(parents=True, exist_ok=True); LOCK.write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
now = datetime.now(timezone.utc).replace(microsecond=0)
manifest = {"schema": "redagent.r112-promotion/v1", "runtime_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
    "source_sha256": lock["source_sha256"], "qualification_receipt_sha256": lock["qualification_receipt_sha256"],
    "enabled_campaigns": campaigns, "sink_only": True, "human_delivery": False, "external_delivery": False,
    "raw_submission_retention": False, "deletion_required": True, "critical_vulnerability_count": 0,
    "production_qualified": False, "author": "redagent-r112-author", "reviewer": "redagent-r112-reviewer",
    "promoted_at": now.isoformat().replace("+00:00", "Z"), "expires_at": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z")}
content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(); private_key = ec.generate_private_key(ec.SECP256R1())
signature = private_key.sign(content, ec.ECDSA(hashes.SHA256())); PRIVATE.parent.mkdir(parents=True, exist_ok=True)
PRIVATE.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password)))
PUBLIC.write_bytes(private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
MANIFEST.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
SIGNATURE.write_text(json.dumps({"schema": "redagent.ecdsa-p256-signature/v1", "algorithm": "ECDSA_P256_SHA256",
    "manifest_sha256": hashlib.sha256(content).hexdigest(), "signature_bytes": list(signature)}, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
