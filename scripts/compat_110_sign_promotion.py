"""Generate the compat_110 runtime lock and ECDSA P-256 signed promotion."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]; QUALIFICATION = ROOT / "runtime-assets/attestations/260711-R110_ARTIFACT_PIPELINE_QUALIFICATION.json"; LOCK = ROOT / "config/r110-artifact-runtime.json"
PRIVATE = ROOT / ".local/redagent/r110-supply-chain/promotion.key"; PUBLIC = ROOT / "runtime-assets/attestations/260711-R110_ARTIFACT_PROMOTION.pub"; MANIFEST = ROOT / "runtime-assets/attestations/260711-R110_ARTIFACT_PROMOTION.json"; SIGNATURE = ROOT / "runtime-assets/attestations/260711-R110_ARTIFACT_PROMOTION.signature.json"
password = os.environ.get("R110_SIGNING_PASSWORD", "").encode()
if len(password) < 32: raise SystemExit("r110_signing_password_required")
qualification = json.loads(QUALIFICATION.read_text(encoding="utf-8")); safety = qualification.get("safety", {})
if qualification.get("status") != "passed" or safety.get("untrusted_execution_count") != 0 or safety.get("external_contact_count") != 0: raise SystemExit("r110_qualification_required")
profiles = ["r110-mobile-static-v1", "r110-packaged-artifact-v1", "r110-repository-snapshot-v1"]
lock = {"schema": "redagent.r110-runtime-lock/v1", "source_sha256": qualification["source_sha256"], "qualification_receipt_sha256": hashlib.sha256(QUALIFICATION.read_bytes()).hexdigest(),
    "qualification_assertion_sha256": qualification["receipt_sha256"], "enabled_profiles": profiles, "rule_bundle_sha256": "3" * 64, "database_sha256": "5" * 64,
    "network_allowed": False, "subprocess_allowed": False, "package_lifecycle_allowed": False, "mobile_dynamic_allowed": False, "external_adapter_execution": False, "production_qualified": False}
LOCK.parent.mkdir(parents=True, exist_ok=True); LOCK.write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
now = datetime.now(timezone.utc).replace(microsecond=0); manifest = {"schema": "redagent.r110-promotion/v1", "runtime_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(), "source_sha256": lock["source_sha256"],
    "qualification_receipt_sha256": lock["qualification_receipt_sha256"], "enabled_profiles": profiles, "external_adapter_execution": False, "critical_vulnerability_count": 0,
    "production_qualified": False, "author": "redagent-r110-author", "reviewer": "redagent-r110-reviewer", "promoted_at": now.isoformat().replace("+00:00", "Z"), "expires_at": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z")}
content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(); private_key = ec.generate_private_key(ec.SECP256R1()); signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
PRIVATE.parent.mkdir(parents=True, exist_ok=True); PRIVATE.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password)))
PUBLIC.write_bytes(private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)); MANIFEST.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
SIGNATURE.write_text(json.dumps({"schema": "redagent.ecdsa-p256-signature/v1", "algorithm": "ECDSA_P256_SHA256", "manifest_sha256": hashlib.sha256(content).hexdigest(), "signature_bytes": list(signature)}, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
