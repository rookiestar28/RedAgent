from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    password = os.environ.get("R115_SIGNING_PASSWORD", "").encode()
    if len(password) < 20:
        raise SystemExit("signing_password_required")
    planning = ROOT / "runtime-assets" / "attestations"; local = ROOT / ".local/redagent/r115"; config = ROOT / "config"
    local.mkdir(parents=True, exist_ok=True); config.mkdir(parents=True, exist_ok=True)
    qualification_path = planning / "260712-R115_FINDING_OPERATIONS_QUALIFICATION.json"
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    assertion = dict(qualification); assertion_sha = assertion.pop("receipt_sha256")
    if hashlib.sha256(json.dumps(assertion, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != assertion_sha:
        raise SystemExit("qualification_digest_invalid")
    disabled = {"external_connectors": False, "arbitrary_destination": False, "arbitrary_payload": False,
                "ai_approval": False, "generator_publication": False, "unreviewed_publication": False,
                "unredacted_publication": False, "network_enabled": False}
    lock = {"schema": "redagent.r115-runtime-lock/v1", "enabled_connectors": ["fixture-ticket"],
            "fingerprint_recipe": "redagent-fingerprint-v1", "sarif_version": "2.1.0",
            "ocsf_version": "1.8.0", "cyclonedx_version": "1.6",
            "qualification_assertion_sha256": assertion_sha, **disabled}
    lock_path = config / "r115-finding-operations-runtime.json"
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = {"schema": "redagent.r115-promotion/v1", "scenario_sha256": qualification["scenario_sha256"],
                "qualification_receipt_sha256": hashlib.sha256(qualification_path.read_bytes()).hexdigest(),
                "runtime_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                "fixture_connector_count": 1, "production_qualified": False,
                "author": "engineer-r115", "reviewer": "reviewer-r115", "promoted_at": now.isoformat(),
                "expires_at": (now + timedelta(days=30)).isoformat(), **disabled}
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_path = planning / "260712-R115_FINDING_OPERATIONS_PROMOTION.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    private_path = local / "promotion-key.pem"
    if private_path.exists():
        private = serialization.load_pem_private_key(private_path.read_bytes(), password=password)
    else:
        private = ec.generate_private_key(ec.SECP256R1())
        private_path.write_bytes(private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        ))
    (planning / "260712-R115_FINDING_OPERATIONS_PROMOTION.pub").write_bytes(
        private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    signature = private.sign(content, ec.ECDSA(hashes.SHA256()))
    signature_doc = {"schema": "redagent.ecdsa-p256-signature/v1", "algorithm": "ECDSA_P256_SHA256",
                     "manifest_sha256": hashlib.sha256(content).hexdigest(), "signature_bytes": list(signature)}
    (planning / "260712-R115_FINDING_OPERATIONS_PROMOTION.signature.json").write_text(
        json.dumps(signature_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    print(json.dumps({"status": "signed", "manifest_sha256": signature_doc["manifest_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
