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
    password = os.environ.get("R114_SIGNING_PASSWORD", "").encode()
    if len(password) < 20:
        raise SystemExit("signing_password_required")
    planning = ROOT / "runtime-assets" / "attestations"
    local = ROOT / ".local/redagent/r114"
    config = ROOT / "config"
    local.mkdir(parents=True, exist_ok=True); config.mkdir(parents=True, exist_ok=True)
    qualification_path = planning / "260712-R114_MCP_WORKBENCH_QUALIFICATION.json"
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    assertion = dict(qualification); assertion_sha = assertion.pop("receipt_sha256")
    if hashlib.sha256(json.dumps(assertion, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != assertion_sha:
        raise SystemExit("qualification_digest_invalid")
    lock = {"schema": "redagent.r114-runtime-lock/v1", "protocol_version": "2025-11-25",
            "enabled_transports": ["in_process"], "inventory_sha256": qualification["inventory_sha256"],
            "qualification_assertion_sha256": assertion_sha, "remote_http": False, "stdio": False,
            "provider_mcp": False, "dynamic_discovery": False, "dynamic_registration": False,
            "token_passthrough": False, "ambient_environment": False, "direct_runner_dispatch": False,
            "sensitive_retention": False}
    lock_path = config / "r114-mcp-workbench-runtime.json"
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = {"schema": "redagent.r114-promotion/v1", "source_sha256": qualification["inventory_sha256"],
                "qualification_receipt_sha256": hashlib.sha256(qualification_path.read_bytes()).hexdigest(),
                "runtime_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                "protocol_version": "2025-11-25", "fixture_inventory_count": 2,
                "remote_http": False, "stdio": False, "provider_mcp": False, "dynamic_discovery": False,
                "dynamic_registration": False, "token_passthrough": False, "ambient_environment": False,
                "direct_runner_dispatch": False, "sensitive_retention": False, "production_qualified": False,
                "critical_vulnerability_count": 0, "author": "engineer-r114", "reviewer": "reviewer-r114",
                "promoted_at": now.isoformat(), "expires_at": (now + timedelta(days=30)).isoformat()}
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_path = planning / "260712-R114_MCP_WORKBENCH_PROMOTION.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    private_path = local / "promotion-key.pem"
    if private_path.exists():
        private = serialization.load_pem_private_key(private_path.read_bytes(), password=password)
    else:
        private = ec.generate_private_key(ec.SECP256R1())
        private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.BestAvailableEncryption(password)))
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (planning / "260712-R114_MCP_WORKBENCH_PROMOTION.pub").write_bytes(public)
    signature = private.sign(content, ec.ECDSA(hashes.SHA256()))
    signature_doc = {"schema": "redagent.ecdsa-p256-signature/v1", "algorithm": "ECDSA_P256_SHA256",
                     "manifest_sha256": hashlib.sha256(content).hexdigest(), "signature_bytes": list(signature)}
    (planning / "260712-R114_MCP_WORKBENCH_PROMOTION.signature.json").write_text(
        json.dumps(signature_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "signed", "manifest_sha256": signature_doc["manifest_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
