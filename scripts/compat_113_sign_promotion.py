"""Generate the compat_113 runtime lock and ECDSA P-256 signed promotion."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "runtime-assets/attestations/260712-R113_AGENT_KERNEL_QUALIFICATION.json"
LOCK = ROOT / "config/r113-agent-kernel-runtime.json"
PRIVATE = ROOT / ".local/redagent/r113-agent/promotion.key"
PUBLIC = ROOT / "runtime-assets/attestations/260712-R113_AGENT_KERNEL_PROMOTION.pub"
MANIFEST = ROOT / "runtime-assets/attestations/260712-R113_AGENT_KERNEL_PROMOTION.json"
SIGNATURE = ROOT / "runtime-assets/attestations/260712-R113_AGENT_KERNEL_PROMOTION.signature.json"

password = os.environ.get("R113_SIGNING_PASSWORD", "").encode()
if len(password) < 32:
    raise SystemExit("r113_signing_password_required")
qualification = json.loads(QUALIFICATION.read_text(encoding="utf-8"))
if (
    qualification.get("status") != "passed"
    or qualification.get("projected_capability_count") != 9
    or qualification.get("adversarial_case_count") != qualification.get("denied_case_count")
    or any(qualification.get(name) != 0 for name in (
        "external_contact_count", "direct_dispatch_count", "sensitive_retention_count",
    ))
):
    raise SystemExit("r113_qualification_required")

lock = {
    "schema": "redagent.r113-runtime-lock/v1",
    "registry_sha256": qualification["registry_sha256"],
    "qualification_receipt_sha256": hashlib.sha256(QUALIFICATION.read_bytes()).hexdigest(),
    "qualification_assertion_sha256": qualification["receipt_sha256"],
    "enabled_providers": ["deterministic-fake"],
    "openai_adapter_state": "disabled-until-separately-qualified",
    "projected_capability_count": 9,
    "external_model_calls": False,
    "provider_storage": False,
    "background_mode": False,
    "parallel_tool_calls": False,
    "hosted_tools": False,
    "mcp": False,
    "direct_runner_dispatch": False,
    "sensitive_trace_capture": False,
}
LOCK.parent.mkdir(parents=True, exist_ok=True)
LOCK.write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
now = datetime.now(timezone.utc).replace(microsecond=0)
manifest = {
    "schema": "redagent.r113-promotion/v1",
    "runtime_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
    "source_sha256": lock["registry_sha256"],
    "qualification_receipt_sha256": lock["qualification_receipt_sha256"],
    "enabled_providers": ["deterministic-fake"],
    "projected_capability_count": 9,
    "external_model_calls": False,
    "provider_storage": False,
    "background_mode": False,
    "parallel_tool_calls": False,
    "hosted_tools": False,
    "mcp": False,
    "direct_runner_dispatch": False,
    "sensitive_trace_capture": False,
    "critical_vulnerability_count": 0,
    "production_qualified": False,
    "author": "redagent-r113-author",
    "reviewer": "redagent-r113-reviewer",
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
MANIFEST.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
SIGNATURE.write_text(json.dumps({
    "schema": "redagent.ecdsa-p256-signature/v1", "algorithm": "ECDSA_P256_SHA256",
    "manifest_sha256": hashlib.sha256(content).hexdigest(), "signature_bytes": list(signature),
}, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
