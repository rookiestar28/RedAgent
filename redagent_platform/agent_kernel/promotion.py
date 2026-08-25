"""Verify signed compat_113 fake-provider runtime lock and no-authority qualification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from redagent_platform.runner_service.contracts import ArtifactVerificationReceipt


@dataclass(frozen=True, kw_only=True)
class AgentKernelPromotionReceipt:
    receipt: ArtifactVerificationReceipt
    manifest_sha256: str
    signature_sha256: str
    runtime_lock_sha256: str
    projected_capability_count: int


def verify_agent_kernel_promotion(workspace: Path, *, now: datetime) -> AgentKernelPromotionReceipt:
    planning = workspace / "runtime-assets" / "attestations"
    manifest_path = planning / "260712-R113_AGENT_KERNEL_PROMOTION.json"
    signature_path = planning / "260712-R113_AGENT_KERNEL_PROMOTION.signature.json"
    public_path = planning / "260712-R113_AGENT_KERNEL_PROMOTION.pub"
    lock_path = workspace / "config/r113-agent-kernel-runtime.json"
    qualification_path = planning / "260712-R113_AGENT_KERNEL_QUALIFICATION.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature = json.loads(signature_path.read_text(encoding="utf-8"))
        public_bytes = public_path.read_bytes()
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("agent_promotion_input_invalid") from exc
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_sha = hashlib.sha256(content).hexdigest()
    lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    qualification_sha = hashlib.sha256(qualification_path.read_bytes()).hexdigest()
    assertion = dict(qualification)
    asserted_sha = assertion.pop("receipt_sha256", None)
    computed_sha = hashlib.sha256(json.dumps(assertion, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    zero_counters = ("external_contact_count", "direct_dispatch_count", "sensitive_retention_count")
    if (
        manifest.get("schema") != "redagent.r113-promotion/v1"
        or manifest.get("runtime_lock_sha256") != lock_sha
        or manifest.get("source_sha256") != lock.get("registry_sha256")
        or manifest.get("qualification_receipt_sha256") != qualification_sha
        or lock.get("qualification_assertion_sha256") != asserted_sha
        or asserted_sha != computed_sha
        or qualification.get("status") != "passed"
        or any(qualification.get(name) != 0 for name in zero_counters)
        or qualification.get("projected_capability_count") != 9
        or qualification.get("adversarial_case_count") != qualification.get("denied_case_count")
        or lock.get("enabled_providers") != ["deterministic-fake"]
        or lock.get("projected_capability_count") != 9
        or any(lock.get(name) is not False for name in (
            "external_model_calls", "provider_storage", "background_mode", "parallel_tool_calls",
            "hosted_tools", "mcp", "direct_runner_dispatch", "sensitive_trace_capture",
        ))
        or any(manifest.get(name) is not False for name in (
            "external_model_calls", "provider_storage", "background_mode", "parallel_tool_calls",
            "hosted_tools", "mcp", "direct_runner_dispatch", "sensitive_trace_capture", "production_qualified",
        ))
        or manifest.get("critical_vulnerability_count") != 0
        or manifest.get("author") == manifest.get("reviewer")
        or signature.get("schema") != "redagent.ecdsa-p256-signature/v1"
        or signature.get("algorithm") != "ECDSA_P256_SHA256"
        or signature.get("manifest_sha256") != manifest_sha
    ):
        raise ValueError("agent_promotion_safety_invalid")
    promoted_at = _time(manifest.get("promoted_at"))
    expires_at = _time(manifest.get("expires_at"))
    if now.tzinfo is None or now.utcoffset() is None or not promoted_at <= now < expires_at:
        raise ValueError("agent_promotion_inactive")
    try:
        public = serialization.load_pem_public_key(public_bytes)
        values = signature["signature_bytes"]
        if (
            not isinstance(public, ec.EllipticCurvePublicKey)
            or not isinstance(public.curve, ec.SECP256R1)
            or not isinstance(values, list)
            or any(not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 255 for item in values)
        ):
            raise ValueError
        public.verify(bytes(values), content, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise ValueError("agent_promotion_signature_invalid") from exc
    receipt = ArtifactVerificationReceipt(
        receipt_id=f"r113-agent-{manifest_sha[:24]}", image_digest=f"sha256:{manifest['source_sha256']}",
        signature_verified=True, signer_identity=f"ecdsa-p256:{hashlib.sha256(public_bytes).hexdigest()[:32]}",
        provenance_sha256=manifest_sha, sbom_sha256=lock_sha,
        vulnerability_review="accepted_no_critical", verifier="redagent-r113-promotion-verifier",
        verified_at=promoted_at, expires_at=expires_at,
    )
    return AgentKernelPromotionReceipt(
        receipt=receipt, manifest_sha256=manifest_sha,
        signature_sha256=hashlib.sha256(signature_path.read_bytes()).hexdigest(),
        runtime_lock_sha256=lock_sha, projected_capability_count=9,
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("agent_promotion_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("agent_promotion_time_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("agent_promotion_time_invalid")
    return parsed
