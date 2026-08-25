"""Internal compat_100 registry provisioning for the certified compat_104 artifact."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from redagent_platform.runner_service.repository import RunnerRepository
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from redagent_platform.zap_service.promotion import verify_current_zap_promotion


async def register_zap_capability(
    session, *, workspace: Path, tenant_id: str, actor_user_id: str,
    correlation_id: str, occurred_at: datetime,
) -> dict[str, object]:
    planning = workspace / "runtime-assets" / "attestations"
    receipt, signature_sha256 = verify_current_zap_promotion(
        promotion_bytes=(planning / "260824-R104_ZAP_ARTIFACT_PROMOTION_V2.json").read_bytes(),
        bundle_bytes=(planning / "260824-R104_ZAP_ARTIFACT_PROMOTION_V2.sigstore.json").read_bytes(),
        public_key_bytes=(planning / "260824-R104_ZAP_ARTIFACT_PROMOTION_V2.pub").read_bytes(),
        runtime_lock_bytes=(workspace / "config/r104-zap-runtime-v2.json").read_bytes(),
        qualification_bytes=(
            planning / "260824-R104_ZAP_RUNTIME_QUALIFICATION_V2.json"
        ).read_bytes(),
        now=occurred_at,
    )
    repository = RunnerRepository(
        session, tenant_id=tenant_id, actor_user_id=actor_user_id,
        correlation_id=correlation_id,
    )
    artifact = await repository.register_artifact(
        receipt, signature_sha256=signature_sha256, occurred_at=occurred_at,
    )
    capability = await repository.register_capability(
        build_zap_capability_manifest(
            platform="linux/amd64", artifact_receipt_id=receipt.receipt_id,
        ),
        occurred_at=occurred_at,
    )
    return {
        "artifact_receipt_id": artifact["receipt_id"],
        "image_digest": artifact["image_digest"],
        "capability_id": capability["capability_id"],
        "capability_revision": capability["capability_revision"],
        "manifest_sha256": capability["manifest_sha256"],
    }
