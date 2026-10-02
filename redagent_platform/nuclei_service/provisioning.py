"""Register the verified compat_105 engine and capability in the compat_100 registry."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from redagent_platform.nuclei_service.artifact_promotion import (
    verify_current_nuclei_artifact_promotion,
)
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.runner_service.repository import RunnerRepository


async def register_nuclei_capability(
    session, *, workspace: Path, tenant_id: str, actor_user_id: str,
    correlation_id: str, occurred_at: datetime,
) -> dict[str, object]:
    planning = workspace / "runtime-assets" / "attestations"
    receipt, signature_sha256 = verify_current_nuclei_artifact_promotion(
        promotion_bytes=(planning / "261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.json").read_bytes(),
        signature_bundle_bytes=(planning / "261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.sigstore.json").read_bytes(),
        public_key_bytes=(planning / "261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.pub").read_bytes(),
        runtime_lock_bytes=(workspace / "config/r105-nuclei-runtime-v3.json").read_bytes(),
        qualification_bytes=(
            planning / "261002-R105_NUCLEI_RUNTIME_QUALIFICATION_V3.json"
        ).read_bytes(),
        now=occurred_at,
    )
    repository = RunnerRepository(session, tenant_id=tenant_id, actor_user_id=actor_user_id,
                                  correlation_id=correlation_id)
    artifact = await repository.register_artifact(receipt, signature_sha256=signature_sha256,
                                                  occurred_at=occurred_at)
    capability = await repository.register_capability(build_nuclei_capability_manifest(
        platform="linux/amd64", artifact_receipt_id=receipt.receipt_id), occurred_at=occurred_at)
    return {"artifact_receipt_id": artifact["receipt_id"], "image_digest": artifact["image_digest"],
            "capability_id": capability["capability_id"],
            "capability_revision": capability["capability_revision"],
            "manifest_sha256": capability["manifest_sha256"]}
