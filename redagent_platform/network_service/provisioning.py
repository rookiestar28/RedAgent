"""Register the signed compat_107 worker artifact and closed capability in R100."""

from datetime import datetime
from pathlib import Path

from redagent_platform.network_service.capability import build_network_capability_manifest
from redagent_platform.network_service.promotion import verify_network_promotion
from redagent_platform.runner_service.repository import RunnerRepository


async def register_network_capability(
    session, *, workspace: Path, tenant_id: str, actor_user_id: str,
    correlation_id: str, occurred_at: datetime,
) -> dict[str, object]:
    # CRITICAL: registry state is derived only from the current signed compat_107 promotion.
    promotion = verify_network_promotion(workspace, now=occurred_at)
    repository = RunnerRepository(
        session, tenant_id=tenant_id, actor_user_id=actor_user_id,
        correlation_id=correlation_id,
    )
    artifact = await repository.register_artifact(
        promotion.receipt, signature_sha256=promotion.signature_sha256,
        occurred_at=occurred_at,
    )
    capability = await repository.register_capability(
        build_network_capability_manifest(artifact_receipt_id=promotion.receipt.receipt_id),
        occurred_at=occurred_at,
    )
    return {
        "artifact_receipt_id": artifact["receipt_id"],
        "image_digest": artifact["image_digest"],
        "capability_id": capability["capability_id"],
        "capability_revision": capability["capability_revision"],
        "manifest_sha256": capability["manifest_sha256"],
    }
