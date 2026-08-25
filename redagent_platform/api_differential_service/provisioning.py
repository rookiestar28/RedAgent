"""Register the signed compat_106 engine artifact and closed capability in R100."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from redagent_platform.api_differential_service.capability import (
    build_api_differential_capability_manifest,
)
from redagent_platform.api_differential_service.promotion import (
    verify_api_differential_promotion,
)
from redagent_platform.runner_service.repository import RunnerRepository


async def register_api_differential_capability(
    session, *, workspace: Path, tenant_id: str, actor_user_id: str,
    correlation_id: str, occurred_at: datetime,
) -> dict[str, object]:
    # CRITICAL: registry state must be derived from the currently valid signed bundle, never caller claims.
    receipt, _, _, signature_sha256 = verify_api_differential_promotion(
        workspace, now=occurred_at,
    )
    repository = RunnerRepository(
        session, tenant_id=tenant_id, actor_user_id=actor_user_id,
        correlation_id=correlation_id,
    )
    artifact = await repository.register_artifact(
        receipt, signature_sha256=signature_sha256, occurred_at=occurred_at,
    )
    capability = await repository.register_capability(
        build_api_differential_capability_manifest(artifact_receipt_id=receipt.receipt_id),
        occurred_at=occurred_at,
    )
    return {
        "artifact_receipt_id": artifact["receipt_id"],
        "image_digest": artifact["image_digest"],
        "capability_id": capability["capability_id"],
        "capability_revision": capability["capability_revision"],
        "manifest_sha256": capability["manifest_sha256"],
    }
