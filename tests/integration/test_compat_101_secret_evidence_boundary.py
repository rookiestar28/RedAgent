from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
from uuid import uuid4

from redagent_platform.containment_service.contracts import ContainmentOutcome, ContainmentPhase
from redagent_platform.containment_service.coordinator import CallbackContainmentBackend, ContainmentCoordinator
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.contracts import ObjectPutRequest, RetentionMode, content_sha256
from redagent_platform.secret_service.fakes import DeterministicFakeSecretProvider


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 20, 0, tzinfo=timezone.utc)


def test_exact_provider_revoke_and_evidence_version_lock_are_real_independent_phases() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    suffix = uuid4().hex[:10]
    provider = DeterministicFakeSecretProvider(seed=f"r101-{suffix}")
    issued = await provider.issue("database-role-r101")
    with issued.material.expose_once():
        pass
    root = ROOT / ".local" / "redagent" / f"r101-boundary-{suffix}"
    backend = LocalAppendOnlyBackend(root, profile="synthetic-local")
    content = b'{"fixture":"r101-partial-evidence"}'
    object_key = f"tenants/synthetic/jobs/compat_101/artifacts/{suffix}"
    stored = backend.put(ObjectPutRequest(
        object_key=object_key, content=content, content_type="application/json",
        content_sha256=content_sha256(content), retention_mode=RetentionMode.COMPLIANCE.value,
        retain_until=(NOW + timedelta(days=30)).isoformat(), legal_hold=False,
        kms_reference="kms:r101-synthetic", operation_id=f"operation-{suffix}",
    ))
    observed: list[ContainmentPhase] = []

    def simple(phase: ContainmentPhase):
        async def callback() -> bool:
            observed.append(phase)
            return True
        return callback

    async def revoke() -> bool:
        observed.append(ContainmentPhase.LEASE_REVOCATION)
        await provider.revoke_sync(issued.provider_lease_reference)
        return not (await provider.lookup_status(issued.provider_lease_reference)).active

    async def lock_evidence() -> bool:
        observed.append(ContainmentPhase.EVIDENCE_LOCK)
        backend.place_legal_hold(stored.object_key, stored.version_id)
        backend.place_legal_hold(stored.object_key, stored.version_id)
        marker = backend.holds / f"{stored.storage_name}.{stored.version_id}.hold"
        return marker.read_text(encoding="utf-8") == "ON\n"

    callbacks = {phase: simple(phase) for phase in ContainmentPhase}
    callbacks[ContainmentPhase.LEASE_REVOCATION] = revoke
    callbacks[ContainmentPhase.EVIDENCE_LOCK] = lock_evidence
    try:
        result = await ContainmentCoordinator(
            CallbackContainmentBackend(callbacks), clock=lambda: NOW,
        ).contain()
        assert result.assessment.outcome is ContainmentOutcome.CONTAINED
        assert observed == list(ContainmentPhase)
        assert not (await provider.lookup_status(issued.provider_lease_reference)).active
        assert backend.verify_exact(stored).ok
    finally:
        # Cleanup is restricted to the generated ignored workspace-local fixture root.
        shutil.rmtree(root, ignore_errors=True)
