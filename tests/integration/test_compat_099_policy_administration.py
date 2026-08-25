from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.policy_service.lifecycle import BundleRevision
from redagent_platform.policy_service.repository import (
    PolicyAdministrationRepository,
    PolicyDecisionConflict,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 15, 0, tzinfo=timezone.utc)
HASH_A = "a" * 64
HASH_B = "b" * 64


def test_bundle_registration_convergence_promotion_sod_and_rollback() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r099-admin-{suffix}"
    promoter = f"promoter-r099-{suffix}"
    try:
        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=promoter,
                correlation_id=f"bootstrap-{suffix}",
            )
            await control.bootstrap_tenant(name="compat_099 Admin Tenant", occurred_at=NOW)
            await control.bootstrap_user(user_id=promoter, subject=promoter, occurred_at=NOW)
            admin = PolicyAdministrationRepository(
                session, tenant_id=tenant, actor_user_id=promoter,
                correlation_id=f"admin-{suffix}",
            )
            v1 = await admin.register_bundle(_bundle("r099-v1", HASH_A), occurred_at=NOW)
            await admin.register_bundle(_bundle("r099-v0", HASH_B), occurred_at=NOW)
            with pytest.raises(PolicyDecisionConflict, match="agent_convergence"):
                await admin.promote(
                    revision="r099-v1", expected_version=1, idempotency_key=f"incomplete-{suffix}",
                    reason="Convergence must be complete before promotion", rollback=False, occurred_at=NOW,
                )

        async with sessions() as session, session.begin():
            admin = PolicyAdministrationRepository(
                session, tenant_id=tenant, actor_user_id=promoter,
                correlation_id=f"agents-{suffix}",
            )
            for boundary in ("api", "workflow", "evidence", "secret", "runner"):
                await admin.record_agent_status(
                    agent_id=f"{boundary}-pdp", boundary=boundary, active_revision="r099-v1",
                    artifact_sha256=HASH_A, bundle_state="OK", error_code=None, occurred_at=NOW,
                )
            promoted = await admin.promote(
                revision="r099-v1", expected_version=int(v1["version"]),
                idempotency_key=f"promote-{suffix}", reason="Reviewed compat_099 policy promotion",
                rollback=False, occurred_at=NOW,
            )
            assert promoted["promotion_state"] == "promoted"

        async with sessions() as session, session.begin():
            admin = PolicyAdministrationRepository(
                session, tenant_id=tenant, actor_user_id=promoter,
                correlation_id=f"rollback-{suffix}",
            )
            for boundary in ("api", "workflow", "evidence", "secret", "runner"):
                await admin.record_agent_status(
                    agent_id=f"{boundary}-pdp", boundary=boundary, active_revision="r099-v0",
                    artifact_sha256=HASH_B, bundle_state="OK", error_code=None, occurred_at=NOW,
                )
            rolled_back = await admin.promote(
                revision="r099-v0", expected_version=1,
                idempotency_key=f"rollback-{suffix}", reason="Rollback after bounded synthetic failure",
                rollback=True, occurred_at=NOW,
            )
            assert rolled_back["promotion_state"] == "rollback_promoted"
            assert rolled_back["previous_revision"] == "r099-v1"
    finally:
        await engine.dispose()


def _bundle(revision: str, artifact_hash: str) -> BundleRevision:
    return BundleRevision(
        revision=revision, source_sha256=HASH_B, artifact_sha256=artifact_hash,
        artifact_size=4096, manifest_roots=("redagent", "system"), rego_version=1,
        signing_key_id="r099-local-key", signing_scope="redagent-policy",
        signing_algorithm="RS256", author_user_id="author-r099", reviewer_user_id="reviewer-r099",
        test_evidence_sha256=HASH_A, conformance_sha256=HASH_B,
        coverage_basis_points=9000, signature_verified=True, status="accepted",
    )
