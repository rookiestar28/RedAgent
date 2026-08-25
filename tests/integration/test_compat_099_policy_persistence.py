from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.policy_service.contracts import (
    PolicyBoundary,
    PolicyDecision,
    PolicyDecisionInput,
    PolicyObligation,
    policy_input_hash,
)
from redagent_platform.policy_service.repository import TransactionalPolicyDecisionRecorder


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc)


def test_postgresql_decision_receipt_audit_outbox_idempotency_and_rls() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r099-{suffix}"
    actor = f"operator-r099-{suffix}"
    request = PolicyDecisionInput(
        boundary=PolicyBoundary.API, action="job.create", tenant_id=tenant, subject_id=actor,
        roles=("operator",), permissions=("job:create",), resource_type="job",
        resource_id=f"job-r099-{suffix}", policy_reference="policy:compat_099:1",
        roe_version_id=f"roe-r099-{suffix}", correlation_id=f"correlation-r099-{suffix}",
        requested_at=NOW, attributes={"job_status": "pending", "resource_version": 1},
    )
    decision = PolicyDecision(
        decision_id=f"opa-r099-{suffix}", bundle_revision="r099-v1",
        input_hash=policy_input_hash(request), allowed=True, reason_code="boundary_authorized",
        obligations=(PolicyObligation.AUDIT, PolicyObligation.REQUIRE_EXPECTED_VERSION),
        issued_at=NOW, valid_until=NOW + timedelta(seconds=30),
    )
    try:
        async with sessions() as session, session.begin():
            repository = ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"bootstrap-r099-{suffix}",
            )
            await repository.bootstrap_tenant(name="compat_099 Policy Tenant", occurred_at=NOW)
            await repository.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)

        recorder = TransactionalPolicyDecisionRecorder(sessions)
        first = await recorder.persist_decision_and_receipt(request, decision, operation="api.job.create")
        replay = await recorder.persist_decision_and_receipt(request, decision, operation="api.job.create")
        assert replay == first

        async with sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
            decision_rows = (
                await session.execute(select(metadata.tables["policy_decisions"]).where(
                    metadata.tables["policy_decisions"].c.tenant_id == tenant,
                ))
            ).mappings().all()
            receipt_rows = (
                await session.execute(select(metadata.tables["policy_boundary_receipts"]).where(
                    metadata.tables["policy_boundary_receipts"].c.tenant_id == tenant,
                ))
            ).mappings().all()
            assert len(decision_rows) == 1 and len(receipt_rows) == 1
            rendered = json.dumps([dict(decision_rows[0]), dict(receipt_rows[0])], default=str, sort_keys=True)
            for forbidden in ("roles", "permissions", "request_body", "rego", "private_key"):
                assert forbidden not in rendered.lower()
            audit_count = await session.scalar(select(metadata.tables["audit_events"].c.id).where(
                metadata.tables["audit_events"].c.tenant_id == tenant,
                metadata.tables["audit_events"].c.action == "policy.decision.allowed",
            ))
            outbox_count = await session.scalar(select(metadata.tables["outbox_events"].c.id).where(
                metadata.tables["outbox_events"].c.tenant_id == tenant,
                metadata.tables["outbox_events"].c.event_type == "policy.decision.allowed",
            ))
            assert audit_count and outbox_count

        role_name = f"r099_test_{suffix}"
        async with sessions() as session:
            transaction = await session.begin()
            try:
                # CRITICAL: the role identifier is generated exclusively from a hex UUID suffix.
                await session.execute(text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'))
                await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
                await session.execute(text(f'GRANT SELECT ON policy_decisions TO "{role_name}"'))
                await session.execute(text(f'SET LOCAL ROLE "{role_name}"'))
                await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": f"other-r099-{suffix}"})
                hidden = await session.scalar(select(metadata.tables["policy_decisions"].c.id).where(
                    metadata.tables["policy_decisions"].c.opa_decision_id == decision.decision_id,
                ))
                assert hidden is None
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()
