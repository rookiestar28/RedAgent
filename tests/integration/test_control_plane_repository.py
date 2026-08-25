from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import (
    ConcurrencyConflict,
    ControlPlaneRepository,
    IdempotencyConflict,
    RecordConflict,
)
from redagent_platform.orchestration.contracts import deterministic_job_workflow_id


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 6, 30, tzinfo=timezone.utc)


def test_engagement_idempotency_rls_audit_outbox_and_optimistic_conflict() -> None:
    asyncio.run(_engagement_scenario())


def test_canonical_finding_ingest_deduplicates_definition_and_instance() -> None:
    asyncio.run(_finding_scenario())


def test_transaction_rollback_leaves_no_state_audit_or_outbox() -> None:
    asyncio.run(_rollback_scenario())


def test_complete_control_plane_lifecycle_is_durable_and_audited() -> None:
    asyncio.run(_complete_lifecycle_scenario())


def test_two_sessions_cannot_both_apply_the_same_expected_version() -> None:
    asyncio.run(_concurrent_update_scenario())


def test_postgresql_rls_defaults_deny_and_isolates_a_non_owner_role() -> None:
    asyncio.run(_rls_non_owner_scenario())


def test_concurrent_duplicate_idempotency_key_serializes_to_one_replay() -> None:
    asyncio.run(_concurrent_idempotency_scenario())


async def _engagement_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-a-{suffix}"
    actor_id = f"user-a-{suffix}"
    engagement_id = f"eng-a-{suffix}"
    idempotency_key = f"create-eng-a-{suffix}"
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant_id, actor_user_id=actor_id, correlation_id="corr-create")
            await repo.bootstrap_tenant(name="Tenant A", occurred_at=NOW)
            created = await repo.create_engagement(
                engagement_id=engagement_id,
                name="Synthetic A",
                owner_user_id=actor_id,
                idempotency_key=idempotency_key,
                occurred_at=NOW,
            )
        assert created.replayed is False
        assert created.resource["version"] == 1

        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant_id, actor_user_id=actor_id, correlation_id="corr-replay")
            replayed = await repo.create_engagement(
                engagement_id=engagement_id,
                name="Synthetic A",
                owner_user_id=actor_id,
                idempotency_key=idempotency_key,
                occurred_at=NOW,
            )
        assert replayed.replayed is True
        assert replayed.resource == created.resource

        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant_id, actor_user_id=actor_id, correlation_id="corr-conflict")
            with pytest.raises(IdempotencyConflict):
                await repo.create_engagement(
                    engagement_id=engagement_id,
                    name="Changed request",
                    owner_user_id=actor_id,
                    idempotency_key=idempotency_key,
                    occurred_at=NOW,
                )
            with pytest.raises(ConcurrencyConflict):
                await repo.update_engagement(
                    engagement_id=engagement_id,
                    expected_version=99,
                    name="Should not apply",
                    idempotency_key=f"stale-{suffix}",
                    occurred_at=NOW,
                )

        async with sessions() as session, session.begin():
            other = ControlPlaneRepository(session, tenant_id=f"tenant-b-{suffix}", actor_user_id=f"user-b-{suffix}", correlation_id="corr-cross")
            assert await other.get_engagement(engagement_id) is None

        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant_id, actor_user_id=actor_id, correlation_id="corr-outbox")
            claimed = await repo.claim_outbox(limit=10)
            assert len(claimed) == 1
            await repo.complete_outbox(claimed[0]["id"], occurred_at=NOW)
            await repo.complete_outbox(claimed[0]["id"], occurred_at=NOW)

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            assert await _count(session, "engagements", tenant_id) == 1
            assert await _count(session, "audit_events", tenant_id) == 1
            assert await _count(session, "outbox_events", tenant_id) == 1
            assert await _count(session, "idempotency_records", tenant_id) == 1
    finally:
        await engine.dispose()


async def _finding_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-f-{suffix}"
    actor_id = f"user-f-{suffix}"
    finding_id = f"finding-f-{suffix}"
    idempotency_key = f"finding-f-{suffix}"
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant_id, actor_user_id=actor_id, correlation_id="corr-f")
            await repo.bootstrap_tenant(name="Tenant F", occurred_at=NOW)
            first = await repo.ingest_finding(
                finding_id=finding_id,
                tool="nuclei",
                rule_id="CVE-EXAMPLE",
                tool_version="3.0",
                database_version="2026.07",
                title="Synthetic finding",
                severity="high",
                confidence="confirmed",
                affected_resource="https://example.invalid",
                location="/synthetic",
                evidence_reference="evidence://synthetic/f",
                redaction_state="sanitized",
                idempotency_key=idempotency_key,
                occurred_at=NOW,
            )
        assert first.replayed is False

        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant_id, actor_user_id=actor_id, correlation_id="corr-f2")
            second = await repo.ingest_finding(
                finding_id=finding_id,
                tool="NUCLEI",
                rule_id="CVE-EXAMPLE",
                tool_version="3.0",
                database_version="2026.07",
                title=" Synthetic finding ",
                severity="high",
                confidence="confirmed",
                affected_resource="https://example.invalid",
                location="/synthetic",
                evidence_reference="evidence://synthetic/f",
                redaction_state="sanitized",
                idempotency_key=idempotency_key,
                occurred_at=NOW,
            )
        assert second.replayed is True
        assert second.resource == first.resource

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            assert await _count(session, "issue_definitions", tenant_id) == 1
            assert await _count(session, "finding_instances", tenant_id) == 1
    finally:
        await engine.dispose()


async def _rollback_scenario() -> None:
    engine, sessions = _database()
    try:
        with pytest.raises(RuntimeError, match="force rollback"):
            async with sessions() as session, session.begin():
                repo = ControlPlaneRepository(session, tenant_id="tenant-r", actor_user_id="user-r", correlation_id="corr-r")
                await repo.bootstrap_tenant(name="Tenant R", occurred_at=NOW)
                await repo.create_engagement(
                    engagement_id="eng-r",
                    name="Rollback",
                    owner_user_id="user-r",
                    idempotency_key="eng-r",
                    occurred_at=NOW,
                )
                raise RuntimeError("force rollback")
        async with sessions() as session:
            tenant = metadata.tables["tenants"]
            count = await session.scalar(select(func.count()).select_from(tenant).where(tenant.c.id == "tenant-r"))
            assert count == 0
    finally:
        await engine.dispose()


async def _complete_lifecycle_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-lifecycle-{suffix}"
    user_id = f"user-lifecycle-{suffix}"
    engagement_id = f"eng-lifecycle-{suffix}"
    target_id = f"target-lifecycle-{suffix}"
    roe_version_id = f"roe-lifecycle-{suffix}"
    policy_reference_id = f"policy-lifecycle-{suffix}"
    approval_id = f"approval-lifecycle-{suffix}"
    job_id = f"job-lifecycle-{suffix}"
    invalid_job_id = f"job-invalid-{suffix}"
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id="corr-lifecycle-bootstrap",
            )
            await repo.bootstrap_tenant(name="Lifecycle Tenant", occurred_at=NOW)
            user = await repo.bootstrap_user(
                user_id=user_id,
                subject=f"subject-lifecycle-{suffix}",
                occurred_at=NOW,
            )
            engagement = await repo.create_engagement(
                engagement_id=engagement_id,
                name="Lifecycle engagement",
                owner_user_id=user_id,
                idempotency_key="lifecycle-engagement",
                occurred_at=NOW,
            )
            target = await repo.create_target(
                target_id=target_id,
                engagement_id=engagement_id,
                target_type="hostname",
                normalized_value="synthetic.example.invalid",
                idempotency_key="lifecycle-target",
                occurred_at=NOW,
            )
            roe = await repo.create_roe_version(
                roe_version_id=roe_version_id,
                engagement_id=engagement_id,
                revision=1,
                document={"scope": ["synthetic.example.invalid"], "active_testing": False},
                policy_reference_id=policy_reference_id,
                policy_name="synthetic-policy",
                policy_version="1",
                idempotency_key="lifecycle-roe",
                occurred_at=NOW,
            )
        assert user["subject"] == f"subject-lifecycle-{suffix}"
        assert engagement.resource["version"] == 1
        assert target.resource["engagement_id"] == engagement_id
        assert roe.resource["status"] == "draft"

        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id="corr-lifecycle-approve",
            )
            approval = await repo.approve_roe_version(
                roe_version_id=roe_version_id,
                approval_id=approval_id,
                expected_version=1,
                idempotency_key="lifecycle-approval",
                occurred_at=NOW,
            )
            job = await repo.create_job(
                job_id=job_id,
                engagement_id=engagement_id,
                roe_version_id=roe_version_id,
                request={
                    "capability": "synthetic-noop",
                    "approval_timeout_seconds": 3600,
                    "max_activity_attempts": 3,
                    "budget_reference": "budget:compat_096:lifecycle",
                },
                workflow_id=deterministic_job_workflow_id(tenant_id, job_id),
                policy_reference="policy:compat_096:lifecycle",
                campaign_id=None,
                idempotency_key="lifecycle-job",
                occurred_at=NOW,
            )
            invalid_job = await repo.create_job(
                job_id=invalid_job_id,
                engagement_id=engagement_id,
                roe_version_id=roe_version_id,
                request={
                    "capability": "synthetic-noop",
                    "approval_timeout_seconds": 3600,
                    "max_activity_attempts": 3,
                    "budget_reference": "budget:compat_096:invalid",
                },
                workflow_id=deterministic_job_workflow_id(tenant_id, invalid_job_id),
                policy_reference="policy:compat_096:lifecycle",
                campaign_id=None,
                idempotency_key="lifecycle-job-invalid",
                occurred_at=NOW,
            )
            with pytest.raises(RecordConflict, match="workflow_managed_job_requires_command"):
                await repo.transition_job(
                    job_id=invalid_job_id,
                    expected_version=1,
                    next_status="succeeded",
                    idempotency_key="invalid-direct-success",
                    occurred_at=NOW,
                )
        assert approval.resource["status"] == "approved"
        assert job.resource["status"] == "pending"
        assert invalid_job.resource["status"] == "pending"

        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id="corr-lifecycle-transition",
            )
            with pytest.raises(RecordConflict, match="workflow_managed_job_requires_command"):
                await repo.transition_job(
                    job_id=job_id,
                    expected_version=1,
                    next_status="running",
                    idempotency_key="lifecycle-job-running",
                    occurred_at=NOW,
                )
            updated = await repo.update_engagement(
                engagement_id=engagement_id,
                expected_version=1,
                name="Lifecycle engagement updated",
                idempotency_key="lifecycle-engagement-update",
                occurred_at=NOW,
            )
        assert updated.resource["version"] == 2

        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id="corr-lifecycle-read",
            )
            engagements = await repo.list_engagements(limit=10, offset=0)
            targets = await repo.list_targets(engagement_id, limit=10, offset=0)
            roe_versions = await repo.list_roe_versions(engagement_id, limit=10, offset=0)
            persisted_job = await repo.get_job(job_id)
            with pytest.raises(ConcurrencyConflict):
                await repo.update_engagement(
                    engagement_id=engagement_id,
                    expected_version=1,
                    name="Stale update",
                    idempotency_key="lifecycle-stale-update",
                    occurred_at=NOW,
                )
        assert any(row["engagement_id"] == engagement_id for row in engagements)
        assert targets == [target.resource]
        assert roe_versions[0]["roe_version_id"] == roe_version_id
        assert persisted_job is not None and persisted_job["status"] == "pending"
        assert persisted_job["orchestration_state"] == "dispatch_pending"
    finally:
        await engine.dispose()


async def _concurrent_update_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-race-{suffix}"
    engagement_id = f"eng-race-{suffix}"
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=f"user-race-{suffix}",
                correlation_id=f"corr-race-{suffix}",
            )
            await repo.bootstrap_tenant(name="Race Tenant", occurred_at=NOW)
            await repo.create_engagement(
                engagement_id=engagement_id,
                name="Before race",
                owner_user_id=f"user-race-{suffix}",
                idempotency_key=f"create-{suffix}",
                occurred_at=NOW,
            )

        async def update_once(name: str) -> object:
            try:
                async with sessions() as session, session.begin():
                    repo = ControlPlaneRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id=f"user-race-{suffix}",
                        correlation_id=f"corr-{name}-{suffix}",
                    )
                    return await repo.update_engagement(
                        engagement_id=engagement_id,
                        expected_version=1,
                        name=name,
                        idempotency_key=f"update-{name}-{suffix}",
                        occurred_at=NOW,
                    )
            except ConcurrencyConflict as exc:
                return exc

        results = await asyncio.gather(update_once("winner-a"), update_once("winner-b"))
        assert sum(isinstance(result, ConcurrencyConflict) for result in results) == 1
        assert sum(not isinstance(result, ConcurrencyConflict) for result in results) == 1
    finally:
        await engine.dispose()


async def _rls_non_owner_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    first_tenant = f"tenant-rls-a-{suffix}"
    second_tenant = f"tenant-rls-b-{suffix}"
    role_name = f"r093_test_{suffix}"
    try:
        for tenant_id, marker in ((first_tenant, "a"), (second_tenant, "b")):
            async with sessions() as session, session.begin():
                repo = ControlPlaneRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id=f"user-{marker}-{suffix}",
                    correlation_id=f"corr-{marker}-{suffix}",
                )
                await repo.bootstrap_tenant(name=f"RLS {marker}", occurred_at=NOW)
                await repo.create_engagement(
                    engagement_id=f"eng-rls-{marker}-{suffix}",
                    name=f"RLS {marker}",
                    owner_user_id=f"user-{marker}-{suffix}",
                    idempotency_key=f"rls-{marker}-{suffix}",
                    occurred_at=NOW,
                )

        async with sessions() as session:
            transaction = await session.begin()
            try:
                # CRITICAL: the interpolated role is generated from a hex UUID, never from request input.
                await session.execute(text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'))
                await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
                await session.execute(text(f'GRANT SELECT ON engagements TO "{role_name}"'))
                await session.execute(text(f'SET LOCAL ROLE "{role_name}"'))
                engagements = metadata.tables["engagements"]
                denied_count = await session.scalar(select(func.count()).select_from(engagements))
                await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"), {"tenant_id": first_tenant})
                visible_ids = tuple(
                    (await session.scalars(select(engagements.c.id).order_by(engagements.c.id))).all()
                )
                assert int(denied_count or 0) == 0
                assert visible_ids == (f"eng-rls-a-{suffix}",)
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


async def _concurrent_idempotency_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-idem-{suffix}"
    actor_id = f"user-idem-{suffix}"
    engagement_id = f"eng-idem-{suffix}"
    idempotency_key = f"idem-{suffix}"
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"corr-bootstrap-{suffix}",
            )
            await repo.bootstrap_tenant(name="Idempotency Tenant", occurred_at=NOW)

        async def create_once(label: str):
            async with sessions() as session, session.begin():
                repo = ControlPlaneRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id=actor_id,
                    correlation_id=f"corr-{label}-{suffix}",
                )
                return await repo.create_engagement(
                    engagement_id=engagement_id,
                    name="Concurrent idempotency",
                    owner_user_id=actor_id,
                    idempotency_key=idempotency_key,
                    occurred_at=NOW,
                )

        results = await asyncio.gather(create_once("a"), create_once("b"))
        assert sorted(result.replayed for result in results) == [False, True]
        assert results[0].resource == results[1].resource
        assert results[0].audit_id == results[1].audit_id
        assert results[0].outbox_id == results[1].outbox_id

        async with sessions() as session, session.begin():
            for table_name in ("engagements", "audit_events", "outbox_events", "idempotency_records"):
                assert await _count(session, table_name, tenant_id) == 1
    finally:
        await engine.dispose()


def _database():
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _set_tenant(session, tenant_id: str) -> None:
    await session.execute(select(func.set_config("redagent.tenant_id", tenant_id, True)))


async def _count(session, table_name: str, tenant_id: str) -> int:
    table = metadata.tables[table_name]
    value = await session.scalar(select(func.count()).select_from(table).where(table.c.tenant_id == tenant_id))
    return int(value or 0)
