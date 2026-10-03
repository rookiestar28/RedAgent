from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.application_contracts import (
    APPLICATION_CONTRACT_VERSION,
    ApplicationBindingConflict,
    ApplicationIdempotencyConflict,
    ApplicationRevisionConflict,
    AutonomousCampaignLifecycle,
    AutonomousCampaignNativeRootV1,
    CreateAutonomousCampaignIntentV1,
    RevokeAutonomousCampaignIntentV1,
)
from redagent_platform.campaign_service.application_repository import (
    PostgresAutonomousCampaignApplicationRepository,
)
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0029_autonomous_campaign_application.py"
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)


def test_r171_create_replay_revoke_restart_rls_and_append_only_history() -> None:
    asyncio.run(_lifecycle_scenario())


def test_r171_concurrent_create_replay_has_one_authoritative_event() -> None:
    asyncio.run(_concurrent_scenario())


def test_r171_populated_downgrade_guard_is_rls_independent_for_non_bypass_owner() -> None:
    asyncio.run(_non_bypass_owner_downgrade_guard_scenario())


def test_operator_native_root_is_atomic_effect_free_and_concurrently_replayable() -> None:
    asyncio.run(_operator_native_root_scenario())


@pytest.mark.parametrize("mutation", ["engagement", "target", "roe", "inactive"])
def test_operator_native_root_rejects_current_owner_drift_without_partial_intent(mutation: str) -> None:
    asyncio.run(_operator_native_root_scenario(mutation=mutation))


def test_operator_native_root_rolls_back_with_application_audit_failure(monkeypatch) -> None:
    asyncio.run(_operator_native_root_scenario(monkeypatch=monkeypatch))


def test_operator_native_root_replay_inactive_principal_is_denied_inside_native_transaction():
    asyncio.run(_operator_native_root_scenario(replay_inactive=True))


async def _operator_native_root_scenario(*, mutation=None, monkeypatch=None, replay_inactive=False) -> None:
    from redagent_platform.persistence.repository import ControlPlaneRepository

    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-operator-{suffix}"
    try:
        actor, engagement, target = await _bootstrap(sessions, tenant=tenant, suffix=suffix)
        roe_id = f"roe-{suffix}"
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            await session.execute(insert(metadata.tables["tenant_memberships"]).values(
                id=f"membership-{suffix}", user_id=actor, tenant_id=tenant,
                status="inactive" if mutation == "inactive" else "active",
                generation=1, last_validated_at=NOW, version=1, created_at=NOW, updated_at=NOW,
            ))
            owner = ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"root-{suffix}",
            )
            await owner.create_roe_version(
                roe_version_id=roe_id, engagement_id=engagement, revision=1,
                document={"scope": ["owned-loopback"], "active_testing": True},
                policy_reference_id=f"policy-{suffix}", policy_name="owned-loopback",
                policy_version="1", idempotency_key=f"roe-{suffix}", occurred_at=NOW,
            )
            if mutation != "roe":
                await owner.approve_roe_version(
                    roe_version_id=roe_id, approval_id=f"approval-{suffix}",
                    expected_version=1, idempotency_key=f"approve-{suffix}", occurred_at=NOW,
                )
        command = replace(
            _create_command(tenant=tenant, actor=actor, engagement=engagement, target=target, suffix=suffix),
            native_root=AutonomousCampaignNativeRootV1(
                name="Assess HTTP security posture",
                engagement_revision=2 if mutation == "engagement" else 1,
                target_revision=2 if mutation == "target" else 1,
                roe_revision=1,
            ),
        )
        repository = PostgresAutonomousCampaignApplicationRepository(sessions)
        if monkeypatch is not None:
            import redagent_platform.campaign_service.application_repository as application_repository

            async def fail_audit(*_args, **_kwargs):
                raise RuntimeError("operator_audit_failed")

            monkeypatch.setattr(application_repository, "_record_mutation", fail_audit)
            with pytest.raises(RuntimeError, match="operator_audit_failed"):
                await repository.create_intent(command)
        elif mutation is not None:
            with pytest.raises(ApplicationBindingConflict):
                await repository.create_intent(command)
        else:
            first, second = await asyncio.gather(
                repository.create_intent(command), repository.create_intent(command),
            )
            assert sorted((first.replayed, second.replayed)) == [False, True]
            assert first.application == second.application
            with pytest.raises(ApplicationIdempotencyConflict):
                await repository.create_intent(replace(
                    command, native_root=replace(command.native_root, name="Verify X-Content-Type-Options"),
                ))
            if replay_inactive:
                async with sessions() as session, session.begin():
                    await _set_tenant(session, tenant)
                    memberships = metadata.tables["tenant_memberships"]
                    await session.execute(update(memberships).where(
                        memberships.c.tenant_id == tenant, memberships.c.user_id == actor,
                    ).values(status="inactive"))
                with pytest.raises(ApplicationBindingConflict, match="operator_principal_inactive"):
                    await repository.create_intent(command)
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            expected = 1 if mutation is None and monkeypatch is None else 0
            campaigns = metadata.tables["campaigns"]
            root = (await session.execute(select(campaigns).where(
                campaigns.c.tenant_id == tenant, campaigns.c.id == command.campaign_id,
            ))).mappings().one_or_none()
            assert (root is not None) == bool(expected)
            if root is not None:
                assert root["roe_version_id"] == roe_id
                assert root["intent_sha256"] == command.intent_sha256
                assert root["status"] == "intent_created"
                assert root["workflow_run_id"] is None
                assert root["aggregate_sequence"] == 0
            for table_name in ("autonomous_campaign_applications", "autonomous_campaign_application_events"):
                assert await _count(session, metadata.tables[table_name], tenant) == expected
            outbox = metadata.tables["outbox_events"]
            assert await session.scalar(select(func.count()).select_from(outbox).where(
                outbox.c.tenant_id == tenant, outbox.c.aggregate_id == command.campaign_id,
            )) == 0
    finally:
        await engine.dispose()


async def _lifecycle_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r171-{suffix}"
    other_tenant = f"tenant-r171-other-{suffix}"
    actor, engagement, target = await _bootstrap(sessions, tenant=tenant, suffix=suffix)
    _, other_engagement, other_target = await _bootstrap(sessions, tenant=other_tenant, suffix=f"other-{suffix}")
    command = _create_command(
        tenant=tenant,
        actor=actor,
        engagement=engagement,
        target=target,
        suffix=suffix,
    )
    try:
        repository = PostgresAutonomousCampaignApplicationRepository(sessions)
        first = await repository.create_intent(command)
        replay = await repository.create_intent(
            replace(
                command,
                correlation_id=f"replay-{suffix}",
                occurred_at=NOW + timedelta(seconds=1),
            )
        )
        assert first.replayed is False
        assert replay.replayed is True
        assert replay.application == first.application
        assert replay.audit_id == first.audit_id
        assert replay.event_id == first.event_id

        with pytest.raises(ApplicationIdempotencyConflict, match="application_idempotency_mismatch"):
            await repository.create_intent(
                replace(command, intent_sha256="f" * 64, occurred_at=NOW + timedelta(seconds=2))
            )

        with pytest.raises(ApplicationRevisionConflict, match="application_revision_conflict"):
            await repository.revoke_intent(_revoke_command(command, expected_revision=2, suffix=f"stale-{suffix}"))

        revoke_command = _revoke_command(command, expected_revision=1, suffix=suffix)
        revoked = await repository.revoke_intent(revoke_command)
        assert revoked.application.lifecycle_state is AutonomousCampaignLifecycle.REVOKED
        assert revoked.application.aggregate_revision == 2

        revoke_replay = await repository.revoke_intent(
            replace(
                revoke_command,
                correlation_id=f"revoke-replay-{suffix}"[:100],
                occurred_at=NOW + timedelta(seconds=11),
            )
        )
        assert revoke_replay.replayed is True
        assert revoke_replay.application == revoked.application
        assert revoke_replay.audit_id == revoked.audit_id
        assert revoke_replay.event_id == revoked.event_id

        with pytest.raises(ApplicationIdempotencyConflict, match="application_idempotency_mismatch"):
            await repository.revoke_intent(
                replace(
                    revoke_command,
                    reason_sha256="d" * 64,
                    occurred_at=NOW + timedelta(seconds=12),
                )
            )

        restarted = PostgresAutonomousCampaignApplicationRepository(sessions)
        recovered = await restarted.read(tenant_id=tenant, campaign_id=command.campaign_id)
        assert recovered == revoked.application
        assert await restarted.read(tenant_id=other_tenant, campaign_id=command.campaign_id) is None

        with pytest.raises(ApplicationBindingConflict, match="application_binding_not_found"):
            await repository.create_intent(
                replace(
                    command,
                    campaign_id=f"cross-{suffix}",
                    engagement_id=other_engagement,
                    target_id=other_target,
                    intent_sha256="d" * 64,
                    source_binding_sha256="e" * 64,
                    idempotency_key=f"cross-{suffix}",
                )
            )

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            events = metadata.tables["autonomous_campaign_application_events"]
            assert await _count(session, events, tenant) == 2
            audits = metadata.tables["audit_events"]
            audit_count = await session.scalar(
                select(func.count())
                .select_from(audits)
                .where(
                    audits.c.tenant_id == tenant,
                    audits.c.subject_type == "autonomous_campaign_application",
                    audits.c.subject_id == command.campaign_id,
                )
            )
            assert int(audit_count or 0) == 2
            idempotency = metadata.tables["idempotency_records"]
            revoke_idempotency_count = await session.scalar(
                select(func.count())
                .select_from(idempotency)
                .where(
                    idempotency.c.tenant_id == tenant,
                    idempotency.c.operation == "autonomous_campaign.application.revoke.v1",
                )
            )
            assert int(revoke_idempotency_count or 0) == 1
            outbox = metadata.tables["outbox_events"]
            emitted = await session.scalar(
                select(func.count())
                .select_from(outbox)
                .where(
                    outbox.c.tenant_id == tenant,
                    outbox.c.aggregate_id == command.campaign_id,
                )
            )
            assert int(emitted or 0) == 0
            with pytest.raises(DBAPIError, match="autonomous_campaign_application_event_immutable"):
                async with session.begin_nested():
                    await session.execute(
                        update(events)
                        .where(
                            events.c.tenant_id == tenant,
                            events.c.application_id == command.campaign_id,
                        )
                        .values(event_type="tampered")
                    )
    finally:
        await engine.dispose()


async def _concurrent_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r171-concurrent-{suffix}"
    actor, engagement, target = await _bootstrap(sessions, tenant=tenant, suffix=suffix)
    command = _create_command(
        tenant=tenant,
        actor=actor,
        engagement=engagement,
        target=target,
        suffix=suffix,
    )
    try:
        one, two = await asyncio.gather(
            PostgresAutonomousCampaignApplicationRepository(sessions).create_intent(command),
            PostgresAutonomousCampaignApplicationRepository(sessions).create_intent(command),
        )
        assert sorted((one.replayed, two.replayed)) == [False, True]
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            assert await _count(session, metadata.tables["autonomous_campaign_applications"], tenant) == 1
            assert await _count(session, metadata.tables["autonomous_campaign_application_events"], tenant) == 1
            idempotency = metadata.tables["idempotency_records"]
            count = await session.scalar(
                select(func.count())
                .select_from(idempotency)
                .where(
                    idempotency.c.tenant_id == tenant,
                    idempotency.c.operation == "autonomous_campaign.application.create.v1",
                )
            )
            assert int(count or 0) == 1
    finally:
        await engine.dispose()


async def _non_bypass_owner_downgrade_guard_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r171-rls-{suffix}"
    actor, engagement, target = await _bootstrap(sessions, tenant=tenant, suffix=suffix)
    command = _create_command(
        tenant=tenant,
        actor=actor,
        engagement=engagement,
        target=target,
        suffix=suffix,
    )
    await PostgresAutonomousCampaignApplicationRepository(sessions).create_intent(command)
    role_name = f"r171_owner_{suffix}"
    migration = _load_migration()
    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                # CRITICAL: this identifier is generated exclusively from a hex UUID.
                await connection.execute(
                    text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS')
                )
                await connection.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
                for table_name in (
                    "autonomous_campaign_application_events",
                    "autonomous_campaign_applications",
                ):
                    await connection.execute(text(f'ALTER TABLE {table_name} OWNER TO "{role_name}"'))
                await connection.execute(text(f'SET LOCAL ROLE "{role_name}"'))
                await connection.execute(text("SELECT set_config('redagent.tenant_id', '', true)"))

                for table_name in (
                    "autonomous_campaign_application_events",
                    "autonomous_campaign_applications",
                ):
                    hidden = await connection.scalar(text(f"SELECT count(*) FROM {table_name}"))
                    assert int(hidden or 0) == 0

                populated = await connection.run_sync(migration._has_persisted_application_state)
                assert populated is True

                force_flags = (
                    await connection.execute(
                        text(
                            "SELECT relname, relforcerowsecurity FROM pg_class "
                            "WHERE relname IN ('autonomous_campaign_application_events', "
                            "'autonomous_campaign_applications') ORDER BY relname"
                        )
                    )
                ).all()
                assert force_flags == [
                    ("autonomous_campaign_application_events", True),
                    ("autonomous_campaign_applications", True),
                ]
                for table_name in (
                    "autonomous_campaign_application_events",
                    "autonomous_campaign_applications",
                ):
                    hidden = await connection.scalar(text(f"SELECT count(*) FROM {table_name}"))
                    assert int(hidden or 0) == 0
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("r171_migration_0029", MIGRATION)
    if spec is None or spec.loader is None:
        raise AssertionError("r171_migration_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _create_command(
    *, tenant: str, actor: str, engagement: str, target: str, suffix: str
) -> CreateAutonomousCampaignIntentV1:
    return CreateAutonomousCampaignIntentV1(
        schema_version=APPLICATION_CONTRACT_VERSION,
        tenant_id=tenant,
        campaign_id=f"campaign-{suffix}"[:64],
        engagement_id=engagement,
        target_id=target,
        actor_user_id=actor,
        intent_sha256="a" * 64,
        source_binding_sha256="b" * 64,
        expected_revision=0,
        idempotency_key=f"create-{suffix}",
        correlation_id=f"correlation-{suffix}",
        occurred_at=NOW,
    )


def _revoke_command(
    create: CreateAutonomousCampaignIntentV1, *, expected_revision: int, suffix: str
) -> RevokeAutonomousCampaignIntentV1:
    return RevokeAutonomousCampaignIntentV1(
        schema_version=APPLICATION_CONTRACT_VERSION,
        tenant_id=create.tenant_id,
        campaign_id=create.campaign_id,
        actor_user_id=create.actor_user_id,
        reason_sha256="c" * 64,
        expected_revision=expected_revision,
        idempotency_key=f"revoke-{suffix}",
        correlation_id=f"revoke-correlation-{suffix}"[:100],
        occurred_at=NOW + timedelta(seconds=10),
    )


async def _bootstrap(sessions, *, tenant: str, suffix: str) -> tuple[str, str, str]:
    actor = f"user-{suffix}"[:64]
    engagement = f"engagement-{suffix}"[:64]
    target = f"target-{suffix}"[:64]
    async with sessions() as session, session.begin():
        await session.execute(
            insert(metadata.tables["tenants"]).values(
                id=tenant,
                name=f"R171 {suffix}"[:200],
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        await _set_tenant(session, tenant)
        await session.execute(
            insert(metadata.tables["users"]).values(
                id=actor,
                subject=f"subject-{suffix}"[:200],
                tenant_id=tenant,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        await session.execute(
            insert(metadata.tables["engagements"]).values(
                id=engagement,
                name=f"R171 engagement {suffix}"[:200],
                owner_user_id=actor,
                tenant_id=tenant,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        await session.execute(
            insert(metadata.tables["targets"]).values(
                id=target,
                engagement_id=engagement,
                target_type="url",
                normalized_value=f"http://127.0.0.1:{10000 + int(suffix[-3:], 16) % 50000}",
                tenant_id=tenant,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    return actor, engagement, target


def _database():
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _set_tenant(session, tenant: str) -> None:
    await session.execute(select(func.set_config("redagent.tenant_id", tenant, True)))


async def _count(session, table, tenant: str) -> int:
    value = await session.scalar(select(func.count()).select_from(table).where(table.c.tenant_id == tenant))
    return int(value or 0)
