from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.activity_store import (
    PostgresCampaignActivityStateOwner,
    PostgresR124CampaignRecoveryOwner,
)
from redagent_platform.campaign_service.repository import (
    PostgresR124AuthorizedOptionOwner,
    StartCampaignCommand,
)
from redagent_platform.campaign_service.resolver import ResolutionRequest
from redagent_platform.campaign_service.runtime import _read_base_authority
from redagent_platform.campaign_service.service import (
    IdempotencyConflict,
    PostgresCampaignStartStore,
    R124EtagConflict,
)
from redagent_platform.campaign_service.status import (
    PostgresR124CampaignPresentationOwner,
    R124PrincipalInactive,
)
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)


def test_r124_postgres_options_are_membership_and_tenant_scoped() -> None:
    asyncio.run(_option_scenario())


def test_r124_postgres_projection_and_recovery_are_canonical_and_idempotent() -> None:
    asyncio.run(_projection_and_recovery_scenario())


def test_r124_recovery_rolls_back_checkpoint_when_receipt_persistence_fails(monkeypatch) -> None:
    asyncio.run(_recovery_rollback_scenario(monkeypatch))


class _RecoveryContainmentOwner:
    def __init__(self) -> None:
        self.calls = 0

    async def contain(self, **values):
        del values
        self.calls += 1
        return "contained", "operator_requested_containment"


async def _option_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex[:12]
    tenant = f"tenant-r124-opt-{suffix}"
    actor = f"user-r124-opt-{suffix}"
    engagement = f"eng-r124-opt-{suffix}"
    target = f"target-r124-opt-{suffix}"
    roe = f"roe-r124-opt-{suffix}"
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            actor=actor,
            engagement=engagement,
            target=target,
            roe=roe,
        )
        owner = PostgresR124AuthorizedOptionOwner(sessions)
        engagements = await owner.list_engagements(
            tenant_id=tenant,
            principal_id=actor,
            now=NOW,
        )
        assert [(item.resource_id, item.eligible) for item in engagements] == [
            (engagement, True)
        ]
        targets = await owner.list_targets(
            tenant_id=tenant,
            principal_id=actor,
            engagement_id=engagement,
            now=NOW,
        )
        assert [(item.resource_id, item.parent_id, item.eligible) for item in targets] == [
            (target, engagement, True)
        ]
        service_id = f"service-r124-opt-{suffix}"
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            await session.execute(insert(metadata.tables["service_identities"]).values(
                id=service_id,
                tenant_id=tenant,
                client_id=f"client-r124-opt-{suffix}",
                name="compat_124 CLI",
                secret_hash="0" * 64,
                roles=["operator"],
                expires_at=NOW + timedelta(hours=1),
                revoked_at=None,
                generation=1,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            ))
        service_engagements = await owner.list_engagements(
            tenant_id=tenant,
            principal_id=f"service:{service_id}",
            now=NOW,
        )
        assert [(item.resource_id, item.eligible) for item in service_engagements] == [
            (engagement, True)
        ]
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            base_authority = await _read_base_authority(
                session,
                ResolutionRequest(
                    tenant_id=tenant,
                    principal_id=f"service:{service_id}",
                    engagement_id=engagement,
                    target_id=target,
                ),
                NOW,
            )
        assert base_authority is not None
        assert base_authority["target_value"] == "http://127.0.0.1:41731"
        assert await owner.list_engagements(
            tenant_id=tenant,
            principal_id="user-not-a-member",
            now=NOW,
        ) == ()
        assert await owner.list_engagements(
            tenant_id=f"tenant-other-{suffix}",
            principal_id=actor,
            now=NOW,
        ) == ()
    finally:
        await engine.dispose()


async def _projection_and_recovery_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex[:12]
    tenant = f"tenant-r124-core-{suffix}"
    actor = f"user-r124-core-{suffix}"
    engagement = f"eng-r124-core-{suffix}"
    target = f"target-r124-core-{suffix}"
    roe = f"roe-r124-core-{suffix}"
    campaign = f"campaign-r124-{suffix}"
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            actor=actor,
            engagement=engagement,
            target=target,
            roe=roe,
        )
        start_store = PostgresCampaignStartStore(
            sessions,
            correlation_prefix="r124-integration",
        )
        start_command = _start_command(
            campaign=campaign,
            engagement=engagement,
            target=target,
            roe=roe,
            suffix=suffix,
        )
        started = await start_store.start(
            start_command,
            tenant_id=tenant,
            actor_user_id=actor,
            occurred_at=NOW,
            idempotency_key=f"r124-start-{suffix}",
            request_sha256="e" * 64,
        )
        replayed_start = await start_store.start(
            start_command,
            tenant_id=tenant,
            actor_user_id=actor,
            occurred_at=NOW,
            idempotency_key=f"r124-start-{suffix}",
            request_sha256="e" * 64,
        )
        assert started.replayed is False
        assert replayed_start.replayed is True
        assert replayed_start.campaign_id == campaign
        preflight_replay = await start_store.replay(
            tenant_id=tenant,
            actor_user_id=actor,
            idempotency_key=f"r124-start-{suffix}",
            request_sha256="e" * 64,
        )
        assert preflight_replay is not None
        assert preflight_replay.replayed is True
        with pytest.raises(IdempotencyConflict, match="idempotency_key_request_mismatch"):
            await start_store.start(
                start_command,
                tenant_id=tenant,
                actor_user_id=actor,
                occurred_at=NOW,
                idempotency_key=f"r124-start-{suffix}",
                request_sha256="f" * 64,
            )

        presentation = PostgresR124CampaignPresentationOwner(sessions)
        listed = await presentation.list_campaigns(
            tenant_id=tenant,
            principal_id=actor,
            limit=10,
            cursor=None,
            now=NOW,
        )
        assert [item["campaign_id"] for item in listed["data"]] == [campaign]
        with pytest.raises(R124PrincipalInactive, match="r124_principal_inactive"):
            await presentation.list_campaigns(
                tenant_id=tenant,
                principal_id="user-not-a-member",
                limit=10,
                cursor=None,
                now=NOW,
            )
        aggregate = await presentation.read_campaign(
            tenant_id=tenant,
            principal_id=actor,
            campaign_id=campaign,
            now=NOW,
        )
        assert aggregate["data"]["etag"] == f'"{campaign}:1"'
        assert aggregate["data"]["plan"]["primary"] == "Primary web posture assessment"
        assert aggregate["data"]["recovery"]["stop_visible"] is True
        inspector = await presentation.inspect_campaign(
            tenant_id=tenant,
            principal_id=actor,
            campaign_id=campaign,
            now=NOW,
        )
        assert inspector["data"]["engagement_id"] == engagement
        assert inspector["data"]["context_sha256"] == "2" * 64

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            await session.execute(
                update(metadata.tables["campaigns"])
                .where(
                    metadata.tables["campaigns"].c.tenant_id == tenant,
                    metadata.tables["campaigns"].c.id == campaign,
                )
                .values(attention_reason="stale_authority")
            )
        attention = await presentation.list_attention(
            tenant_id=tenant,
            principal_id=actor,
            limit=10,
            cursor=None,
            now=NOW,
        )
        assert [(item["category"], item["reason"]) for item in attention["data"]] == [
            ("stale_authority", "stale_authority")
        ]

        containment = _RecoveryContainmentOwner()
        state_owner = PostgresCampaignActivityStateOwner(
            sessions,
            safety_gate=object(),
            containment_owner=containment,
            actor_user_id=actor,
        )
        recovery = PostgresR124CampaignRecoveryOwner(sessions, state_owner)
        values = {
            "tenant_id": tenant,
            "campaign_id": campaign,
            "signal_id": f"signal-{suffix}",
            "actor_user_id": actor,
            "reason_sha256": "a" * 64,
            "expected_revision": 1,
            "idempotency_key": f"r124-recovery-{suffix}",
            "request_sha256": "b" * 64,
            "now": NOW,
            "correlation_id": f"r124-recovery-{suffix}",
        }
        first, second = await asyncio.gather(
            recovery.recover(**values),
            recovery.recover(**values),
        )
        assert sorted((first.replayed, second.replayed)) == [False, True]
        assert {(first.state, first.revision), (second.state, second.revision)} == {
            ("contained", 2)
        }
        assert containment.calls == 1
        with pytest.raises(IdempotencyConflict, match="idempotency_key_request_mismatch"):
            await recovery.recover(**{**values, "request_sha256": "c" * 64})
        with pytest.raises(R124EtagConflict, match="r124_etag_conflict"):
            await recovery.recover(
                **{
                    **values,
                    "idempotency_key": f"r124-stale-{suffix}",
                    "request_sha256": "d" * 64,
                    "expected_revision": 99,
                }
            )

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            record_count = await session.scalar(
                select(func.count())
                .select_from(metadata.tables["idempotency_records"])
                .where(
                    metadata.tables["idempotency_records"].c.tenant_id == tenant,
                    metadata.tables["idempotency_records"].c.operation
                    == "campaign.r124.recovery",
                )
            )
            assert record_count == 1
    finally:
        await engine.dispose()


async def _recovery_rollback_scenario(monkeypatch) -> None:
    import redagent_platform.campaign_service.activity_store as activity_store

    engine, sessions = _database()
    suffix = uuid4().hex[:12]
    tenant = f"tenant-r124-rollback-{suffix}"
    actor = f"user-r124-rollback-{suffix}"
    engagement = f"eng-r124-rollback-{suffix}"
    target = f"target-r124-rollback-{suffix}"
    roe = f"roe-r124-rollback-{suffix}"
    campaign = f"campaign-r124-rollback-{suffix}"
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            actor=actor,
            engagement=engagement,
            target=target,
            roe=roe,
        )
        await PostgresCampaignStartStore(sessions).start(
            _start_command(
                campaign=campaign,
                engagement=engagement,
                target=target,
                roe=roe,
                suffix=suffix,
            ),
            tenant_id=tenant,
            actor_user_id=actor,
            occurred_at=NOW,
        )
        containment = _RecoveryContainmentOwner()
        recovery = PostgresR124CampaignRecoveryOwner(
            sessions,
            PostgresCampaignActivityStateOwner(
                sessions,
                safety_gate=object(),
                containment_owner=containment,
                actor_user_id=actor,
            ),
        )
        real_insert = activity_store.insert

        def fail_idempotency_insert(table):
            if table.name == "idempotency_records":
                raise RuntimeError("receipt_persistence_failed")
            return real_insert(table)

        monkeypatch.setattr(activity_store, "insert", fail_idempotency_insert)
        with pytest.raises(RuntimeError, match="receipt_persistence_failed"):
            await recovery.recover(
                tenant_id=tenant,
                campaign_id=campaign,
                signal_id=f"signal-{suffix}",
                actor_user_id=actor,
                reason_sha256="a" * 64,
                expected_revision=1,
                idempotency_key=f"rollback-{suffix}",
                request_sha256="b" * 64,
                now=NOW,
                correlation_id=f"rollback-{suffix}",
            )
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            sequence = await session.scalar(select(metadata.tables["campaigns"].c.aggregate_sequence).where(
                metadata.tables["campaigns"].c.tenant_id == tenant,
                metadata.tables["campaigns"].c.id == campaign,
            ))
            receipt_count = await session.scalar(select(func.count()).select_from(
                metadata.tables["idempotency_records"]
            ).where(
                metadata.tables["idempotency_records"].c.tenant_id == tenant,
                metadata.tables["idempotency_records"].c.operation == "campaign.r124.recovery",
            ))
        assert sequence == 1
        assert receipt_count == 0
        assert containment.calls == 1
    finally:
        await engine.dispose()


def _start_command(
    *, campaign: str, engagement: str, target: str, roe: str, suffix: str
) -> StartCampaignCommand:
    return StartCampaignCommand(
        campaign_id=campaign,
        engagement_id=engagement,
        target_id=target,
        roe_id=roe,
        strategy_record_id=f"strategy-record-{suffix}",
        strategy_revision_id=f"strategy-revision-{suffix}",
        workflow_id=f"workflow-r124-{suffix}",
        name="Owned loopback posture",
        intent_sha256="1" * 64,
        context_schema="redagent.r119-context/v1",
        context_sha256="2" * 64,
        context_payload={"target_id": target},
        decision_schema="redagent.r121-strategy-receipt/v1",
        decision_sha256="3" * 64,
        decision_payload={
            "outcome": "planned",
            "reason": "primary_selected",
            "candidates": [
                {
                    "capability_id": "zap-controlled-runtime",
                    "eligible": True,
                    "reason": "selected_primary",
                }
            ],
        },
        plan_revision=1,
        replan_count=0,
        plan_sha256="4" * 64,
        plan_payload={
            "depth": 1,
            "primary": {
                "capability_id": "zap-controlled-runtime",
                "budget": {"max_operations": 2, "max_elapsed_seconds": 300},
                "evidence_schemas": ["redagent.evidence/v1"],
                "cleanup": "cleanup_receipt_required",
                "approval_class": "standing Tier 1 authority",
            },
            "successor": None,
        },
        proposal_ceiling_sha256="5" * 64,
        approval_receipt_id=f"approval-{suffix}",
        approval_receipt_revision=1,
        approval_receipt_sha256="6" * 64,
        envelope_core_sha256="7" * 64,
        envelope_sha256="8" * 64,
        workflow_request_sha256="9" * 64,
    )


async def _bootstrap(
    sessions,
    *,
    tenant: str,
    actor: str,
    engagement: str,
    target: str,
    roe: str,
) -> None:
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(
            session,
            tenant_id=tenant,
            actor_user_id=actor,
            correlation_id=f"bootstrap-{tenant}",
        )
        await repo.bootstrap_tenant(name="compat_124 tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
        await session.execute(
            insert(metadata.tables["tenant_memberships"]).values(
                id=f"membership-{actor}",
                tenant_id=tenant,
                user_id=actor,
                status="active",
                generation=1,
                last_validated_at=NOW,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        await repo.create_engagement(
            engagement_id=engagement,
            name="compat_124 owned loopback",
            owner_user_id=actor,
            idempotency_key=f"eng-{engagement}",
            occurred_at=NOW,
        )
        await repo.create_target(
            target_id=target,
            engagement_id=engagement,
            target_type="url",
            normalized_value="http://127.0.0.1:41731",
            idempotency_key=f"target-{target}",
            occurred_at=NOW,
        )
        await repo.create_roe_version(
            roe_version_id=roe,
            engagement_id=engagement,
            revision=1,
            document={"scope": ["http://127.0.0.1:41731"], "active_testing": True},
            policy_reference_id=f"policy-{roe}",
            policy_name="r124-owned-loopback",
            policy_version="1",
            idempotency_key=f"roe-{roe}",
            occurred_at=NOW,
        )
        await repo.approve_roe_version(
            roe_version_id=roe,
            approval_id=f"approval-{roe}",
            expected_version=1,
            idempotency_key=f"approve-{roe}",
            occurred_at=NOW,
        )


def _database():
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _set_tenant(session, tenant: str) -> None:
    await session.execute(select(func.set_config("redagent.tenant_id", tenant, True)))
