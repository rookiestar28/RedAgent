from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.exc import DBAPIError

from redagent_platform.campaign_service.application_contracts import (
    ApplicationIdempotencyConflict,
    AutonomousCampaignLifecycle,
)
from redagent_platform.campaign_service.application_repository import (
    PostgresAutonomousCampaignApplicationRepository,
)
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.approval_contracts import (
    PLAN_APPROVE_SCHEMA_VERSION,
    PLAN_STAGE_SCHEMA_VERSION,
    ApproveAutonomousCampaignPlanV1,
    StageAutonomousCampaignPlanV1,
    canonical_approval_decision_request_sha256,
)
from redagent_platform.campaign_service.authority_envelope import (
    CampaignApproverRequirementV2,
    SignedCampaignAuthorityEnvelopeV2,
    sign_campaign_authority,
)
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.validation import (
    VALIDATOR_SHA256,
    VALIDATOR_VERSION,
    validate_candidate_plan,
)
from redagent_platform.persistence.models import metadata
from tests.integration.test_autonomous_campaign_application_repository import (
    NOW,
    _bootstrap,
    _create_command,
    _database,
    _set_tenant,
)
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_authority_envelope import lifecycle, trusted_key
from tests.unit.test_campaign_planning_contracts import authority, domain, limits, world


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0030_autonomous_campaign_plan_approval.py"


def test_r172_stage_restart_concurrent_approval_rls_and_immutable_evidence() -> None:
    asyncio.run(_approval_scenario())


async def _approval_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r172-{suffix}"[:64]
    other_tenant = f"tenant-r172-other-{suffix}"[:64]
    actor, engagement, target = await _bootstrap(sessions, tenant=tenant, suffix=suffix)
    approver = f"approver-{suffix}"[:64]
    async with sessions() as session, session.begin():
        await _set_tenant(session, tenant)
        await session.execute(
            insert(metadata.tables["users"]).values(
                id=approver,
                subject=f"subject-approver-{suffix}"[:200],
                tenant_id=tenant,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    repository = PostgresAutonomousCampaignApplicationRepository(sessions)
    create = _create_command(
        tenant=tenant,
        actor=actor,
        engagement=engagement,
        target=target,
        suffix=suffix,
    )
    try:
        await repository.create_intent(create)
        current_authority = authority(
            envelope_id=f"authority-{suffix}"[:64],
            tenant_id=tenant,
            engagement_id=engagement,
            target_ids=(target,),
            valid_from=NOW,
            expires_at=NOW + timedelta(seconds=60),
            required_approvers=(CampaignApproverRequirementV2(approver, "campaign-owner"),),
            nonce=f"nonce-{suffix}"[:100],
        )
        private_key = Ed25519PrivateKey.generate()
        signed_approval = sign_campaign_authority(
            current_authority,
            private_key,
            approver_id=approver,
            approver_role="campaign-owner",
            key_id="key-a",
            approved_at=NOW + timedelta(seconds=1),
            expires_at=NOW + timedelta(seconds=45),
        )
        signed = SignedCampaignAuthorityEnvelopeV2(
            authority=current_authority,
            approvals=(signed_approval,),
        )
        current_domain = domain()
        planned = plan_attack_path(current_domain, current_authority, world(), search_limits())
        assert planned.revision is not None
        certificate = validate_candidate_plan(
            planned.revision.candidate_plan,
            current_domain,
            current_authority,
            limits=limits(),
            validated_at=NOW + timedelta(seconds=2),
        )
        stage = StageAutonomousCampaignPlanV1(
            schema_version=PLAN_STAGE_SCHEMA_VERSION,
            tenant_id=tenant,
            campaign_id=create.campaign_id,
            actor_user_id=actor,
            expected_revision=1,
            signed_authority=signed,
            authority_lifecycle=lifecycle(
                current_authority,
                observed_at=NOW + timedelta(seconds=1),
                valid_until=NOW + timedelta(seconds=50),
            ),
            domain=current_domain,
            revision=planned.revision,
            certificate=certificate,
            idempotency_key=f"stage-{suffix}",
            correlation_id=f"stage-correlation-{suffix}"[:100],
            occurred_at=NOW + timedelta(seconds=3),
        )
        service = AutonomousCampaignApplicationService(
            repository,
            trusted_approval_keys={"key-a": trusted_key(private_key, approver_id=approver)},
            validation_limits=limits(),
            trusted_validator_version=VALIDATOR_VERSION,
            trusted_validator_sha256=VALIDATOR_SHA256,
        )
        staged = await service.stage_plan(stage)
        assert staged.application.lifecycle_state is AutonomousCampaignLifecycle.AWAITING_APPROVAL
        assert staged.application.aggregate_revision == 3

        restarted_repository = PostgresAutonomousCampaignApplicationRepository(sessions)
        assert await restarted_repository.read_plan_preview(
            tenant_id=tenant,
            campaign_id=create.campaign_id,
        ) == staged.preview
        assert await restarted_repository.read_plan_preview(
            tenant_id=other_tenant,
            campaign_id=create.campaign_id,
        ) is None

        approval = ApproveAutonomousCampaignPlanV1(
            schema_version=PLAN_APPROVE_SCHEMA_VERSION,
            tenant_id=tenant,
            campaign_id=create.campaign_id,
            preview_id=staged.preview.preview_id,
            preview_sha256=staged.preview.preview_sha256,
            actor_user_id=approver,
            actor_permissions=("campaign:approve", "campaign:read"),
            expected_revision=3,
            idempotency_key=f"approve-{suffix}",
            correlation_id=f"approve-correlation-{suffix}"[:100],
            occurred_at=NOW + timedelta(seconds=4),
        )
        first, replay = await asyncio.gather(
            service.approve_plan(approval),
            AutonomousCampaignApplicationService(restarted_repository).approve_plan(approval),
        )
        assert sorted((first.replayed, replay.replayed)) == [False, True]
        accepted = first if not first.replayed else replay
        assert accepted.application.lifecycle_state is AutonomousCampaignLifecycle.APPROVED
        assert accepted.application.aggregate_revision == 4
        assert accepted.receipt.request_sha256 == canonical_approval_decision_request_sha256(approval)

        with pytest.raises(ApplicationIdempotencyConflict, match="application_idempotency_mismatch"):
            await service.approve_plan(
                replace(
                    approval,
                    actor_permissions=("campaign:approve", "campaign:read", "job:read"),
                    occurred_at=NOW + timedelta(seconds=5),
                )
            )

        recovered = await restarted_repository.read(tenant_id=tenant, campaign_id=create.campaign_id)
        assert recovered == accepted.application
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            events = metadata.tables["autonomous_campaign_application_events"]
            event_count = await session.scalar(
                select(func.count()).select_from(events).where(
                    events.c.tenant_id == tenant,
                    events.c.application_id == create.campaign_id,
                )
            )
            assert int(event_count or 0) == 4
            receipts = metadata.tables["autonomous_campaign_plan_approval_receipts"]
            receipt_rows = (
                await session.execute(
                    select(receipts.c.receipt_payload).where(receipts.c.tenant_id == tenant)
                )
            ).all()
            assert len(receipt_rows) == 1
            event_request_sha256 = await session.scalar(
                select(events.c.request_sha256).where(
                    events.c.tenant_id == tenant,
                    events.c.application_id == create.campaign_id,
                    events.c.event_type == "autonomous_campaign.plan.approved.v1",
                )
            )
            idempotency_records = metadata.tables["idempotency_records"]
            idempotency_request_sha256 = await session.scalar(
                select(idempotency_records.c.request_hash).where(
                    idempotency_records.c.tenant_id == tenant,
                    idempotency_records.c.operation == "autonomous_campaign.plan.approve.v1",
                    idempotency_records.c.idempotency_key == approval.idempotency_key,
                )
            )
            assert event_request_sha256 == accepted.receipt.request_sha256
            assert idempotency_request_sha256 == accepted.receipt.request_sha256
            previews = metadata.tables["autonomous_campaign_plan_previews"]
            persisted_preview = await session.scalar(
                select(previews.c.preview_payload).where(
                    previews.c.tenant_id == tenant,
                    previews.c.id == staged.preview.preview_id,
                )
            )
            persisted = json.dumps(
                {"preview": persisted_preview, "receipt": receipt_rows[0].receipt_payload},
                default=str,
            )
            assert "signature_hex" not in persisted
            assert "arguments" not in persisted
            with pytest.raises(DBAPIError, match="autonomous_campaign_plan_approval_receipt_immutable"):
                async with session.begin_nested():
                    await session.execute(
                        update(receipts).where(receipts.c.tenant_id == tenant).values(reason_code="tampered")
                    )

        migration = _load_migration()
        role_name = f"r172_owner_{suffix}"
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                # CRITICAL: this identifier is generated exclusively from a hex UUID.
                await connection.execute(
                    text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS')
                )
                await connection.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
                for table_name in (
                    "autonomous_campaign_plan_previews",
                    "autonomous_campaign_plan_approval_receipts",
                ):
                    await connection.execute(text(f'ALTER TABLE {table_name} OWNER TO "{role_name}"'))
                await connection.execute(text(f'SET LOCAL ROLE "{role_name}"'))
                await connection.execute(text("SELECT set_config('redagent.tenant_id', '', true)"))
                for table_name in (
                    "autonomous_campaign_plan_previews",
                    "autonomous_campaign_plan_approval_receipts",
                ):
                    assert int(await connection.scalar(text(f"SELECT count(*) FROM {table_name}")) or 0) == 0
                assert await connection.run_sync(migration._has_persisted_approval_state) is True
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("r172_migration_0030", MIGRATION)
    if spec is None or spec.loader is None:
        raise AssertionError("r172_migration_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
