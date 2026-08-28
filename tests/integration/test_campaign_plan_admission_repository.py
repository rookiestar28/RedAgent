from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.admission_contracts import CampaignReservationState
from redagent_platform.campaign_service.admission_repository import (
    AdmissionConflict,
    AdmissionReservationCommandV1,
    CampaignAdmissionRepository,
)
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


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


def test_atomic_admission_replay_and_budget_exhaustion() -> None:
    asyncio.run(_atomic_scenario())


def test_concurrent_admission_never_over_reserves_campaign_budget() -> None:
    asyncio.run(_concurrent_scenario())


def test_admission_rejects_cross_tenant_campaign_without_partial_writes() -> None:
    asyncio.run(_cross_tenant_scenario())


def test_admission_rejects_policy_command_substitutions_without_partial_writes() -> None:
    asyncio.run(_command_substitution_scenario())


async def _atomic_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r158-{suffix}"
    actor = f"user-r158-{suffix}"
    campaign = f"campaign-r158-{suffix}"
    try:
        await _bootstrap(sessions, tenant=tenant, actor=actor, campaign=campaign, suffix=suffix)
        command = _command(tenant=tenant, campaign=campaign, suffix=suffix, amount=60)
        with pytest.raises(RuntimeError, match="synthetic_admission_crash"):
            async with sessions() as session, session.begin():
                repo = CampaignAdmissionRepository(
                    session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"crash-{suffix}"
                )
                await repo.admit(command)
                raise RuntimeError("synthetic_admission_crash")
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            for table_name in (
                "campaign_budget_ledgers",
                "campaign_budget_reservations",
                "campaign_budget_events",
                "plan_admission_receipts",
            ):
                assert await _count(session, table_name, tenant) == 0

        async with sessions() as session, session.begin():
            repo = CampaignAdmissionRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"corr-{suffix}"
            )
            first = await repo.admit(command)
        async with sessions() as session, session.begin():
            repo = CampaignAdmissionRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"corr-{suffix}"
            )
            replay = await repo.admit(command)
        assert first == replay
        assert first.outcome.value == "admitted"
        async with sessions() as session, session.begin():
            repo = CampaignAdmissionRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"mismatch-{suffix}"
            )
            with pytest.raises(AdmissionConflict, match="plan_admission_idempotency_mismatch"):
                await repo.admit(replace(command, request_sha256=_digest(f"changed-{suffix}")))
        async with sessions() as session, session.begin():
            repo = CampaignAdmissionRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"hold-{suffix}"
            )
            held = await repo.transition_reservation(
                reservation_id=first.reservation_id,
                target=CampaignReservationState.HELD,
                effect_started=True,
                reconciliation_code="effect_ambiguous",
                now=NOW + timedelta(seconds=1),
            )
            assert held is CampaignReservationState.HELD
        async with sessions() as session, session.begin():
            repo = CampaignAdmissionRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"expire-{suffix}"
            )
            try:
                await repo.transition_reservation(
                    reservation_id=first.reservation_id,
                    target=CampaignReservationState.EXPIRED,
                    effect_started=True,
                    reconciliation_code=None,
                    now=NOW + timedelta(minutes=2),
                )
            except ValueError as exc:
                assert str(exc) == "campaign_reservation_held_requires_reconciliation"
            else:
                raise AssertionError("held reservation expired without reconciliation")
        async with sessions() as session, session.begin():
            repo = CampaignAdmissionRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"release-{suffix}"
            )
            released = await repo.transition_reservation(
                reservation_id=first.reservation_id,
                target=CampaignReservationState.RELEASED,
                effect_started=True,
                reconciliation_code="not_applied",
                now=NOW + timedelta(minutes=2),
            )
            assert released is CampaignReservationState.RELEASED
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            assert await _count(session, "campaign_budget_ledgers", tenant) == 1
            assert await _count(session, "campaign_budget_reservations", tenant) == 1
            assert await _count(session, "campaign_budget_events", tenant) == 3
            assert await _count(session, "plan_admission_receipts", tenant) == 1

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            events = metadata.tables["campaign_budget_events"]
            receipts = metadata.tables["plan_admission_receipts"]
            with pytest.raises(DBAPIError, match="campaign_budget_event_immutable"):
                async with session.begin_nested():
                    await session.execute(
                        update(events)
                        .where(events.c.tenant_id == tenant)
                        .values(event_type="campaign.budget.tampered.v1")
                    )
            with pytest.raises(DBAPIError, match="plan_admission_receipt_immutable"):
                async with session.begin_nested():
                    await session.execute(
                        update(receipts).where(receipts.c.tenant_id == tenant).values(reason_code="tampered")
                    )

        await _assert_admission_rls(engine, tenant=tenant, suffix=suffix)

        over = _command(
            tenant=tenant,
            campaign=campaign,
            suffix=f"{suffix}-over",
            amount=110,
            engagement_suffix=suffix,
        )
        async with sessions() as session, session.begin():
            repo = CampaignAdmissionRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"over-{suffix}"
            )
            try:
                await repo.admit(over)
            except AdmissionConflict as exc:
                assert str(exc) == "campaign_budget_exhausted"
            else:
                raise AssertionError("over-budget admission unexpectedly succeeded")
    finally:
        await engine.dispose()


async def _concurrent_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r158-race-{suffix}"
    actor = f"user-r158-race-{suffix}"
    campaign = f"campaign-r158-race-{suffix}"
    try:
        await _bootstrap(sessions, tenant=tenant, actor=actor, campaign=campaign, suffix=suffix)

        async def admit(label: str):
            async with sessions() as session, session.begin():
                repo = CampaignAdmissionRepository(
                    session,
                    tenant_id=tenant,
                    actor_user_id=actor,
                    correlation_id=f"race-{label}-{suffix}",
                )
                return await repo.admit(
                    _command(
                        tenant=tenant,
                        campaign=campaign,
                        suffix=f"{suffix}-{label}",
                        amount=60,
                        engagement_suffix=suffix,
                    )
                )

        results = await asyncio.gather(admit("a"), admit("b"), return_exceptions=True)
        assert sum(not isinstance(result, BaseException) for result in results) == 1
        failures = [result for result in results if isinstance(result, BaseException)]
        assert len(failures) == 1 and str(failures[0]) == "campaign_budget_residual_changed"
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            assert await _count(session, "campaign_budget_reservations", tenant) == 1
    finally:
        await engine.dispose()


async def _cross_tenant_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_a = f"tenant-r158-a-{suffix}"
    actor_a = f"user-r158-a-{suffix}"
    campaign_a = f"campaign-r158-a-{suffix}"
    suffix_b = f"{suffix}-b"
    tenant_b = f"tenant-r158-b-{suffix}"
    actor_b = f"user-r158-b-{suffix}"
    campaign_b = f"campaign-r158-b-{suffix}"
    try:
        await _bootstrap(sessions, tenant=tenant_a, actor=actor_a, campaign=campaign_a, suffix=suffix)
        await _bootstrap(sessions, tenant=tenant_b, actor=actor_b, campaign=campaign_b, suffix=suffix_b)
        commands = (
            _command(tenant=tenant_a, campaign=campaign_b, suffix=suffix_b, amount=20),
            _command(tenant=tenant_a, campaign=campaign_a, suffix=f"{suffix}-wrong-engagement", amount=20),
        )
        table_names = (
            "campaign_budget_ledgers",
            "campaign_budget_reservations",
            "campaign_budget_events",
            "plan_admission_receipts",
            "policy_decisions",
            "policy_boundary_receipts",
            "audit_events",
            "outbox_events",
        )
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_a)
            before = {name: await _count(session, name, tenant_a) for name in table_names}
        for command in commands:
            async with sessions() as session, session.begin():
                repo = CampaignAdmissionRepository(
                    session,
                    tenant_id=tenant_a,
                    actor_user_id=actor_a,
                    correlation_id=f"campaign-binding-{suffix}",
                )
                with pytest.raises(AdmissionConflict, match="plan_admission_campaign_binding_mismatch"):
                    await repo.admit(command)

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_a)
            with pytest.raises(DBAPIError, match="fk_campaign_budget_ledger_tenant_campaign"):
                async with session.begin_nested():
                    await session.execute(
                        insert(metadata.tables["campaign_budget_ledgers"]).values(
                            id=f"budget-ledger-cross-{suffix}",
                            campaign_id=campaign_b,
                            envelope_sha256="a" * 64,
                            duration_seconds=1,
                            requests=1,
                            rate_per_minute=1,
                            concurrency=1,
                            risk_micropoints=1,
                            cost_microunits=1,
                            evidence_bytes=1,
                            data_bytes=1,
                            tenant_id=tenant_a,
                            version=1,
                            created_at=NOW,
                            updated_at=NOW,
                        )
                    )

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_a)
            for table_name in table_names:
                assert await _count(session, table_name, tenant_a) == before[table_name]
    finally:
        await engine.dispose()


async def _command_substitution_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r158-bind-{suffix}"
    actor = f"user-r158-bind-{suffix}"
    campaign = f"campaign-r158-bind-{suffix}"
    table_names = (
        "campaign_budget_ledgers",
        "campaign_budget_reservations",
        "campaign_budget_events",
        "plan_admission_receipts",
        "policy_decisions",
        "policy_boundary_receipts",
        "audit_events",
        "outbox_events",
    )
    try:
        await _bootstrap(sessions, tenant=tenant, actor=actor, campaign=campaign, suffix=suffix)
        command = _command(tenant=tenant, campaign=campaign, suffix=suffix, amount=20)

        def with_request(request: PolicyDecisionInput) -> AdmissionReservationCommandV1:
            return replace(
                command,
                policy_request=request,
                policy_decision=replace(command.policy_decision, input_hash=policy_input_hash(request)),
            )

        substitutions = [
            with_request(
                replace(
                    command.policy_request,
                    roe_version_id="different-engagement",
                    attributes=dict(command.policy_request.attributes),
                )
            ),
            with_request(
                replace(
                    command.policy_request,
                    requested_at=command.issued_at + timedelta(microseconds=1),
                    attributes=dict(command.policy_request.attributes),
                )
            ),
        ]
        for attribute in (
            "campaign_lifecycle_epoch",
            "campaign_policy_revocation_epoch",
            "campaign_roe_revocation_epoch",
            "campaign_kill_switch_epoch",
        ):
            changed = dict(command.policy_request.attributes)
            changed[attribute] = int(changed[attribute]) + 1
            substitutions.append(with_request(replace(command.policy_request, attributes=changed)))

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            before = {name: await _count(session, name, tenant) for name in table_names}
        for substituted in substitutions:
            async with sessions() as session, session.begin():
                repo = CampaignAdmissionRepository(
                    session,
                    tenant_id=tenant,
                    actor_user_id=actor,
                    correlation_id=f"binding-{suffix}",
                )
                with pytest.raises(AdmissionConflict, match="plan_admission_command_binding_mismatch"):
                    await repo.admit(substituted)
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            for table_name in table_names:
                assert await _count(session, table_name, tenant) == before[table_name]
    finally:
        await engine.dispose()


async def _assert_admission_rls(engine, *, tenant: str, suffix: str) -> None:
    role_name = f"r158_test_{suffix}"
    async with engine.connect() as connection:
        transaction = await connection.begin()
        try:
            # CRITICAL: the interpolated role identifier is generated exclusively from a hex UUID.
            await connection.execute(
                text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS')
            )
            await connection.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
            for table_name in (
                "campaign_budget_ledgers",
                "campaign_budget_reservations",
                "campaign_budget_events",
                "plan_admission_receipts",
            ):
                await connection.execute(text(f'GRANT SELECT ON {table_name} TO "{role_name}"'))
            await connection.execute(text(f'SET LOCAL ROLE "{role_name}"'))
            for table_name in (
                "campaign_budget_ledgers",
                "campaign_budget_reservations",
                "campaign_budget_events",
                "plan_admission_receipts",
            ):
                table = metadata.tables[table_name]
                denied = await connection.scalar(select(func.count()).select_from(table))
                assert int(denied or 0) == 0
            await connection.execute(
                text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
                {"tenant": tenant},
            )
            for table_name in (
                "campaign_budget_ledgers",
                "campaign_budget_reservations",
                "campaign_budget_events",
                "plan_admission_receipts",
            ):
                table = metadata.tables[table_name]
                visible = await connection.scalar(select(func.count()).select_from(table))
                assert int(visible or 0) > 0
        finally:
            await transaction.rollback()


def _command(
    *,
    tenant: str,
    campaign: str,
    suffix: str,
    amount: int,
    engagement_suffix: str | None = None,
) -> AdmissionReservationCommandV1:
    residual = _budget(100)
    engagement = f"eng-{engagement_suffix or suffix}"[:100]
    policy_request = PolicyDecisionInput(
        boundary=PolicyBoundary.WORKFLOW,
        action="campaign.plan.admit",
        tenant_id=tenant,
        subject_id=f"user-{suffix}"[:64],
        roles=("campaign-operator",),
        permissions=("campaign:admit",),
        resource_type="campaign_plan",
        resource_id=campaign,
        policy_reference="policy-a",
        roe_version_id=engagement,
        correlation_id=f"corr-{suffix}"[:100],
        requested_at=NOW,
        attributes={
            "campaign_authority_sha256": "a" * 64,
            "campaign_policy_bundle_sha256": "b" * 64,
            "campaign_domain_sha256": "c" * 64,
            "campaign_plan_sha256": _digest(suffix),
            "campaign_certificate_sha256": "d" * 64,
            "campaign_subset_proof_sha256": "e" * 64,
            "campaign_residual_budget_sha256": residual.budget_sha256,
            "campaign_lifecycle_epoch": 1,
            "campaign_policy_revocation_epoch": 2,
            "campaign_roe_revocation_epoch": 3,
            "campaign_kill_switch_epoch": 4,
        },
    )
    decision = PolicyDecision(
        decision_id=f"decision-{suffix}"[:100],
        bundle_revision="policy-a",
        input_hash=policy_input_hash(policy_request),
        allowed=True,
        reason_code="boundary_authorized",
        obligations=(PolicyObligation.AUDIT, PolicyObligation.REQUIRE_EXPECTED_VERSION),
        issued_at=NOW,
        valid_until=NOW + timedelta(seconds=30),
    )
    return AdmissionReservationCommandV1(
        campaign_id=campaign,
        engagement_id=engagement,
        signed_authority_sha256="f" * 64,
        authority_sha256="a" * 64,
        domain_sha256="c" * 64,
        plan_sha256=_digest(suffix),
        certificate_sha256="d" * 64,
        validator_version="validator-v1",
        validator_sha256="1" * 64,
        subset_proof_sha256="e" * 64,
        policy_bundle_sha256="b" * 64,
        authorized_budget=_budget(100),
        reserved_budget=_budget(amount),
        policy_request=policy_request,
        policy_decision=decision,
        idempotency_key=f"admit-{suffix}",
        request_sha256=_digest(f"request-{suffix}"),
        lifecycle_epoch=1,
        policy_revocation_epoch=2,
        roe_revocation_epoch=3,
        kill_switch_epoch=4,
        issued_at=NOW,
        lease_expires_at=NOW + timedelta(seconds=20),
    )


def _budget(amount: int) -> CampaignBudgetVectorV1:
    return CampaignBudgetVectorV1(amount, amount, amount, amount, amount, amount, amount, amount)


def _digest(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def _bootstrap(sessions, *, tenant: str, actor: str, campaign: str, suffix: str) -> None:
    engagement = f"eng-{suffix}"[:64]
    roe = f"roe-{suffix}"[:64]
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(
            session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}"
        )
        await repo.bootstrap_tenant(name="R158 tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
        await repo.create_engagement(
            engagement_id=engagement,
            name="R158 engagement",
            owner_user_id=actor,
            idempotency_key=f"eng-{suffix}",
            occurred_at=NOW,
        )
        await repo.create_roe_version(
            roe_version_id=roe,
            engagement_id=engagement,
            revision=1,
            document={"scope": ["synthetic-loopback"], "active_testing": False},
            policy_reference_id=f"policy-{suffix}",
            policy_name="r158-synthetic",
            policy_version="1",
            idempotency_key=f"roe-{suffix}",
            occurred_at=NOW,
        )
        await session.execute(
            insert(metadata.tables["campaigns"]).values(
                id=campaign,
                engagement_id=engagement,
                roe_version_id=roe,
                name="R158 campaign",
                status="draft",
                workflow_id=f"workflow-{suffix}"[:64],
                orchestration_revision=1,
                aggregate_sequence=0,
                replan_count=0,
                tenant_id=tenant,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )


def _database():
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _set_tenant(session, tenant: str) -> None:
    await session.execute(select(func.set_config("redagent.tenant_id", tenant, True)))


async def _count(session, table_name: str, tenant: str) -> int:
    table = metadata.tables[table_name]
    value = await session.scalar(select(func.count()).select_from(table).where(table.c.tenant_id == tenant))
    return int(value or 0)
