from __future__ import annotations

import asyncio
from datetime import timedelta
from dataclasses import replace
from uuid import uuid4

import pytest
from sqlalchemy import insert, update

from redagent_platform.campaign_service.application_contracts import (
    ApplicationBindingConflict, ApplicationRevisionConflict, ApplicationIdempotencyConflict,
    ApplicationTransitionConflict,
)
from redagent_platform.persistence.models import metadata
from tests.integration.test_autonomous_campaign_admission_start_repository import _prepare_approved_campaign
from tests.integration.test_autonomous_campaign_application_repository import NOW, _set_tenant


async def _current_membership(prepared):
    actor = prepared.command.actor_user_id
    application = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
    async with prepared.sessions() as session, session.begin():
        await _set_tenant(session, prepared.tenant)
        await session.execute(insert(metadata.tables["tenant_memberships"]).values(
            id=f"membership-{uuid4().hex}", tenant_id=prepared.tenant, user_id=actor,
            status="active", generation=1, last_validated_at=NOW,
            version=1, created_at=NOW, updated_at=NOW,
        ))
        # This older admission fixture predates normal atomic root creation. Bind its inert native
        # row explicitly for projection tests; normal API qualification must create its own root.
        campaigns = metadata.tables["campaigns"]
        await session.execute(update(campaigns).where(
            campaigns.c.tenant_id == prepared.tenant, campaigns.c.id == prepared.campaign,
        ).values(intent_sha256=application.intent_sha256))
    return actor


def test_native_operator_status_reads_exact_current_preview_approval_and_start_without_verifying_execution():
    asyncio.run(_status_scenario())


async def _status_scenario():
    from redagent_platform.campaign_service.operator_repository import PostgresAutonomousCampaignOperatorOwner

    prepared = await _prepare_approved_campaign()
    try:
        actor = await _current_membership(prepared)
        owner = PostgresAutonomousCampaignOperatorOwner(prepared.sessions)
        values = dict(tenant_id=prepared.tenant, campaign_id=prepared.campaign,
                      principal_id=actor, now=prepared.command.occurred_at)
        approved = await owner.read_status(**values)
        bundle = await prepared.repository.read_current_approval_bundle(
            tenant_id=prepared.tenant, campaign_id=prepared.campaign,
            approval_receipt_id=prepared.command.approval_receipt_id,
        )
        assert approved["lifecycle_state"] == "APPROVED"
        assert approved["target_label"].startswith("url: http://127.0.0.1:")
        assert approved["preview"]["preview_id"] == bundle.preview.preview_id
        assert approved["preview_etag"] == bundle.preview.etag
        assert approved["approval_etag"] == f'"r173-{approved["aggregate_revision"]}-{prepared.command.approval_receipt_sha256}"'
        assert approved["approval"]["receipt_id"] == prepared.command.approval_receipt_id
        assert approved["start"] is None
        assert approved["operations"]["execution"]["state"] == "unavailable"
        assert approved["result"]["export_state"] == "unavailable_without_verified_bundle"
        from redagent_platform.campaign_service.status import PostgresCampaignCorePresentationOwner
        catalog = await PostgresCampaignCorePresentationOwner(prepared.sessions).list_campaigns(
            tenant_id=prepared.tenant, principal_id=actor, limit=50, cursor=None, now=prepared.command.occurred_at,
        )
        assert len(catalog["data"]) == 1
        assert catalog["data"][0]["operator_kind"] == "canonical"
        assert catalog["data"][0]["status"] == approved["lifecycle_state"]
        assert catalog["data"][0]["aggregate_sequence"] == approved["aggregate_revision"]
        assert catalog["data"][0]["authority_state"] == "requires_current_verification"

        started = await prepared.service.admit_and_queue(prepared.command)
        queued = await owner.read_status(**values)
        assert queued["aggregate_revision"] == started.application.aggregate_revision
        assert queued["start"]["execution_run_id"] == started.execution_run_id
        assert queued["start"]["admission_receipt_id"] == started.admission_receipt.receipt_id
        assert queued["operations"]["execution"]["state"] == "start_pending"

        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            runs = metadata.tables["campaign_execution_runs"]
            await session.execute(update(runs).where(
                runs.c.tenant_id == prepared.tenant, runs.c.id == started.execution_run_id,
            ).values(run_state="completed", completed_at=NOW + timedelta(seconds=10)))
        completed = await owner.read_status(**values)
        assert completed["operations"]["execution"]["state"] == "completed"
        assert completed["lifecycle_state"] != "VERIFIED"
        assert completed["result"]["evidence_state"] == "pending"
        assert completed["result"]["export_state"] == "unavailable_without_verified_bundle"
        assert "evidence_pending" in completed["attention"]
    finally:
        await prepared.engine.dispose()


def test_native_operator_status_retains_expired_authority_visibility_but_denies_inactive_or_foreign_principals():
    asyncio.run(_visibility_scenario())


async def _visibility_scenario():
    from redagent_platform.campaign_service.operator_repository import PostgresAutonomousCampaignOperatorOwner

    prepared = await _prepare_approved_campaign()
    try:
        actor = await _current_membership(prepared)
        owner = PostgresAutonomousCampaignOperatorOwner(prepared.sessions)
        values = dict(tenant_id=prepared.tenant, campaign_id=prepared.campaign,
                      principal_id=actor, now=NOW + timedelta(minutes=2))
        status = await owner.read_status(**values)
        assert status["preview_expired"] is True
        assert status["approval"]["expired"] is True
        assert "preview_expired" in status["attention"]
        with pytest.raises(ApplicationBindingConflict, match="operator_principal_inactive"):
            await owner.read_status(**{**values, "tenant_id": "foreign-tenant"})
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            memberships = metadata.tables["tenant_memberships"]
            await session.execute(update(memberships).where(
                memberships.c.tenant_id == prepared.tenant, memberships.c.user_id == actor,
            ).values(status="inactive"))
        with pytest.raises(ApplicationBindingConflict, match="operator_principal_inactive"):
            await owner.read_status(**values)
    finally:
        await prepared.engine.dispose()


def test_operator_stop_commits_one_durable_flag_and_audit_before_replay_and_rejects_stale_or_changed_input():
    asyncio.run(_stop_scenario())


async def _stop_scenario():
    from redagent_platform.campaign_service.operator_repository import PostgresAutonomousCampaignOperatorOwner
    from redagent_platform.campaign_service.operator_contracts import AutonomousCampaignOperatorRecoveryV1

    prepared = await _prepare_approved_campaign()
    try:
        actor = await _current_membership(prepared)
        started = await prepared.service.admit_and_queue(prepared.command)
        owner = PostgresAutonomousCampaignOperatorOwner(prepared.sessions)
        command = AutonomousCampaignOperatorRecoveryV1(
            action="stop", tenant_id=prepared.tenant, campaign_id=prepared.campaign,
            actor_user_id=actor, expected_revision=started.application.aggregate_revision,
            reason_sha256="c" * 64, idempotency_key=f"stop-{uuid4().hex}",
            correlation_id="operator-stop-test", occurred_at=NOW + timedelta(seconds=15),
        )
        with pytest.raises(ApplicationRevisionConflict):
            await owner.request_stop(replace(command, expected_revision=command.expected_revision - 1))
        first, second = await asyncio.gather(owner.request_stop(command), owner.request_stop(command))
        assert {first.mutation.replayed, second.mutation.replayed} == {False, True}
        assert first.execution_run_id == second.execution_run_id == started.execution_run_id
        assert first.mutation.audit_id == second.mutation.audit_id
        status = await owner.read_status(tenant_id=prepared.tenant, campaign_id=prepared.campaign,
                                       principal_id=actor, now=command.occurred_at)
        assert status["operations"]["execution"]["stop_requested"] is True
        assert status["aggregate_revision"] == command.expected_revision + 1
        assert status["lifecycle_state"] == started.application.lifecycle_state.value
        assert status["result"]["cleanup_state"] != "complete"
        assert "stop_requested" in status["attention"]
        with pytest.raises(ApplicationIdempotencyConflict):
            await owner.request_stop(replace(command, reason_sha256="d" * 64))
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            runs = metadata.tables["campaign_execution_runs"]
            await session.execute(update(runs).where(
                runs.c.tenant_id == prepared.tenant, runs.c.id == started.execution_run_id,
            ).values(workflow_run_id="workflow-run-later", run_state="contained", completed_at=command.occurred_at))
        replay = await owner.request_stop(command)
        assert replay.mutation.replayed
        with pytest.raises(ApplicationTransitionConflict, match="operator_run_terminal"):
            await owner.request_stop(replace(command, expected_revision=command.expected_revision + 1,
                                            idempotency_key="new-terminal-stop"))
    finally:
        await prepared.engine.dispose()


def test_operator_stop_audit_failure_rolls_back_flag_revision_and_replay(monkeypatch):
    asyncio.run(_stop_rollback_scenario(monkeypatch))


async def _stop_rollback_scenario(monkeypatch):
    from redagent_platform.campaign_service.operator_repository import PostgresAutonomousCampaignOperatorOwner
    from redagent_platform.campaign_service.operator_contracts import AutonomousCampaignOperatorRecoveryV1
    import redagent_platform.campaign_service.operator_repository as module

    prepared = await _prepare_approved_campaign()
    try:
        actor = await _current_membership(prepared)
        started = await prepared.service.admit_and_queue(prepared.command)
        owner = PostgresAutonomousCampaignOperatorOwner(prepared.sessions)
        original = module._record_lifecycle_event
        async def fail(*_args, **_kwargs):
            raise RuntimeError("injected-audit-failure")
        monkeypatch.setattr(module, "_record_lifecycle_event", fail)
        command = AutonomousCampaignOperatorRecoveryV1(
            action="stop", tenant_id=prepared.tenant, campaign_id=prepared.campaign,
            actor_user_id=actor, expected_revision=started.application.aggregate_revision,
            reason_sha256="c" * 64, idempotency_key=f"rollback-stop-{uuid4().hex}",
            correlation_id="operator-stop-test", occurred_at=NOW + timedelta(seconds=15),
        )
        with pytest.raises(RuntimeError, match="injected-audit-failure"):
            await owner.request_stop(command)
        status = await owner.read_status(tenant_id=prepared.tenant, campaign_id=prepared.campaign,
                                       principal_id=actor, now=command.occurred_at)
        assert status["aggregate_revision"] == command.expected_revision
        assert status["operations"]["execution"]["stop_requested"] is False
        monkeypatch.setattr(module, "_record_lifecycle_event", original)
        committed = await owner.request_stop(command)
        assert committed.mutation.replayed is False
    finally:
        await prepared.engine.dispose()


def test_operator_revoke_checks_current_principal_on_replay_and_preserves_closed_lifecycle_edges():
    asyncio.run(_revoke_scenario())


async def _revoke_scenario():
    from redagent_platform.campaign_service.operator_repository import PostgresAutonomousCampaignOperatorOwner
    from redagent_platform.campaign_service.operator_contracts import AutonomousCampaignOperatorRecoveryV1

    prepared = await _prepare_approved_campaign()
    try:
        actor = await _current_membership(prepared)
        state = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        owner = PostgresAutonomousCampaignOperatorOwner(prepared.sessions)
        command = AutonomousCampaignOperatorRecoveryV1(
            action="revoke", tenant_id=prepared.tenant, campaign_id=prepared.campaign,
            actor_user_id=actor, expected_revision=state.aggregate_revision, reason_sha256="c" * 64,
            idempotency_key=f"revoke-{uuid4().hex}", correlation_id="operator-revoke-test",
            occurred_at=NOW + timedelta(seconds=15),
        )
        revoked = await owner.request_revoke(command)
        assert revoked.application.lifecycle_state.value == "REVOKED"
        assert (await owner.request_revoke(command)).replayed
        with pytest.raises(ApplicationTransitionConflict):
            await owner.request_revoke(replace(command, expected_revision=command.expected_revision + 1,
                                              idempotency_key="revoke-terminal-again"))
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            memberships = metadata.tables["tenant_memberships"]
            await session.execute(update(memberships).where(
                memberships.c.tenant_id == prepared.tenant, memberships.c.user_id == actor,
            ).values(status="inactive"))
        with pytest.raises(ApplicationBindingConflict, match="operator_principal_inactive"):
            await owner.request_revoke(command)
    finally:
        await prepared.engine.dispose()
