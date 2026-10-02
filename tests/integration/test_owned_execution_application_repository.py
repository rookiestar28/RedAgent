from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError
from alembic.migration import MigrationContext
from alembic.operations import Operations
import importlib.util
from pathlib import Path

from redagent_platform.campaign_service.application_contracts import APPLICATION_CONTRACT_VERSION, AutonomousCampaignMode, RevokeAutonomousCampaignIntentV1
from redagent_platform.campaign_service.admission_start_relay import AutonomousCampaignStartBridgeRelay
from redagent_platform.campaign_service.dag_execution_activity_store import PostgresDagExecutionActivityStateOwner
from redagent_platform.campaign_service.dag_relay_store import PostgresDagWorkflowRelayRepository
from redagent_platform.campaign_service.owned_execution import OwnedExecutionDenied
from redagent_platform.campaign_service.owned_execution_store import assert_owned_execution_current
from redagent_platform.campaign_service.dag_containment_store import PostgresDagContainmentOwner
from redagent_platform.campaign_service.dag_manifest_lineage import PostgresDagManifestLineageOwner
from redagent_platform.campaign_service.dag_effect_transition_store import PostgresDagEffectTransitionStore
from redagent_platform.campaign_service.dag_lifecycle_store import PostgresDagLifecycleOwner
from redagent_platform.campaign_service.authority_envelope import CampaignAuthorityLifecycleState
from redagent_platform.campaign_service.dag_execution_contracts import DagContainActivityInputV1, DagStopSignalV1, DAG_EXECUTION_SCHEMA_VERSION, DagRunState
from redagent_platform.campaign_service.relay import RelayFailure
from redagent_platform.orchestration.dag_execution_gateway import workflow_input_from_dag_start_payload
from redagent_platform.persistence.models import metadata
from tests.integration.test_autonomous_campaign_admission_start_repository import NOW, _prepare_approved_campaign
from tests.integration.test_autonomous_campaign_admission_start_relay_repository import _Gateway, _repository
from tests.integration.test_autonomous_campaign_application_repository import _set_tenant


def test_populated_auto_mode_refuses_downgrade_without_rewriting_history():
    asyncio.run(_downgrade_scenario())


async def _downgrade_scenario():
    prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO)
    path = Path(__file__).resolve().parents[2] / "migrations/versions/0032_owned_execution_mode.py"
    spec = importlib.util.spec_from_file_location("owned_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    def downgrade(connection):
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()
    try:
        with pytest.raises(DBAPIError, match="mode_plan_only"):
            async with prepared.engine.begin() as connection:
                await connection.run_sync(downgrade)
        current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        assert current.mode is AutonomousCampaignMode.OWNED_LOOPBACK_AUTO
    finally:
        await prepared.engine.dispose()


class _IncompleteCleanup:
    async def contain(self, **values):
        return "manual_review_required", "campaign_stop_active_cleanup_required"


def test_lost_activity_reply_uses_current_locked_revision_for_cleanup_attention():
    asyncio.run(_cleanup_scenario())


def test_owned_dag_manifest_lineage_creates_exact_claimed_job_in_tenant_transaction():
    asyncio.run(_manifest_lineage_scenario())


def test_locked_lifecycle_uses_explicit_application_clock_and_retains_expiry():
    asyncio.run(_lifecycle_clock_scenario())


async def _lifecycle_clock_scenario():
    prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO)
    try:
        await prepared.service.admit_and_queue(prepared.command)
        bridge = _repository(prepared)
        claim = (await bridge.claim_admission_start_bridges(claim_owner="clock-bridge", now=NOW + timedelta(seconds=6), lease_seconds=20, limit=1))[0]
        await AutonomousCampaignStartBridgeRelay(repository=bridge, gateway=_Gateway()).deliver(claim, now=NOW + timedelta(seconds=7))
        owner = PostgresDagLifecycleOwner(prepared.sessions)
        authority_sha256 = prepared.context.signed_authority.authority.authority_sha256
        observed = NOW + timedelta(seconds=10)
        active = await owner.read_current_lifecycle(tenant_id=prepared.tenant, authority_sha256=authority_sha256, now=observed)
        assert active is not None and active.state is CampaignAuthorityLifecycleState.ACTIVE
        assert active.observed_at == observed
        assert active.valid_until <= NOW + timedelta(seconds=60)
        expired = await owner.read_current_lifecycle(tenant_id=prepared.tenant, authority_sha256=authority_sha256, now=NOW + timedelta(minutes=5))
        assert expired is not None and expired.state is CampaignAuthorityLifecycleState.EXPIRED
        assert expired.reason_code == "authority_expired"
    finally:
        await prepared.engine.dispose()


async def _manifest_lineage_scenario():
    prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO)
    try:
        await prepared.service.admit_and_queue(prepared.command)
        bridge = _repository(prepared)
        claim = (await bridge.claim_admission_start_bridges(claim_owner="lineage-bridge", now=NOW + timedelta(seconds=6), lease_seconds=20, limit=1))[0]
        await AutonomousCampaignStartBridgeRelay(repository=bridge, gateway=_Gateway()).deliver(claim, now=NOW + timedelta(seconds=7))
        relay = PostgresDagWorkflowRelayRepository(prepared.sessions, tenant_id=prepared.tenant, actor_user_id=prepared.command.actor_user_id, correlation_prefix="lineage-relay")
        claim = (await relay.claim_dag_workflow_starts(claim_owner="lineage-dag", now=NOW + timedelta(seconds=8), lease_seconds=20, limit=1))[0]
        request = workflow_input_from_dag_start_payload(claim.payload)
        await relay.acknowledge_dag_workflow_start(event_id=claim.event_id, claim_owner=claim.claim_owner, workflow_run_id="lineage-run", occurred_at=NOW + timedelta(seconds=9))
        state = PostgresDagExecutionActivityStateOwner(prepared.sessions, actor_user_id=prepared.command.actor_user_id, correlation_prefix="lineage-state", owned_execution_enabled=True)
        material = await state.prepare(request, now=NOW + timedelta(seconds=10))
        command = material.effect_command
        assert command is not None
        store = PostgresDagEffectTransitionStore(prepared.sessions, actor_user_id=prepared.command.actor_user_id, correlation_prefix="lineage-effect")
        await store.claim(command, now=NOW + timedelta(seconds=11))
        owner = PostgresDagManifestLineageOwner()
        async with prepared.sessions() as session, session.begin():
            lineage = await owner.prepare(session, command, actor_user_id=prepared.command.actor_user_id, stable="lineage", now=NOW + timedelta(seconds=12))
            replay = await owner.prepare(session, command, actor_user_id=prepared.command.actor_user_id, stable="lineage", now=NOW + timedelta(seconds=13))
            assert replay == lineage
            assert lineage.campaign_id == prepared.campaign
            jobs = metadata.tables["jobs"]
            job = (await session.execute(select(jobs).where(jobs.c.tenant_id == prepared.tenant, jobs.c.id == lineage.job_id))).mappings().one()
            assert job["request"]["execution_run_id"] == request.execution_run_id
            assert job["request"]["effect_id"] == command.effect_id
    finally:
        await prepared.engine.dispose()


async def _cleanup_scenario():
    prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO)
    try:
        admitted = await prepared.service.admit_and_queue(prepared.command)
        bridge = _repository(prepared)
        claim = (await bridge.claim_admission_start_bridges(claim_owner="cleanup-bridge", now=NOW + timedelta(seconds=6), lease_seconds=20, limit=1))[0]
        await AutonomousCampaignStartBridgeRelay(repository=bridge, gateway=_Gateway()).deliver(claim, now=NOW + timedelta(seconds=7))
        relay = PostgresDagWorkflowRelayRepository(prepared.sessions, tenant_id=prepared.tenant, actor_user_id="cleanup-worker", correlation_prefix="cleanup-relay")
        claim = (await relay.claim_dag_workflow_starts(claim_owner="cleanup-dag", now=NOW + timedelta(seconds=8), lease_seconds=20, limit=1))[0]
        request = workflow_input_from_dag_start_payload(claim.payload)
        assert admitted.execution_run_id == request.execution_run_id
        await relay.acknowledge_dag_workflow_start(event_id=claim.event_id, claim_owner=claim.claim_owner, workflow_run_id="cleanup-run", occurred_at=NOW + timedelta(seconds=9))
        state = PostgresDagExecutionActivityStateOwner(prepared.sessions, actor_user_id="cleanup-worker", correlation_prefix="cleanup-state", owned_execution_enabled=True)
        before = await state.snapshot(request, now=NOW + timedelta(seconds=10))
        # Durable frontier progress survives a lost Activity reply.
        progressed = await state.prepare(request, now=NOW + timedelta(seconds=11))
        assert progressed.snapshot.revision > before.revision
        stop = DagContainActivityInputV1(request=request, expected_revision=before.revision, stop=DagStopSignalV1(schema_version=DAG_EXECUTION_SCHEMA_VERSION, signal_id="cleanup-stop", actor_user_id=prepared.command.actor_user_id, reason_sha256="c" * 64))
        owner = PostgresDagContainmentOwner(prepared.sessions, _IncompleteCleanup(), correlation_prefix="cleanup-test")
        result = await owner.contain(stop, now=NOW + timedelta(seconds=12))
        assert result.state is DagRunState.MANUAL_REVIEW_REQUIRED
        assert result.stop_requested
        current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        assert current.lifecycle_state.value == "CLEANUP_INCOMPLETE"
        assert current.attention_reason == "campaign_stop_active_cleanup_required"
        replay = await owner.contain(stop, now=NOW + timedelta(seconds=13))
        assert replay == result
    finally:
        await prepared.engine.dispose()


def test_unknown_dag_start_projects_query_only_attention_then_bounded_manual_review():
    asyncio.run(_unknown_start_scenario())


def test_expired_dag_start_claim_recovers_by_query_only_then_attaches_same_run():
    asyncio.run(_recovered_start_scenario())


async def _recovered_start_scenario():
    prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO)
    try:
        admitted = await prepared.service.admit_and_queue(prepared.command)
        bridge = _repository(prepared)
        claim = (await bridge.claim_admission_start_bridges(claim_owner="expired-bridge", now=NOW + timedelta(seconds=6), lease_seconds=20, limit=1))[0]
        await AutonomousCampaignStartBridgeRelay(repository=bridge, gateway=_Gateway()).deliver(claim, now=NOW + timedelta(seconds=7))
        relay = PostgresDagWorkflowRelayRepository(prepared.sessions, tenant_id=prepared.tenant, actor_user_id="expired-worker", correlation_prefix="expired-relay")
        first = (await relay.claim_dag_workflow_starts(claim_owner="expired-dag", now=NOW + timedelta(seconds=8), lease_seconds=1, limit=1))[0]
        assert not first.reconciliation_only
        recovered = (await relay.claim_dag_workflow_starts(claim_owner="expired-restarted", now=NOW + timedelta(seconds=10), lease_seconds=20, limit=1))[0]
        assert recovered.reconciliation_only
        assert recovered.event_id == first.event_id
        await relay.record_dag_workflow_start_failure(event_id=recovered.event_id, claim_owner=recovered.claim_owner, failure=RelayFailure.AMBIGUOUS_START, last_error="duplicate_query_unavailable", occurred_at=NOW + timedelta(seconds=11), max_attempts=5)
        query = (await relay.claim_dag_workflow_starts(claim_owner="expired-found", now=NOW + timedelta(seconds=12), lease_seconds=20, limit=1))[0]
        await relay.acknowledge_dag_workflow_start(event_id=query.event_id, claim_owner=query.claim_owner, workflow_run_id="expired-existing-run", occurred_at=NOW + timedelta(seconds=13), duplicate_confirmed=True)
        request = workflow_input_from_dag_start_payload(query.payload)
        assert request.execution_run_id == admitted.execution_run_id
        state = PostgresDagExecutionActivityStateOwner(prepared.sessions, actor_user_id="expired-worker", correlation_prefix="expired-state", owned_execution_enabled=True)
        material = await state.prepare(request, now=NOW + timedelta(seconds=14))
        assert material.effect_command is not None
        current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        assert current.lifecycle_state.value == "RUNNING"
        assert not await relay.claim_dag_workflow_starts(claim_owner="expired-again", now=NOW + timedelta(seconds=15), lease_seconds=20, limit=1)
    finally:
        await prepared.engine.dispose()


async def _unknown_start_scenario():
    prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO)
    try:
        await prepared.service.admit_and_queue(prepared.command)
        bridge = _repository(prepared)
        claim = (await bridge.claim_admission_start_bridges(claim_owner="unknown-bridge", now=NOW + timedelta(seconds=6), lease_seconds=20, limit=1))[0]
        await AutonomousCampaignStartBridgeRelay(repository=bridge, gateway=_Gateway()).deliver(claim, now=NOW + timedelta(seconds=7))
        relay = PostgresDagWorkflowRelayRepository(prepared.sessions, tenant_id=prepared.tenant, actor_user_id="unknown-worker", correlation_prefix="unknown-relay")
        first = (await relay.claim_dag_workflow_starts(claim_owner="unknown-dag", now=NOW + timedelta(seconds=8), lease_seconds=20, limit=1))[0]
        await relay.record_dag_workflow_start_failure(event_id=first.event_id, claim_owner=first.claim_owner, failure=RelayFailure.AMBIGUOUS_START, last_error="duplicate_query_unavailable", occurred_at=NOW + timedelta(seconds=9), max_attempts=2)
        current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        assert current.lifecycle_state.value == "RECONCILIATION_REQUIRED"
        second = (await relay.claim_dag_workflow_starts(claim_owner="unknown-restarted", now=NOW + timedelta(seconds=10), lease_seconds=20, limit=1))[0]
        assert second.reconciliation_only
        await relay.record_dag_workflow_start_failure(event_id=second.event_id, claim_owner=second.claim_owner, failure=RelayFailure.AMBIGUOUS_START, last_error="duplicate_query_unavailable", occurred_at=NOW + timedelta(seconds=11), max_attempts=2)
        current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        assert current.lifecycle_state.value == "MANUAL_REVIEW_REQUIRED"
        assert current.attention_reason
        assert not await relay.claim_dag_workflow_starts(claim_owner="unknown-again", now=NOW + timedelta(seconds=12), lease_seconds=20, limit=1)
    finally:
        await prepared.engine.dispose()


@pytest.mark.parametrize("capability_key", ["zap-controlled-runtime@3", "nuclei-trusted-runtime@3"])
def test_approved_auto_queues_one_existing_dag_and_binds_effect_before_io(capability_key):
    asyncio.run(_scenario(capability_key))


async def _scenario(capability_key):
    prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO, capability_key=capability_key)
    try:
        admitted = await prepared.service.admit_and_queue(prepared.command)
        bridge = _repository(prepared)
        claim = (await bridge.claim_admission_start_bridges(claim_owner="owned-bridge", now=NOW + timedelta(seconds=6), lease_seconds=20, limit=1))[0]
        await AutonomousCampaignStartBridgeRelay(repository=bridge, gateway=_Gateway()).deliver(claim, now=NOW + timedelta(seconds=7))
        relay = PostgresDagWorkflowRelayRepository(prepared.sessions, tenant_id=prepared.tenant, actor_user_id="owned-worker", correlation_prefix="owned-relay")
        claims = await relay.claim_dag_workflow_starts(claim_owner="owned-dag", now=NOW + timedelta(seconds=8), lease_seconds=20, limit=10)
        assert len(claims) == 1
        request = workflow_input_from_dag_start_payload(claims[0].payload)
        assert request.execution_run_id == admitted.execution_run_id
        state = PostgresDagExecutionActivityStateOwner(prepared.sessions, actor_user_id="owned-worker", correlation_prefix="owned-frontier", owned_execution_enabled=True)
        # Workflow execution can win the race against its relay acknowledgement.
        material = await state.prepare(request, now=NOW + timedelta(seconds=9))
        assert material.effect_command is not None
        await relay.acknowledge_dag_workflow_start(event_id=claims[0].event_id, claim_owner=claims[0].claim_owner, workflow_run_id="owned-dag-run", occurred_at=NOW + timedelta(seconds=10))
        duplicate = await state.prepare(request, now=NOW + timedelta(seconds=11))
        assert duplicate.effect_command.effect_id == material.effect_command.effect_id
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            runs = metadata.tables["campaign_execution_runs"]
            run = (await session.execute(select(runs).where(runs.c.tenant_id == prepared.tenant, runs.c.id == request.execution_run_id))).mappings().one()
            await assert_owned_execution_current(session, run, now=NOW + timedelta(seconds=12), enabled=True)
            with pytest.raises(OwnedExecutionDenied, match="mode_denied"):
                await assert_owned_execution_current(session, run, now=NOW + timedelta(seconds=12), enabled=False)
            with pytest.raises(OwnedExecutionDenied, match="not_current"):
                await assert_owned_execution_current(session, run, now=NOW + timedelta(seconds=100), enabled=True)
            effects = metadata.tables["campaign_effects"]
            count = (await session.execute(select(func.count()).select_from(effects).where(effects.c.tenant_id == prepared.tenant, effects.c.execution_run_id == request.execution_run_id))).scalar_one()
            assert count == 1
        current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        await prepared.repository.revoke_intent(RevokeAutonomousCampaignIntentV1(
            schema_version=APPLICATION_CONTRACT_VERSION, tenant_id=prepared.tenant,
            campaign_id=prepared.campaign, actor_user_id=prepared.command.actor_user_id,
            reason_sha256="f" * 64, expected_revision=current.aggregate_revision,
            idempotency_key="owned-revoke", correlation_id="owned-revoke", occurred_at=NOW + timedelta(seconds=13),
        ))
        stopped = await state.prepare(request, now=NOW + timedelta(seconds=14))
        assert stopped.effect_command is None
        assert stopped.snapshot.stop_requested
    finally:
        await prepared.engine.dispose()
