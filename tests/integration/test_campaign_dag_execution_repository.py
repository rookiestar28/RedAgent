from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.admission_contracts import (
    CampaignBudgetVectorV1,
)
from redagent_platform.campaign_service.admission_repository import (
    AdmissionReservationCommandV1,
    CampaignAdmissionRepository,
)
from redagent_platform.campaign_service.authority_envelope import (
    CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION,
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
)
from redagent_platform.campaign_service.dag_effect_authority import (
    DagEffectAuthorityGate,
)
from redagent_platform.campaign_service.dag_effect_authority_store import (
    PostgresDagEffectAuthorityStateOwner,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagContainActivityInputV1,
    DagExecutionMode,
    DagRunState,
    DagStopSignalV1,
)
from redagent_platform.campaign_service.dag_containment_store import (
    PostgresDagContainmentOwner,
)
from redagent_platform.campaign_service.dag_execution_activity import DagActivityAction
from redagent_platform.campaign_service.dag_execution_activity_store import (
    PostgresDagExecutionActivityStateOwner,
)
from redagent_platform.campaign_service.dag_effect_transition_store import (
    PostgresDagEffectTransitionStore,
)
from redagent_platform.campaign_service.dag_execution_service import (
    DagExecutionStartRequestV1,
    DagExecutionStartService,
)
from redagent_platform.campaign_service.dag_execution_store import (
    CampaignDagExecutionRepository,
    PostgresDagExecutionStartStore,
)
from redagent_platform.campaign_service.execution import (
    EffectReceiptV1,
    ReconciliationState,
)
from redagent_platform.campaign_service.dag_relay_store import (
    PostgresDagWorkflowRelayRepository,
)
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.planning.contracts import (
    CapabilityIdentityV1,
    FactAssignmentV1,
    ScalarType,
)
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    CanonicalAuthoritySnapshot,
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
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import (
    NOW,
    authority,
    domain,
    limits,
    operator,
    scalar,
    world,
)


ROOT = Path(__file__).resolve().parents[2]


def test_dag_start_replay_rollback_relay_ack_immutability_and_rls() -> None:
    asyncio.run(_dag_repository_scenario())


def test_dag_containment_projects_and_replays_exact_terminal_state() -> None:
    asyncio.run(_dag_containment_scenario())


def test_dag_confirmed_effect_consumes_held_reservation() -> None:
    asyncio.run(_dag_confirmed_effect_scenario())


class _CaptureStore:
    def __init__(self) -> None:
        self.material = None

    async def start(self, material, *, now):
        del now
        self.material = material
        return None


class _AuthorityProvider:
    def __init__(self, snapshot: CanonicalAuthoritySnapshot) -> None:
        self.snapshot = snapshot

    async def read_current_authority(self, request):
        del request
        return self.snapshot


class _LifecycleOwner:
    def __init__(self, lifecycle: CampaignAuthorityLifecycleV2) -> None:
        self.lifecycle = lifecycle

    async def read_current_lifecycle(self, *, tenant_id, authority_sha256):
        del tenant_id, authority_sha256
        return self.lifecycle


class _PolicyOwner:
    async def decide(self, request, *, now):
        return PolicyDecision(
            decision_id=f"dag-policy-{request.resource_id[-12:]}",
            bundle_revision="policy-a",
            input_hash=policy_input_hash(request),
            allowed=True,
            reason_code="boundary_authorized",
            obligations=(
                PolicyObligation.AUDIT,
                PolicyObligation.REQUIRE_EXPECTED_VERSION,
            ),
            issued_at=now,
            valid_until=now + timedelta(seconds=5),
        )


class _ContainmentOwner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def contain(self, **values):
        self.calls.append(values)
        return "contained", "synthetic_stop_contained"


async def _dag_containment_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r159-contain-{suffix}"
    actor = f"user-r159-contain-{suffix}"
    campaign = f"campaign-r159-contain-{suffix}"
    engagement = f"eng-contain-{suffix}"[:64]
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
        )
        current_domain, revision, certificate = _planning_inputs(
            tenant=tenant,
            engagement=engagement,
        )
        await _install_binding_context(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            suffix=suffix,
            execution_manifest_sha256=current_domain.operators[
                0
            ].capability.execution_manifest_sha256,
        )
        receipt = await _admit(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
            domain_sha256=current_domain.domain_sha256,
            plan_sha256=revision.candidate_plan.plan_sha256,
            certificate_sha256=certificate.certificate_sha256,
            validator_version=certificate.validator_version,
            validator_sha256=certificate.validator_sha256,
            authority_sha256=revision.authority_sha256,
        )
        request = DagExecutionStartRequestV1(
            tenant_id=tenant,
            principal_id=actor,
            campaign_id=campaign,
            engagement_id=engagement,
            execution_id=f"execution-contain-{suffix}",
            idempotency_key=f"dag-contain-{suffix}",
            revision=revision,
            domain=current_domain,
            certificate=certificate,
            admission_receipt=receipt,
            max_activity_attempts=2,
            max_transitions=16,
        )
        capture = _CaptureStore()
        await DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, capture).start(
            request,
            now=NOW + timedelta(seconds=40),
        )
        material = capture.material
        assert material is not None
        start = await DagExecutionStartService(
            DagExecutionMode.OWNED_LOOPBACK,
            PostgresDagExecutionStartStore(
                sessions,
                actor_user_id=actor,
                correlation_prefix="dag-containment-start",
            ),
        ).start(request, now=NOW + timedelta(seconds=40))
        relay = PostgresDagWorkflowRelayRepository(
            sessions,
            tenant_id=tenant,
            actor_user_id="redagent-dag-relay",
            correlation_prefix="dag-containment-relay",
        )
        claims = await relay.claim_dag_workflow_starts(
            claim_owner=f"contain-relay-{suffix}"[:100],
            now=NOW + timedelta(seconds=41),
            lease_seconds=30,
            limit=1,
        )
        assert len(claims) == 1
        await relay.acknowledge_dag_workflow_start(
            event_id=claims[0].event_id,
            claim_owner=claims[0].claim_owner,
            workflow_run_id=f"temporal-contain-{suffix}"[:100],
            occurred_at=NOW + timedelta(seconds=42),
        )
        stop = DagStopSignalV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            signal_id=f"stop-{suffix}",
            actor_user_id=actor,
            reason_sha256=_digest(f"stop-reason-{suffix}"),
        )
        contain_input = DagContainActivityInputV1(
            request=material.workflow_input,
            stop=stop,
            expected_revision=start.revision + 1,
        )
        canonical = _ContainmentOwner()
        owner = PostgresDagContainmentOwner(
            sessions,
            canonical,
            correlation_prefix="dag-containment-test",
        )
        first = await owner.contain(
            contain_input,
            now=NOW + timedelta(seconds=43),
        )
        replay = await owner.contain(
            contain_input,
            now=NOW + timedelta(seconds=44),
        )
        assert first == replay
        assert first.state is DagRunState.CONTAINED
        assert first.stop_requested is True
        assert first.terminal_reason == "synthetic_stop_contained"
        assert len(canonical.calls) == 2
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            run = (
                await session.execute(
                    select(metadata.tables["campaign_execution_runs"]).where(
                        metadata.tables["campaign_execution_runs"].c.tenant_id
                        == tenant,
                        metadata.tables["campaign_execution_runs"].c.id
                        == material.execution_run_id,
                    )
                )
            ).mappings().one()
            node_states = tuple(
                (
                    await session.scalars(
                        select(
                            metadata.tables["campaign_execution_nodes"].c.node_state
                        ).where(
                            metadata.tables["campaign_execution_nodes"].c.tenant_id
                            == tenant,
                            metadata.tables[
                                "campaign_execution_nodes"
                            ].c.execution_run_id
                            == material.execution_run_id,
                        )
                    )
                ).all()
            )
            audit_count = await session.scalar(
                select(func.count())
                .select_from(metadata.tables["audit_events"])
                .where(
                    metadata.tables["audit_events"].c.tenant_id == tenant,
                    metadata.tables["audit_events"].c.action
                    == "campaign.dag.containment_recorded",
                )
            )
            assert run["run_state"] == "contained"
            assert run["active_concurrency"] == 0
            assert set(node_states) == {"contained"}
            assert int(audit_count or 0) == 1
    finally:
        await engine.dispose()


async def _dag_confirmed_effect_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r159-confirm-{suffix}"
    actor = f"user-r159-confirm-{suffix}"
    campaign = f"campaign-r159-confirm-{suffix}"
    engagement = f"eng-confirm-{suffix}"[:64]
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
        )
        current_domain, revision, certificate = _planning_inputs(
            tenant=tenant,
            engagement=engagement,
        )
        await _install_binding_context(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            suffix=suffix,
            execution_manifest_sha256=current_domain.operators[
                0
            ].capability.execution_manifest_sha256,
        )
        receipt = await _admit(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
            domain_sha256=current_domain.domain_sha256,
            plan_sha256=revision.candidate_plan.plan_sha256,
            certificate_sha256=certificate.certificate_sha256,
            validator_version=certificate.validator_version,
            validator_sha256=certificate.validator_sha256,
            authority_sha256=revision.authority_sha256,
        )
        request = DagExecutionStartRequestV1(
            tenant_id=tenant,
            principal_id=actor,
            campaign_id=campaign,
            engagement_id=engagement,
            execution_id=f"execution-confirm-{suffix}",
            idempotency_key=f"dag-confirm-{suffix}",
            revision=revision,
            domain=current_domain,
            certificate=certificate,
            admission_receipt=receipt,
            max_activity_attempts=2,
            max_transitions=16,
        )
        capture = _CaptureStore()
        await DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, capture).start(
            request,
            now=NOW + timedelta(seconds=40),
        )
        material = capture.material
        assert material is not None
        await DagExecutionStartService(
            DagExecutionMode.OWNED_LOOPBACK,
            PostgresDagExecutionStartStore(
                sessions,
                actor_user_id=actor,
                correlation_prefix="dag-confirm-start",
            ),
        ).start(request, now=NOW + timedelta(seconds=40))
        state = PostgresDagExecutionActivityStateOwner(
            sessions,
            actor_user_id=actor,
            correlation_prefix="dag-confirm-activity",
        )
        prepared = await state.prepare(
            material.workflow_input,
            now=NOW + timedelta(seconds=41),
        )
        assert prepared.action is DagActivityAction.DISPATCH
        command = prepared.effect_command
        assert command is not None
        transitions = PostgresDagEffectTransitionStore(
            sessions,
            actor_user_id=actor,
            correlation_prefix="dag-confirm-effect",
        )
        claimed_version = await transitions.claim(
            command,
            now=NOW + timedelta(seconds=42),
        )
        request_sha256 = _digest(f"confirmed-adapter-request-{suffix}")
        dispatching_version = await transitions.mark_dispatching(
            command,
            expected_claim_version=claimed_version,
            request_sha256=request_sha256,
            runner_id=f"runner-{suffix}"[:100],
            workload_identity=f"spiffe://redagent.test/runner/{suffix}",
            now=NOW + timedelta(seconds=43),
        )
        gate = DagEffectAuthorityGate(
            PostgresDagEffectAuthorityStateOwner(
                sessions,
                actor_user_id=actor,
                correlation_prefix="dag-confirm-authority",
            ),
            CampaignContextResolver(
                _AuthorityProvider(
                    _authority_snapshot(
                        tenant=tenant,
                        actor=actor,
                        engagement=engagement,
                        target_id=command.target_id,
                        reservation_id=material.reservation_id,
                        suffix=suffix,
                    )
                )
            ),
            _LifecycleOwner(
                CampaignAuthorityLifecycleV2(
                    schema_version=CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION,
                    authority_sha256=revision.authority_sha256,
                    tenant_id=tenant,
                    engagement_id=engagement,
                    state=CampaignAuthorityLifecycleState.ACTIVE,
                    lifecycle_epoch=1,
                    policy_revocation_epoch=2,
                    roe_revocation_epoch=3,
                    kill_switch_epoch=4,
                    observed_at=NOW + timedelta(seconds=43),
                    valid_until=NOW + timedelta(seconds=55),
                    revoked_at=None,
                    reason_code=None,
                )
            ),
            _PolicyOwner(),
        )
        allowed = await gate.recheck(
            command,
            now=NOW + timedelta(seconds=48, milliseconds=500),
        )
        assert allowed.allowed is True
        completed_at = NOW + timedelta(seconds=49)
        effect_receipt = EffectReceiptV1(
            schema_version="redagent.r123-effect-receipt/v1",
            effect_id=command.effect_id,
            effect_intent_sha256=command.effect_intent_sha256,
            envelope_sha256=command.envelope_sha256,
            dispatch_attempt=1,
            dispatch_generation=1,
            runner_id=f"runner-{suffix}"[:100],
            workload_identity=f"spiffe://redagent.test/runner/{suffix}",
            request_sha256=request_sha256,
            started_at=NOW + timedelta(seconds=43),
            completed_at=completed_at,
            adapter_accepted=True,
            external_status="confirmed",
            external_receipt_id=f"external-{suffix}"[:100],
            evidence_ids=(f"evidence-{suffix}"[:100],),
            cleanup_receipt_id=f"cleanup-{suffix}"[:100],
            output_complete=True,
            external_contact_count=0,
            reconciliation_state=ReconciliationState.CONFIRMED,
            reconciliation_evidence_ids=(f"evidence-{suffix}"[:100],),
            redispatch_permitted=False,
            failure_code=None,
        )
        await transitions.confirm(
            command,
            expected_claim_version=dispatching_version,
            receipt_sha256=effect_receipt.receipt_sha256,
            receipt_payload=effect_receipt.canonical_payload,
            now=completed_at,
        )
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            run = (
                await session.execute(
                    select(metadata.tables["campaign_execution_runs"]).where(
                        metadata.tables["campaign_execution_runs"].c.tenant_id
                        == tenant,
                        metadata.tables["campaign_execution_runs"].c.id
                        == material.execution_run_id,
                    )
                )
            ).mappings().one()
            node_state = await session.scalar(
                select(metadata.tables["campaign_execution_nodes"].c.node_state).where(
                    metadata.tables["campaign_execution_nodes"].c.tenant_id
                    == tenant,
                    metadata.tables["campaign_execution_nodes"].c.execution_run_id
                    == material.execution_run_id,
                )
            )
            reservation_state = await session.scalar(
                select(
                    metadata.tables["campaign_budget_reservations"].c.reservation_state
                ).where(
                    metadata.tables["campaign_budget_reservations"].c.tenant_id
                    == tenant,
                    metadata.tables["campaign_budget_reservations"].c.id
                    == material.reservation_id,
                )
            )
            assert run["run_state"] == "completed"
            assert run["terminal_reason"] == "all_nodes_confirmed"
            assert run["active_concurrency"] == 0
            assert node_state == "confirmed"
            assert reservation_state == "consumed"
    finally:
        await engine.dispose()


async def _dag_repository_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r159-{suffix}"
    actor = f"user-r159-{suffix}"
    campaign = f"campaign-r159-{suffix}"
    engagement = f"eng-{suffix}"[:64]
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
        )
        current_domain, revision, certificate = _planning_inputs(
            tenant=tenant,
            engagement=engagement,
        )
        await _install_binding_context(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            suffix=suffix,
            execution_manifest_sha256=current_domain.operators[
                0
            ].capability.execution_manifest_sha256,
        )
        receipt = await _admit(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
            domain_sha256=current_domain.domain_sha256,
            plan_sha256=revision.candidate_plan.plan_sha256,
            certificate_sha256=certificate.certificate_sha256,
            validator_version=certificate.validator_version,
            validator_sha256=certificate.validator_sha256,
            authority_sha256=revision.authority_sha256,
        )
        request = DagExecutionStartRequestV1(
            tenant_id=tenant,
            principal_id=actor,
            campaign_id=campaign,
            engagement_id=engagement,
            execution_id=f"execution-{suffix}",
            idempotency_key=f"dag-start-{suffix}",
            revision=revision,
            domain=current_domain,
            certificate=certificate,
            admission_receipt=receipt,
            max_activity_attempts=2,
            max_transitions=16,
        )
        capture = _CaptureStore()
        await DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, capture).start(
            request,
            now=NOW + timedelta(seconds=40),
        )
        material = capture.material
        assert material is not None

        with pytest.raises(RuntimeError, match="synthetic_dag_start_crash"):
            async with sessions() as session, session.begin():
                repository = CampaignDagExecutionRepository(
                    session,
                    tenant_id=tenant,
                    actor_user_id=actor,
                    correlation_id=f"dag-crash-{suffix}",
                )
                await repository.start(material, now=NOW + timedelta(seconds=40))
                raise RuntimeError("synthetic_dag_start_crash")
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            assert await _count(session, "campaign_execution_runs", tenant) == 0
            assert await _count(session, "campaign_execution_nodes", tenant) == 0
            assert await _dag_start_outbox_count(session, tenant) == 0

        store = PostgresDagExecutionStartStore(
            sessions,
            actor_user_id=actor,
            correlation_prefix="dag-start-test",
        )
        first = await DagExecutionStartService(
            DagExecutionMode.OWNED_LOOPBACK, store
        ).start(request, now=NOW + timedelta(seconds=40))
        replay = await DagExecutionStartService(
            DagExecutionMode.OWNED_LOOPBACK, store
        ).start(request, now=NOW + timedelta(seconds=41))
        assert first == replay
        assert first.state is DagRunState.START_PENDING
        assert first.transition_count == 0

        async with sessions() as session, session.begin():
            repository = CampaignDagExecutionRepository(
                session,
                tenant_id=tenant,
                actor_user_id=actor,
                correlation_id=f"dag-mismatch-{suffix}",
            )
            with pytest.raises(
                RuntimeError, match="dag_start_idempotency_mismatch"
            ):
                await repository.start(
                    replace(material, idempotency_key=f"different-{suffix}"),
                    now=NOW + timedelta(seconds=42),
                )

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            assert await _count(session, "campaign_execution_runs", tenant) == 1
            assert await _count(session, "campaign_execution_nodes", tenant) == len(
                material.nodes
            )
            assert await _dag_start_outbox_count(session, tenant) == 1
            with pytest.raises(
                DBAPIError, match="campaign_execution_run_input_immutable"
            ):
                async with session.begin_nested():
                    await session.execute(
                        update(metadata.tables["campaign_execution_runs"])
                        .where(
                            metadata.tables["campaign_execution_runs"].c.tenant_id
                            == tenant
                        )
                        .values(input_sha256="9" * 64)
                    )

        relay = PostgresDagWorkflowRelayRepository(
            sessions,
            tenant_id=tenant,
            actor_user_id="redagent-dag-relay",
            correlation_prefix="dag-relay-test",
        )
        claims = await relay.claim_dag_workflow_starts(
            claim_owner=f"relay-{suffix}"[:100],
            now=NOW + timedelta(seconds=43),
            lease_seconds=30,
            limit=10,
        )
        assert len(claims) == 1
        assert claims[0].campaign_id == material.execution_run_id
        await relay.acknowledge_dag_workflow_start(
            event_id=claims[0].event_id,
            claim_owner=claims[0].claim_owner,
            workflow_run_id=f"temporal-run-{suffix}"[:100],
            occurred_at=NOW + timedelta(seconds=44),
        )
        assert await relay.claim_dag_workflow_starts(
            claim_owner=f"relay-replay-{suffix}"[:100],
            now=NOW + timedelta(seconds=45),
            lease_seconds=30,
            limit=10,
        ) == []
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            run = (
                await session.execute(
                    select(metadata.tables["campaign_execution_runs"]).where(
                        metadata.tables["campaign_execution_runs"].c.tenant_id
                        == tenant
                    )
                )
            ).mappings().one()
            assert run["run_state"] == "running"
            assert run["workflow_run_id"] == f"temporal-run-{suffix}"[:100]
            assert await _dag_start_outbox_count(
                session, tenant, published=True
            ) == 1

        activity_state = PostgresDagExecutionActivityStateOwner(
            sessions,
            actor_user_id=actor,
            correlation_prefix="dag-activity-test",
        )
        prepared = await activity_state.prepare(
            material.workflow_input,
            now=NOW + timedelta(seconds=46),
        )
        assert prepared.action is DagActivityAction.DISPATCH
        assert prepared.effect_command is not None
        command = prepared.effect_command
        transitions = PostgresDagEffectTransitionStore(
            sessions,
            actor_user_id=actor,
            correlation_prefix="dag-effect-test",
        )
        claimed_version = await transitions.claim(
            command,
            now=NOW + timedelta(seconds=47),
        )
        assert claimed_version == 1
        dispatching_version = await transitions.mark_dispatching(
            command,
            expected_claim_version=claimed_version,
            request_sha256=_digest(f"adapter-request-{suffix}"),
            runner_id=f"runner-{suffix}"[:100],
            workload_identity=f"spiffe://redagent.test/runner/{suffix}",
            now=NOW + timedelta(seconds=48),
        )
        assert dispatching_version == 2
        authority_gate = DagEffectAuthorityGate(
            PostgresDagEffectAuthorityStateOwner(
                sessions,
                actor_user_id=actor,
                correlation_prefix="dag-authority-test",
            ),
            CampaignContextResolver(
                _AuthorityProvider(
                    _authority_snapshot(
                        tenant=tenant,
                        actor=actor,
                        engagement=engagement,
                        target_id=command.target_id,
                        reservation_id=material.reservation_id,
                        suffix=suffix,
                    )
                )
            ),
            _LifecycleOwner(
                CampaignAuthorityLifecycleV2(
                    schema_version=CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION,
                    authority_sha256=revision.authority_sha256,
                    tenant_id=tenant,
                    engagement_id=engagement,
                    state=CampaignAuthorityLifecycleState.ACTIVE,
                    lifecycle_epoch=1,
                    policy_revocation_epoch=2,
                    roe_revocation_epoch=3,
                    kill_switch_epoch=4,
                    observed_at=NOW + timedelta(seconds=48),
                    valid_until=NOW + timedelta(seconds=55),
                    revoked_at=None,
                    reason_code=None,
                )
            ),
            _PolicyOwner(),
        )
        authority = await authority_gate.recheck(
            command,
            now=NOW + timedelta(seconds=48, milliseconds=500),
        )
        assert authority.allowed is True
        await transitions.ambiguity(
            command,
            expected_claim_version=dispatching_version,
            failure_code="synthetic_commit_response_loss",
            now=NOW + timedelta(seconds=49),
        )
        retry = await transitions.lookup_unavailable(
            command,
            expected_claim_version=3,
            failure_code="synthetic_status_unavailable",
            now=NOW + timedelta(seconds=50),
        )
        assert retry.effect_state == "reconciliation_required"
        terminal = await transitions.lookup_unavailable(
            command,
            expected_claim_version=4,
            failure_code="synthetic_status_unavailable",
            now=NOW + timedelta(seconds=52),
        )
        assert terminal.effect_state == "manual_review_required"
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant)
            effect = (
                await session.execute(
                    select(metadata.tables["campaign_effects"]).where(
                        metadata.tables["campaign_effects"].c.tenant_id == tenant,
                        metadata.tables["campaign_effects"].c.effect_id
                        == command.effect_id,
                    )
                )
            ).mappings().one()
            node = (
                await session.execute(
                    select(metadata.tables["campaign_execution_nodes"]).where(
                        metadata.tables["campaign_execution_nodes"].c.tenant_id
                        == tenant,
                        metadata.tables["campaign_execution_nodes"].c.node_id
                        == prepared.snapshot.current_node_id,
                    )
                )
            ).mappings().one()
            run = (
                await session.execute(
                    select(metadata.tables["campaign_execution_runs"]).where(
                        metadata.tables["campaign_execution_runs"].c.tenant_id
                        == tenant,
                        metadata.tables["campaign_execution_runs"].c.id
                        == material.execution_run_id,
                    )
                )
            ).mappings().one()
            reservation = (
                await session.execute(
                    select(metadata.tables["campaign_budget_reservations"]).where(
                        metadata.tables["campaign_budget_reservations"].c.tenant_id
                        == tenant,
                        metadata.tables["campaign_budget_reservations"].c.id
                        == material.reservation_id,
                    )
                )
            ).mappings().one()
            assert effect["effect_state"] == "manual_review_required"
            assert effect["redispatch_permitted"] is False
            assert effect["pre_io_policy_decision_id"] is not None
            assert effect["pre_io_policy_input_sha256"] is not None
            assert node["node_state"] == "manual_review_required"
            assert run["run_state"] == "manual_review_required"
            assert run["active_concurrency"] == 0
            assert run["rate_claimed_requests"] == 1
            assert reservation["reservation_state"] == "held"
            audit_actions = set(
                (
                    await session.scalars(
                            select(metadata.tables["audit_events"].c.action).where(
                                metadata.tables["audit_events"].c.tenant_id == tenant,
                                metadata.tables["audit_events"].c.subject_id
                                == effect["id"],
                        )
                    )
                ).all()
            )
            assert {
                "campaign.dag.effect_claimed",
                "campaign.dag.effect_dispatching",
                "campaign.dag.effect_reconciliation_required",
                "campaign.dag.effect_manual_review_required",
            } <= audit_actions

        await _assert_dag_rls(engine, tenant=tenant, suffix=suffix)
    finally:
        await engine.dispose()


def _authority_snapshot(
    *,
    tenant: str,
    actor: str,
    engagement: str,
    target_id: str,
    reservation_id: str,
    suffix: str,
) -> CanonicalAuthoritySnapshot:
    target_value = "http://127.0.0.1:41731"
    target_document = {
        "target_id": target_id,
        "revision": 1,
        "target_type": "url",
        "normalized_value": target_value,
    }
    target_sha256 = hashlib.sha256(
        json.dumps(
            target_document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return CanonicalAuthoritySnapshot(
        tenant_id=tenant,
        principal_id=actor,
        engagement_id=engagement,
        engagement_version=1,
        roe_version_id=f"roe-current-{suffix}"[:64],
        roe_revision=1,
        roe_sha256="a" * 64,
        roe_status="approved",
        roe_revocation_epoch=3,
        policy_decision_id=f"resolver-decision-{suffix}"[:64],
        policy_revision="policy-a",
        policy_sha256="b" * 64,
        policy_status="allowed",
        policy_revocation_epoch=2,
        target_id=target_id,
        target_revision=1,
        target_sha256=target_sha256,
        target_value=target_value,
        target_resolution_mode="owned-loopback",
        credential_class="none",
        credential_reference=None,
        quota_reference=f"quota-{suffix}"[:100],
        quota_available=True,
        runner_id=f"runner-{suffix}"[:100],
        runner_workload_identity=f"spiffe://redagent.test/runner/{suffix}",
        runner_ready=True,
        reservation_id=reservation_id,
        lease_id=f"lease-{suffix}"[:100],
        lease_expires_at=NOW + timedelta(seconds=55),
        stop_requested=False,
        observed_at=NOW + timedelta(seconds=48),
        expires_at=NOW + timedelta(seconds=54),
    )


def _planning_inputs(
    *, tenant: str, engagement: str, include_finding_observation: bool = False
):
    binding = closed_execution_registry()["zap-controlled-runtime@2"]
    capability = CapabilityIdentityV1(
        capability_id=binding.capability_id,
        capability_revision=binding.capability_revision,
        adapter_id=binding.adapter_id,
        adapter_version=binding.adapter_version,
        execution_manifest_sha256="1" * 64,
        profile_id=binding.profile_id,
        profile_revision=binding.profile_revision,
        profile_sha256=binding.profile_sha256,
        bundle_id=binding.bundle_id,
        bundle_revision=binding.bundle_revision,
        bundle_sha256=binding.bundle_sha256,
    )
    current_operator = replace(operator(), capability=capability)
    if include_finding_observation:
        current_operator = replace(
            current_operator,
            effects=(
                FactAssignmentV1("finding-count", scalar(ScalarType.INTEGER, 1)),
                *current_operator.effects,
            ),
            observation_fact_ids=("finding-count", "posture-collected"),
        )
    current_domain = domain(operators=(current_operator,))
    current_authority = authority(
        tenant_id=tenant,
        engagement_id=engagement,
        capability_ids=(binding.capability_id,),
    )
    result = plan_attack_path(
        current_domain,
        current_authority,
        world(),
        search_limits(),
    )
    assert result.revision is not None
    certificate = validate_candidate_plan(
        result.revision.candidate_plan,
        current_domain,
        current_authority,
        limits=limits(),
        validated_at=NOW + timedelta(seconds=20),
    )
    return current_domain, result.revision, certificate


async def _admit(
    sessions,
    *,
    tenant: str,
    actor: str,
    campaign: str,
    engagement: str,
    suffix: str,
    domain_sha256: str,
    plan_sha256: str,
    certificate_sha256: str,
    validator_version: str,
    validator_sha256: str,
    authority_sha256: str,
    lifecycle_epoch: int = 1,
    policy_revocation_epoch: int = 2,
    roe_revocation_epoch: int = 3,
    kill_switch_epoch: int = 4,
):
    authorized = CampaignBudgetVectorV1(
        10_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000
    )
    reserved = CampaignBudgetVectorV1(10, 10, 10, 1, 10, 100, 1_024, 512)
    policy_request = PolicyDecisionInput(
        boundary=PolicyBoundary.WORKFLOW,
        action="campaign.plan.admit",
        tenant_id=tenant,
        subject_id=actor,
        roles=("campaign-operator",),
        permissions=("campaign:admit",),
        resource_type="campaign_plan",
        resource_id=campaign,
        policy_reference="policy-a",
        roe_version_id=engagement,
        correlation_id=f"admit-{suffix}"[:100],
        requested_at=NOW + timedelta(seconds=30),
        attributes={
            "campaign_authority_sha256": authority_sha256,
            "campaign_policy_bundle_sha256": "b" * 64,
            "campaign_domain_sha256": domain_sha256,
            "campaign_plan_sha256": plan_sha256,
            "campaign_certificate_sha256": certificate_sha256,
            "campaign_subset_proof_sha256": "e" * 64,
            "campaign_residual_budget_sha256": authorized.budget_sha256,
            "campaign_lifecycle_epoch": lifecycle_epoch,
            "campaign_policy_revocation_epoch": policy_revocation_epoch,
            "campaign_roe_revocation_epoch": roe_revocation_epoch,
            "campaign_kill_switch_epoch": kill_switch_epoch,
        },
    )
    decision = PolicyDecision(
        decision_id=f"decision-{suffix}"[:100],
        bundle_revision="policy-a",
        input_hash=policy_input_hash(policy_request),
        allowed=True,
        reason_code="boundary_authorized",
        obligations=(
            PolicyObligation.AUDIT,
            PolicyObligation.REQUIRE_EXPECTED_VERSION,
        ),
        issued_at=NOW + timedelta(seconds=30),
        valid_until=NOW + timedelta(seconds=60),
    )
    command = AdmissionReservationCommandV1(
        campaign_id=campaign,
        engagement_id=engagement,
        signed_authority_sha256="f" * 64,
        authority_sha256=authority_sha256,
        domain_sha256=domain_sha256,
        plan_sha256=plan_sha256,
        certificate_sha256=certificate_sha256,
        validator_version=validator_version,
        validator_sha256=validator_sha256,
        subset_proof_sha256="e" * 64,
        policy_bundle_sha256="b" * 64,
        authorized_budget=authorized,
        reserved_budget=reserved,
        policy_request=policy_request,
        policy_decision=decision,
        idempotency_key=f"admit-{suffix}",
        request_sha256=_digest(f"request-{suffix}"),
        lifecycle_epoch=lifecycle_epoch,
        policy_revocation_epoch=policy_revocation_epoch,
        roe_revocation_epoch=roe_revocation_epoch,
        kill_switch_epoch=kill_switch_epoch,
        issued_at=NOW + timedelta(seconds=30),
        lease_expires_at=NOW + timedelta(seconds=55),
    )
    async with sessions() as session, session.begin():
        return await CampaignAdmissionRepository(
            session,
            tenant_id=tenant,
            actor_user_id=actor,
            correlation_id=f"admit-{suffix}"[:100],
        ).admit(command)


async def _bootstrap(
    sessions,
    *,
    tenant: str,
    actor: str,
    campaign: str,
    engagement: str,
    suffix: str,
) -> None:
    roe = f"roe-{suffix}"[:64]
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(
            session,
            tenant_id=tenant,
            actor_user_id=actor,
            correlation_id=f"bootstrap-{suffix}",
        )
        await repo.bootstrap_tenant(name="R159 tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
        await repo.create_engagement(
            engagement_id=engagement,
            name="R159 engagement",
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
            policy_name="r159-synthetic",
            policy_version="1",
            idempotency_key=f"roe-{suffix}",
            occurred_at=NOW,
        )
        await session.execute(
            insert(metadata.tables["campaigns"]).values(
                id=campaign,
                engagement_id=engagement,
                roe_version_id=roe,
                name="R159 campaign",
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


async def _install_binding_context(
    sessions,
    *,
    tenant: str,
    actor: str,
    campaign: str,
    suffix: str,
    execution_manifest_sha256: str,
) -> None:
    bindings: list[dict[str, object]] = []
    for index, registry_key in enumerate(
        ("zap-controlled-runtime@2", "nuclei-trusted-runtime@2"), start=1
    ):
        closed = closed_execution_registry()[registry_key]
        binding = CapabilityBindingKeyV1(
            schema_version="redagent.r119-capability-binding/v1",
            capability_id=closed.capability_id,
            capability_revision=closed.capability_revision,
            execution_manifest_sha256=(
                execution_manifest_sha256 if index == 1 else "2" * 64
            ),
            adapter_id=closed.adapter_id,
            adapter_version=closed.adapter_version,
            profile_id=closed.profile_id,
            profile_revision=closed.profile_revision,
            profile_sha256=closed.profile_sha256,
            bundle_id=closed.bundle_id,
            bundle_revision=closed.bundle_revision,
            bundle_sha256=closed.bundle_sha256,
            semantics_revision=1,
            semantics_sha256=f"{index + 2}" * 64,
            normalized_output_sha256=f"{index + 4}" * 64,
            projection_revision=1,
            projection_sha256=f"{index + 6}" * 64,
        )
        bindings.append(asdict(binding))
    strategy_id = f"strategy-r159-{suffix}"[:64]
    async with sessions() as session, session.begin():
        await _set_tenant(session, tenant)
        await session.execute(
            insert(metadata.tables["campaign_strategy_revisions"]).values(
                id=strategy_id,
                strategy_revision_id=f"strategy-revision-{suffix}"[:100],
                campaign_id=campaign,
                predecessor_revision_id=None,
                plan_revision=1,
                replan_count=0,
                context_schema="redagent.r119-decision-context/v1",
                context_sha256=_digest(f"context-{suffix}"),
                context_payload={"bindings": bindings},
                decision_schema="redagent.r121-strategy-receipt/v1",
                decision_sha256=_digest(f"decision-{suffix}"),
                decision_payload={"result": "selected"},
                plan_sha256=_digest(f"strategy-plan-{suffix}"),
                plan_payload={"kind": "synthetic-owned-loopback"},
                proposal_ceiling_sha256=_digest(f"ceiling-{suffix}"),
                approval_receipt_id=f"approval-{suffix}"[:100],
                approval_receipt_revision=1,
                approval_receipt_sha256=_digest(f"approval-{suffix}"),
                envelope_core_sha256=_digest(f"envelope-core-{suffix}"),
                envelope_sha256=_digest(f"envelope-{suffix}"),
                created_by_user_id=actor,
                tenant_id=tenant,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        await session.execute(
            update(metadata.tables["campaigns"])
            .where(
                metadata.tables["campaigns"].c.tenant_id == tenant,
                metadata.tables["campaigns"].c.id == campaign,
            )
            .values(current_strategy_revision_id=strategy_id)
        )


async def _assert_dag_rls(engine, *, tenant: str, suffix: str) -> None:
    role_name = f"r159_test_{suffix}"
    async with engine.connect() as connection:
        transaction = await connection.begin()
        try:
            # CRITICAL: the role identifier is generated exclusively from a hex UUID.
            await connection.execute(
                text(
                    f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB '
                    "NOCREATEROLE NOINHERIT NOBYPASSRLS"
                )
            )
            await connection.execute(
                text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"')
            )
            for table_name in (
                "campaign_execution_runs",
                "campaign_execution_nodes",
                "campaign_execution_authority_observations",
            ):
                await connection.execute(
                    text(f'GRANT SELECT ON {table_name} TO "{role_name}"')
                )
            await connection.execute(text(f'SET LOCAL ROLE "{role_name}"'))
            for table_name in (
                "campaign_execution_runs",
                "campaign_execution_nodes",
                "campaign_execution_authority_observations",
            ):
                table = metadata.tables[table_name]
                denied = await connection.scalar(select(func.count()).select_from(table))
                assert int(denied or 0) == 0
            await connection.execute(
                text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
                {"tenant": tenant},
            )
            assert int(
                await connection.scalar(
                    select(func.count()).select_from(
                        metadata.tables["campaign_execution_runs"]
                    )
                )
                or 0
            ) == 1
        finally:
            await transaction.rollback()


def _database():
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _set_tenant(session, tenant: str) -> None:
    await session.execute(select(func.set_config("redagent.tenant_id", tenant, True)))


async def _count(session, table_name: str, tenant: str) -> int:
    table = metadata.tables[table_name]
    value = await session.scalar(
        select(func.count()).select_from(table).where(table.c.tenant_id == tenant)
    )
    return int(value or 0)


async def _dag_start_outbox_count(
    session, tenant: str, *, published: bool | None = None
) -> int:
    outbox = metadata.tables["outbox_events"]
    statement = select(func.count()).select_from(outbox).where(
        outbox.c.tenant_id == tenant,
        outbox.c.event_type == "campaign.dag.start.requested.v1",
    )
    if published is not None:
        statement = statement.where(outbox.c.published.is_(published))
    return int(await session.scalar(statement) or 0)


def _digest(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()
