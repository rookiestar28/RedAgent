from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.admission_repository import (
    AdmissionReservationCommandV1,
    CampaignAdmissionRepository,
)
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagExecutionMode,
    DagNodeState,
    DagRunState,
)
from redagent_platform.campaign_service.dag_execution_service import (
    DagExecutionStartRequestV1,
    DagExecutionStartService,
)
from redagent_platform.campaign_service.dag_execution_store import PostgresDagExecutionStartStore
from redagent_platform.campaign_service.execution import ReconciliationState
from redagent_platform.campaign_service.planning.contracts import ScalarType
from redagent_platform.campaign_service.replanning import (
    bind_replan_admission,
    prepare_bounded_replan,
)
from redagent_platform.campaign_service.replanning_contracts import (
    REPLAN_REQUEST_SCHEMA_VERSION,
    ReplanRequestV1,
    _build_accepted_bounded_replan,
)
from redagent_platform.campaign_service.replanning_repository import (
    CampaignReplanningRepository,
    ReplanningPersistenceConflict,
)
from redagent_platform.campaign_service.trusted_observations import (
    DAG_RESULT_PRODUCER_V1,
    OBSERVATION_CANDIDATE_SCHEMA_VERSION,
    OBSERVATION_POLICY_SCHEMA_VERSION,
    TRUSTED_OBSERVATION_PRODUCER_REGISTRY_SHA256,
    ObservationCandidateV1,
    ObservationPromotionPolicyV1,
    evaluate_observation_history,
    promote_observation,
    verify_dag_node_observation_evidence,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.policy_service.contracts import (
    PolicyBoundary,
    PolicyDecision,
    PolicyDecisionInput,
    PolicyObligation,
    policy_input_hash,
)
from tests.integration.test_campaign_dag_execution_repository import (
    _admit,
    _bootstrap,
    _digest,
    _planning_inputs,
    _set_tenant,
)
from tests.integration.test_migrations import _alembic, _create_database, _drop_database
from tests.unit.test_campaign_dag_execution_start import Store as DagStartStore
from tests.unit.test_campaign_planning_contracts import NOW, authority, scalar
from tests.unit.test_trusted_observations import _effect_receipt, _node_observed


ROOT = Path(__file__).resolve().parents[2]


def test_postgres_trust_replan_readmission_replay_and_immutability() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    suffix = uuid4().hex
    settings = load_database_settings(ROOT, env=os.environ)
    database_name = f"r160_{suffix}"
    test_url = settings.url.set(database=database_name)
    secret_dir = ROOT / ".local" / "redagent" / "test-databases" / database_name
    secret_file = secret_dir / "database-url"
    secret_dir.mkdir(parents=True, exist_ok=False)
    secret_file.write_text(
        f"{test_url.render_as_string(hide_password=False)}\n",
        encoding="utf-8",
    )
    try:
        await _create_database(settings.url.set(database="postgres"), database_name)
        upgraded = _alembic(secret_file, "upgrade", "head")
        assert upgraded.returncode == 0, upgraded.stderr
    except BaseException:
        await _drop_database(settings.url.set(database="postgres"), database_name)
        secret_file.unlink(missing_ok=True)
        secret_dir.rmdir()
        raise
    engine = create_async_engine(test_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant = f"tenant-replan-{suffix}"
    actor = f"user-replan-{suffix}"
    campaign = f"campaign-replan-{suffix}"
    engagement = f"eng-replan-{suffix}"[:64]
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
        )
        current_domain, parent, parent_certificate = _planning_inputs(
            tenant=tenant,
            engagement=engagement,
            include_finding_observation=True,
        )
        parent_receipt = await _admit(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=f"parent-{suffix}"[:64],
            domain_sha256=current_domain.domain_sha256,
            plan_sha256=parent.candidate_plan.plan_sha256,
            certificate_sha256=parent_certificate.certificate_sha256,
            validator_version=parent_certificate.validator_version,
            validator_sha256=parent_certificate.validator_sha256,
            authority_sha256=parent.authority_sha256,
            lifecycle_epoch=1,
            policy_revocation_epoch=1,
            roe_revocation_epoch=1,
            kill_switch_epoch=1,
        )
        current_authority = authority(
            tenant_id=tenant,
            engagement_id=engagement,
            capability_ids=(current_domain.operators[0].capability.capability_id,),
        )
        lifecycle = CampaignAuthorityLifecycleV2(
            schema_version="redagent.campaign-authority-lifecycle/v2",
            authority_sha256=current_authority.authority_sha256,
            tenant_id=tenant,
            engagement_id=engagement,
            state=CampaignAuthorityLifecycleState.ACTIVE,
            lifecycle_epoch=current_authority.lifecycle_epoch,
            policy_revocation_epoch=current_authority.policy_revocation_epoch,
            roe_revocation_epoch=current_authority.roe_revocation_epoch,
            kill_switch_epoch=current_authority.kill_switch_epoch,
            observed_at=NOW + timedelta(seconds=30),
            valid_until=NOW + timedelta(seconds=55),
            revoked_at=None,
            reason_code=None,
        )
        execution_receipt = parent_receipt
        start_store = DagStartStore()
        start_snapshot = await DagExecutionStartService(
            DagExecutionMode.OWNED_LOOPBACK,
            start_store,
        ).start(
            DagExecutionStartRequestV1(
            tenant_id=tenant,
            principal_id=actor,
            campaign_id=campaign,
            engagement_id=engagement,
            execution_id=f"execution-observation-{suffix}"[:127],
            idempotency_key=f"execution-observation-{suffix}"[:127],
            revision=parent,
            domain=current_domain,
            certificate=parent_certificate,
            admission_receipt=execution_receipt,
            max_activity_attempts=2,
            max_transitions=16,
            ),
            now=NOW + timedelta(seconds=31),
        )
        execution_material = start_store.materials[0][0]
        await DagExecutionStartService(
            DagExecutionMode.OWNED_LOOPBACK,
            PostgresDagExecutionStartStore(
                sessions,
                actor_user_id=actor,
                correlation_prefix="replan-source-start",
            ),
        ).start(
            DagExecutionStartRequestV1(
                tenant_id=tenant,
                principal_id=actor,
                campaign_id=campaign,
                engagement_id=engagement,
                execution_id=f"execution-observation-{suffix}"[:127],
                idempotency_key=f"execution-observation-{suffix}"[:127],
                revision=parent,
                domain=current_domain,
                certificate=parent_certificate,
                admission_receipt=execution_receipt,
                max_activity_attempts=2,
                max_transitions=16,
            ),
            now=NOW + timedelta(seconds=31),
        )
        request = execution_material.workflow_input
        effect_receipt = _effect_receipt(ReconciliationState.CONFIRMED)
        snapshot = replace(
            start_snapshot,
            state=DagRunState.RUNNING,
            revision=3,
            transition_count=2,
            current_node_id=execution_material.nodes[0].node_id,
            current_node_state=DagNodeState.CONFIRMED,
        )
        producer = DAG_RESULT_PRODUCER_V1
        candidate = ObservationCandidateV1(
            schema_version=OBSERVATION_CANDIDATE_SCHEMA_VERSION,
            observation_id=f"observation-{suffix}",
            tenant_id=tenant,
            campaign_id=campaign,
            engagement_id=engagement,
            target_id="target-a",
            authority_sha256=current_authority.authority_sha256,
            lifecycle_epoch=current_authority.lifecycle_epoch,
            policy_revocation_epoch=current_authority.policy_revocation_epoch,
            roe_revocation_epoch=current_authority.roe_revocation_epoch,
            kill_switch_epoch=current_authority.kill_switch_epoch,
            fact_id="finding-count",
            value=scalar(ScalarType.INTEGER, 1),
            producer=producer,
            source_result_sha256=effect_receipt.receipt_sha256,
            evidence_sha256=effect_receipt.receipt_sha256,
            observed_at=NOW + timedelta(seconds=31),
            received_at=NOW + timedelta(seconds=32),
            expires_at=NOW + timedelta(seconds=50),
        )
        evidence = verify_dag_node_observation_evidence(
            candidate=candidate,
            request=request,
            snapshot=snapshot,
            execution_material=execution_material,
            domain=current_domain,
            revision=parent,
            observed=_node_observed(effect_receipt),
            effect_receipt=effect_receipt,
            node_id=execution_material.nodes[0].node_id,
            verified_at=NOW + timedelta(seconds=33),
        )
        policy = ObservationPromotionPolicyV1(
            schema_version=OBSERVATION_POLICY_SCHEMA_VERSION,
            tenant_id=tenant,
            campaign_id=campaign,
            engagement_id=engagement,
            authority_sha256=current_authority.authority_sha256,
            target_ids=("target-a",),
            producer_registry_sha256=TRUSTED_OBSERVATION_PRODUCER_REGISTRY_SHA256,
            lifecycle_epoch=current_authority.lifecycle_epoch,
            policy_revocation_epoch=current_authority.policy_revocation_epoch,
            roe_revocation_epoch=current_authority.roe_revocation_epoch,
            kill_switch_epoch=current_authority.kill_switch_epoch,
            max_age_seconds=30,
        )
        decision = promote_observation(candidate, evidence, policy, now=NOW + timedelta(seconds=34))
        assert decision.trusted_observation is not None

        authorized = CampaignBudgetVectorV1(
            10_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000
        )
        async with sessions() as session, session.begin():
            admission = CampaignAdmissionRepository(
                session,
                tenant_id=tenant,
                actor_user_id=actor,
                correlation_id=f"residual-{suffix}"[:100],
            )
            residual = await admission.preview_residual(
                campaign_id=campaign,
                envelope_sha256=current_authority.authority_sha256,
                authorized=authorized,
            )
            await _set_tenant(session, tenant)
            with pytest.raises(
                ReplanningPersistenceConflict,
                match="observation_persistence_source_receipt_mismatch",
            ):
                await CampaignReplanningRepository(
                    session, tenant_id=tenant
                ).append_promotion(
                    campaign_id=campaign,
                    candidate=candidate,
                    decision=decision,
                    occurred_at=NOW + timedelta(seconds=34),
                )
            await session.execute(
                update(metadata.tables["campaign_execution_nodes"])
                .where(
                    metadata.tables["campaign_execution_nodes"].c.tenant_id == tenant,
                    metadata.tables["campaign_execution_nodes"].c.execution_run_id
                    == execution_material.execution_run_id,
                    metadata.tables["campaign_execution_nodes"].c.node_id
                    == execution_material.nodes[0].node_id,
                )
                .values(node_state=effect_receipt.reconciliation_state.value)
            )
            await session.execute(
                insert(metadata.tables["campaign_effects"]).values(
                    id=f"effect-row-{suffix}"[:64],
                    effect_id=effect_receipt.effect_id,
                    campaign_id=campaign,
                    strategy_revision_id=None,
                    execution_run_id=execution_material.execution_run_id,
                    node_id=execution_material.nodes[0].node_id,
                    invocation_id=f"invocation-{suffix}"[:100],
                    effect_intent_sha256=effect_receipt.effect_intent_sha256,
                    effect_intent_payload={},
                    envelope_sha256=effect_receipt.envelope_sha256,
                    effect_state=effect_receipt.reconciliation_state.value,
                    claim_owner=None,
                    claim_expires_at=None,
                    claim_version=1,
                    dispatch_attempt=effect_receipt.dispatch_attempt,
                    dispatch_generation=effect_receipt.dispatch_generation,
                    runner_id=effect_receipt.runner_id,
                    workload_identity=effect_receipt.workload_identity,
                    request_sha256=effect_receipt.request_sha256,
                    pre_io_policy_decision_id=None,
                    pre_io_policy_input_sha256=None,
                    pre_io_policy_valid_until=None,
                    pre_io_authorized_at=None,
                    effect_receipt_sha256=effect_receipt.receipt_sha256,
                    effect_receipt_payload=effect_receipt.canonical_payload,
                    external_status=effect_receipt.external_status,
                    external_receipt_id=effect_receipt.external_receipt_id,
                    evidence_ids=list(effect_receipt.evidence_ids),
                    cleanup_receipt_id=effect_receipt.cleanup_receipt_id,
                    reconciliation_state="confirmed",
                    reconciliation_evidence_ids=list(
                        effect_receipt.reconciliation_evidence_ids
                    ),
                    redispatch_permitted=effect_receipt.redispatch_permitted,
                    failure_code=None,
                    next_retry_at=None,
                    outbox_sequence=1,
                    started_at=effect_receipt.started_at,
                    completed_at=effect_receipt.completed_at,
                    tenant_id=tenant,
                    version=1,
                    created_at=NOW + timedelta(seconds=33),
                    updated_at=NOW + timedelta(seconds=33),
                )
            )
            repository = CampaignReplanningRepository(session, tenant_id=tenant)
            decision_id = await repository.append_promotion(
                campaign_id=campaign,
                candidate=candidate,
                decision=decision,
                occurred_at=NOW + timedelta(seconds=34),
            )
            assert decision_id == await repository.append_promotion(
                campaign_id=campaign,
                candidate=candidate,
                decision=decision,
                occurred_at=NOW + timedelta(seconds=34),
            )
            with pytest.raises(
                ReplanningPersistenceConflict,
                match="observation_persistence_binding_mismatch",
            ):
                await CampaignReplanningRepository(
                    session,
                    tenant_id=f"other-{tenant}"[:128],
                ).append_promotion(
                    campaign_id=campaign,
                    candidate=candidate,
                    decision=decision,
                    occurred_at=NOW + timedelta(seconds=34),
                )

        replan_request = ReplanRequestV1(
            schema_version=REPLAN_REQUEST_SCHEMA_VERSION,
            request_id=f"replan-request-{suffix}",
            tenant_id=tenant,
            campaign_id=campaign,
            engagement_id=engagement,
            parent_revision_id=parent.revision_id,
            parent_revision_sha256=parent.revision_sha256,
            parent_admission_receipt_id=parent_receipt.receipt_id,
            parent_admission_receipt_sha256=parent_receipt.receipt_sha256,
            observation_history=evaluate_observation_history((decision.trusted_observation,)),
            consumed_replans=0,
            requested_at=NOW + timedelta(seconds=35),
        )
        result = prepare_bounded_replan(
            request=replan_request,
            parent_revision=parent,
            parent_admission_receipt=parent_receipt,
            authority=current_authority,
            lifecycle=lifecycle,
            domain=current_domain,
            residual_budget=residual,
            now=NOW + timedelta(seconds=36),
        )
        assert result.proposal is not None
        proposal = result.proposal
        async with sessions() as session, session.begin():
            repository = CampaignReplanningRepository(session, tenant_id=tenant)
            with pytest.raises(
                ReplanningPersistenceConflict,
                match="replan_persistence_admission_digest_mismatch",
            ):
                await repository.append_proposal(
                    campaign_id=campaign,
                    proposal=replace(
                        proposal,
                        parent_admission_receipt_sha256="f" * 64,
                    ),
                    occurred_at=NOW + timedelta(seconds=36),
                )
            proposal_id = await repository.append_proposal(
                campaign_id=campaign,
                proposal=proposal,
                occurred_at=NOW + timedelta(seconds=36),
            )
            assert proposal_id == await repository.append_proposal(
                campaign_id=campaign,
                proposal=proposal,
                occurred_at=NOW + timedelta(seconds=36),
            )

        storm_result = prepare_bounded_replan(
            request=replace(replan_request, request_id=f"storm-replay-{suffix}"),
            parent_revision=parent,
            parent_admission_receipt=parent_receipt,
            authority=current_authority,
            lifecycle=lifecycle,
            domain=current_domain,
            residual_budget=residual,
            now=NOW + timedelta(seconds=36),
        )
        assert storm_result.proposal is not None
        async with sessions() as session, session.begin():
            with pytest.raises(
                ReplanningPersistenceConflict,
                match="replan_persistence_child_revision_conflict",
            ):
                await CampaignReplanningRepository(session, tenant_id=tenant).append_proposal(
                    campaign_id=campaign,
                    proposal=storm_result.proposal,
                    occurred_at=NOW + timedelta(seconds=36),
                )

        child_receipt = await _admit_child(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
            proposal=proposal,
            authorized=authorized,
        )
        accepted = bind_replan_admission(
            proposal=proposal,
            admission_receipt=child_receipt,
            now=NOW + timedelta(seconds=38),
        )
        async with sessions() as session, session.begin():
            repository = CampaignReplanningRepository(session, tenant_id=tenant)
            forged_parent_acceptance = _build_accepted_bounded_replan(
                proposal=proposal,
                child_admission_receipt_id=parent_receipt.receipt_id,
                child_admission_receipt_sha256=parent_receipt.receipt_sha256,
                reservation_id=parent_receipt.reservation_id or "parent-reservation",
            )
            with pytest.raises(
                ReplanningPersistenceConflict,
                match="replan_acceptance_admission_binding_mismatch",
            ):
                await repository.append_acceptance(
                    campaign_id=campaign,
                    proposal_id=proposal_id,
                    accepted=forged_parent_acceptance,
                    occurred_at=NOW + timedelta(seconds=39),
                )
            with pytest.raises(
                ReplanningPersistenceConflict,
                match="replan_acceptance_proposal_binding_mismatch",
            ):
                await repository.append_acceptance(
                    campaign_id=campaign,
                    proposal_id="unrelated-proposal",
                    accepted=accepted,
                    occurred_at=NOW + timedelta(seconds=39),
                )
            acceptance_id = await repository.append_acceptance(
                campaign_id=campaign,
                proposal_id=proposal_id,
                accepted=accepted,
                occurred_at=NOW + timedelta(seconds=39),
            )
            assert acceptance_id == await repository.append_acceptance(
                campaign_id=campaign,
                proposal_id=proposal_id,
                accepted=accepted,
                occurred_at=NOW + timedelta(seconds=39),
            )
            await _set_tenant(session, tenant)
            for table_name in (
                "campaign_observation_decisions",
                "trusted_campaign_observations",
                "campaign_replan_proposals",
                "campaign_replan_acceptances",
            ):
                count = await session.scalar(
                    select(func.count())
                    .select_from(metadata.tables[table_name])
                    .where(metadata.tables[table_name].c.tenant_id == tenant)
                )
                assert int(count or 0) == 1

        async with sessions() as session:
            async with session.begin():
                await _set_tenant(session, tenant)
                with pytest.raises(DBAPIError, match="campaign_replan_proposals_immutable"):
                    await session.execute(
                        update(metadata.tables["campaign_replan_proposals"])
                        .where(metadata.tables["campaign_replan_proposals"].c.id == proposal_id)
                        .values(replan_sequence=2)
                    )
    finally:
        await engine.dispose()
        await _drop_database(settings.url.set(database="postgres"), database_name)
        secret_file.unlink(missing_ok=True)
        secret_dir.rmdir()


async def _admit_child(
    sessions,
    *,
    tenant: str,
    actor: str,
    campaign: str,
    engagement: str,
    suffix: str,
    proposal,
    authorized: CampaignBudgetVectorV1,
):
    occurred_at = NOW + timedelta(seconds=37)
    request = PolicyDecisionInput(
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
        correlation_id=f"child-admit-{suffix}"[:100],
        requested_at=occurred_at,
        attributes={
            "campaign_authority_sha256": proposal.child_revision.authority_sha256,
            "campaign_policy_bundle_sha256": "b" * 64,
            "campaign_domain_sha256": proposal.child_revision.domain_sha256,
            "campaign_plan_sha256": proposal.child_revision.candidate_plan.plan_sha256,
            "campaign_certificate_sha256": proposal.validation_certificate.certificate_sha256,
            "campaign_subset_proof_sha256": proposal.subset_proof.proof_sha256,
            "campaign_residual_budget_sha256": proposal.residual_budget.budget_sha256,
            "campaign_lifecycle_epoch": proposal.lifecycle_epoch,
            "campaign_policy_revocation_epoch": proposal.policy_revocation_epoch,
            "campaign_roe_revocation_epoch": proposal.roe_revocation_epoch,
            "campaign_kill_switch_epoch": proposal.kill_switch_epoch,
        },
    )
    decision = PolicyDecision(
        decision_id=f"child-decision-{suffix}"[:100],
        bundle_revision="policy-a",
        input_hash=policy_input_hash(request),
        allowed=True,
        reason_code="boundary_authorized",
        obligations=(PolicyObligation.AUDIT, PolicyObligation.REQUIRE_EXPECTED_VERSION),
        issued_at=occurred_at,
        valid_until=NOW + timedelta(seconds=50),
    )
    command = AdmissionReservationCommandV1(
        campaign_id=campaign,
        engagement_id=engagement,
        signed_authority_sha256="4" * 64,
        authority_sha256=proposal.child_revision.authority_sha256,
        domain_sha256=proposal.child_revision.domain_sha256,
        plan_sha256=proposal.child_revision.candidate_plan.plan_sha256,
        certificate_sha256=proposal.validation_certificate.certificate_sha256,
        validator_version=proposal.validation_certificate.validator_version,
        validator_sha256=proposal.validation_certificate.validator_sha256,
        subset_proof_sha256=proposal.subset_proof.proof_sha256,
        policy_bundle_sha256="b" * 64,
        authorized_budget=authorized,
        reserved_budget=proposal.planned_budget,
        policy_request=request,
        policy_decision=decision,
        idempotency_key=f"child-admit-{suffix}",
        request_sha256=_digest(f"child-request-{suffix}"),
        lifecycle_epoch=proposal.lifecycle_epoch,
        policy_revocation_epoch=proposal.policy_revocation_epoch,
        roe_revocation_epoch=proposal.roe_revocation_epoch,
        kill_switch_epoch=proposal.kill_switch_epoch,
        issued_at=occurred_at,
        lease_expires_at=NOW + timedelta(seconds=48),
    )
    async with sessions() as session, session.begin():
        return await CampaignAdmissionRepository(
            session,
            tenant_id=tenant,
            actor_user_id=actor,
            correlation_id=f"child-admit-{suffix}"[:100],
        ).admit(command)
