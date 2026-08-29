from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.exc import DBAPIError

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
from redagent_platform.campaign_service.planning.contracts import ScalarType
from redagent_platform.campaign_service.replanning import (
    bind_replan_admission,
    prepare_bounded_replan,
)
from redagent_platform.campaign_service.replanning_contracts import (
    REPLAN_REQUEST_SCHEMA_VERSION,
    ReplanRequestV1,
)
from redagent_platform.campaign_service.replanning_repository import (
    CampaignReplanningRepository,
    ReplanningPersistenceConflict,
)
from redagent_platform.campaign_service.trusted_observations import (
    OBSERVATION_CANDIDATE_SCHEMA_VERSION,
    OBSERVATION_POLICY_SCHEMA_VERSION,
    ObservationCandidateV1,
    ObservationProducerIdentityV1,
    ObservationProducerKind,
    ObservationPromotionPolicyV1,
    evaluate_observation_history,
    promote_observation,
    verify_dag_node_observation_evidence,
)
from redagent_platform.persistence.models import metadata
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
    _database,
    _digest,
    _planning_inputs,
    _set_tenant,
)
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_dag_execution_start import Store as DagStartStore
from tests.unit.test_campaign_planning_contracts import NOW, authority, scalar


def test_postgres_trust_replan_readmission_replay_and_immutability() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
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
        execution_receipt = replace(
            parent_receipt,
            lifecycle_epoch=current_authority.lifecycle_epoch,
            policy_revocation_epoch=current_authority.policy_revocation_epoch,
            roe_revocation_epoch=current_authority.roe_revocation_epoch,
            kill_switch_epoch=current_authority.kill_switch_epoch,
        )
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
        request = execution_material.workflow_input
        snapshot = replace(
            start_snapshot,
            state=DagRunState.RUNNING,
            revision=3,
            transition_count=2,
            current_node_id=execution_material.nodes[0].node_id,
            current_node_state=DagNodeState.CONFIRMED,
        )
        producer = ObservationProducerIdentityV1(
            ObservationProducerKind.DAG_RUNNER_RESULT,
            "owned-loopback-runner",
            "runner-v1",
        )
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
            source_result_sha256="2" * 64,
            evidence_sha256="3" * 64,
            observed_at=NOW + timedelta(seconds=31),
            received_at=NOW + timedelta(seconds=32),
            expires_at=NOW + timedelta(seconds=50),
        )
        evidence = verify_dag_node_observation_evidence(
            candidate=candidate,
            request=request,
            snapshot=snapshot,
            execution_material=execution_material,
            node_id=execution_material.nodes[0].node_id,
            result_sha256=candidate.source_result_sha256,
            evidence_sha256=candidate.evidence_sha256,
            verified_at=NOW + timedelta(seconds=33),
        )
        policy = ObservationPromotionPolicyV1(
            schema_version=OBSERVATION_POLICY_SCHEMA_VERSION,
            tenant_id=tenant,
            campaign_id=campaign,
            engagement_id=engagement,
            authority_sha256=current_authority.authority_sha256,
            target_ids=("target-a",),
            allowed_producers=(producer,),
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
            search_limits=search_limits(),
            now=NOW + timedelta(seconds=36),
        )
        assert result.proposal is not None
        proposal = result.proposal
        async with sessions() as session, session.begin():
            repository = CampaignReplanningRepository(session, tenant_id=tenant)
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
            search_limits=search_limits(),
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
        accepted = bind_replan_admission(proposal=proposal, admission_receipt=child_receipt)
        async with sessions() as session, session.begin():
            repository = CampaignReplanningRepository(session, tenant_id=tenant)
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
