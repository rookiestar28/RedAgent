"""Canonical child preparation; physical provenance and persisted counts belong to the store."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Mapping

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.approval_contracts import (
    PLAN_STAGE_SCHEMA_VERSION, AutonomousCampaignApprovalContextV1, StageAutonomousCampaignPlanV1,
)
from redagent_platform.campaign_service.application_contracts import ApplicationModeDisabled, AutonomousCampaignMode
from redagent_platform.campaign_service.authority_envelope import TrustedCampaignApproverKeyV2, verify_signed_campaign_authority
from redagent_platform.campaign_service.child_replan_contracts import (
    OWNED_COMPLETION_FACTS, CanonicalChildSubsetProofV1, PrepareAutonomousCampaignChildV1, prove_canonical_child_subset,
)
from redagent_platform.campaign_service.child_replan_store import ChildParentConflict, CompletedOwnedParentV1
from redagent_platform.campaign_service.planning.contracts import FactValueV1, ScalarType, ScalarValueV1, canonical_planning_sha256
from redagent_platform.campaign_service.replanning import prepare_owned_bounded_replan
from redagent_platform.campaign_service.replanning_contracts import REPLAN_REQUEST_SCHEMA_VERSION, BoundedReplanProposalV1, ReplanRequestV1
from redagent_platform.campaign_service.trusted_observations import (
    DAG_RESULT_PRODUCER_V1, OBSERVATION_CANDIDATE_SCHEMA_VERSION, OBSERVATION_POLICY_SCHEMA_VERSION,
    TRUSTED_OBSERVATION_PRODUCER_REGISTRY_SHA256, ObservationCandidateV1, ObservationPromotionDecisionV1,
    ObservationPromotionPolicyV1, evaluate_observation_history, promote_observation,
    verify_completed_owned_node_observation_evidence,
)


@dataclass(frozen=True, slots=True)
class CanonicalChildPreparationV1:
    candidate: ObservationCandidateV1
    promotion: ObservationPromotionDecisionV1
    proposal: BoundedReplanProposalV1
    strict_subset: CanonicalChildSubsetProofV1


class CanonicalChildReplanService:
    def __init__(self, store, *, application_service, context_provider, trusted_keys) -> None:
        self._store = store
        self._application_service = application_service
        self._context_provider = context_provider
        self._trusted_keys = dict(trusted_keys)

    async def prepare_child(self, command: PrepareAutonomousCampaignChildV1):
        if self._application_service.mode is not AutonomousCampaignMode.BOUNDED_REPLAN:
            raise ApplicationModeDisabled("bounded_child_mode_required")
        return await self._store.stage_child(command,
            read_context=self._context_provider.read_current_approval_context,
            build_preview=self._build_preview, trusted_keys=self._trusted_keys)

    def _build_preview(self, command, current, context, parent, prepared):
        child = prepared.proposal.child_revision
        remaining = {operator.capability.capability_id for operator in parent.domain.operators
                     if operator.operator_id in {node.operator_id for node in child.candidate_plan.nodes}}
        child_context = replace(context, execution_bindings=tuple(binding for binding in context.execution_bindings
                                                                  if binding.capability_id in remaining))
        stage = StageAutonomousCampaignPlanV1(schema_version=PLAN_STAGE_SCHEMA_VERSION,
            tenant_id=command.tenant_id, campaign_id=command.campaign_id, actor_user_id=command.actor_user_id,
            expected_revision=command.expected_revision, signed_authority=context.signed_authority,
            authority_lifecycle=context.authority_lifecycle, domain=parent.domain, revision=child,
            certificate=prepared.proposal.validation_certificate, idempotency_key=command.idempotency_key,
            correlation_id=command.correlation_id, occurred_at=command.occurred_at)
        # CRITICAL: reuse preview verification without broadening ordinary stage_plan lifecycle edges.
        return self._application_service._build_preview(stage, current, child_context)


def prepare_canonical_child_proposal(
    *, command: PrepareAutonomousCampaignChildV1, parent: CompletedOwnedParentV1,
    context: AutonomousCampaignApprovalContextV1, residual_budget: CampaignBudgetVectorV1,
    consumed_replans: int, trusted_keys: Mapping[str, TrustedCampaignApproverKeyV2],
) -> CanonicalChildPreparationV1:
    if (not isinstance(command, PrepareAutonomousCampaignChildV1) or not isinstance(parent, CompletedOwnedParentV1)
            or not isinstance(context, AutonomousCampaignApprovalContextV1)
            or not isinstance(residual_budget, CampaignBudgetVectorV1) or type(consumed_replans) is not int):
        raise ValueError("canonical_child_preparation_input_invalid")
    now = command.occurred_at
    source = parent.source
    completed_at = source.effect_receipt.completed_at
    if completed_at is None:
        raise ChildParentConflict("canonical_child_confirmed_completion_required")
    authority, lifecycle = context.signed_authority.authority, context.authority_lifecycle
    verify_signed_campaign_authority(context.signed_authority, lifecycle, trusted_keys=trusted_keys, now=now)
    if (command.tenant_id != context.tenant_id or command.campaign_id != context.campaign_id
            or command.tenant_id != source.tenant_id or command.campaign_id != source.campaign_id
            or source.engagement_id != authority.engagement_id or source.target_id not in authority.target_ids
            or source.authority_sha256 != authority.authority_sha256
            or parent.admission_receipt.signed_authority_sha256 != context.signed_authority.signed_authority_sha256
            or source.effect_receipt.envelope_sha256 != authority.authority_sha256
            # CRITICAL: completion inside a grant cannot authorize an effect that began before issuance.
            or not parent.admission_receipt.issued_at <= source.effect_receipt.started_at <= completed_at < parent.admission_receipt.expires_at
            or any(getattr(source, field) != getattr(authority, field) for field in (
                "lifecycle_epoch", "policy_revocation_epoch", "roe_revocation_epoch", "kill_switch_epoch"))):
        raise ChildParentConflict("canonical_child_current_parent_binding_mismatch")
    expires = min(completed_at + timedelta(seconds=120), authority.expires_at,
                  lifecycle.valid_until, *(approval.expires_at for approval in context.signed_authority.approvals))
    candidate = ObservationCandidateV1(
        schema_version=OBSERVATION_CANDIDATE_SCHEMA_VERSION,
        observation_id="owned-completion-" + source.provenance_sha256[:32],
        tenant_id=source.tenant_id, campaign_id=source.campaign_id, engagement_id=source.engagement_id,
        target_id=source.target_id, authority_sha256=source.authority_sha256,
        lifecycle_epoch=source.lifecycle_epoch, policy_revocation_epoch=source.policy_revocation_epoch,
        roe_revocation_epoch=source.roe_revocation_epoch, kill_switch_epoch=source.kill_switch_epoch,
        fact_id=OWNED_COMPLETION_FACTS[source.capability.capability_id], value=ScalarValueV1(ScalarType.BOOLEAN, True),
        producer=DAG_RESULT_PRODUCER_V1, source_result_sha256=source.effect_receipt.receipt_sha256,
        evidence_sha256=source.effect_receipt.receipt_sha256, observed_at=completed_at,
        received_at=now, expires_at=expires,
    )
    evidence = verify_completed_owned_node_observation_evidence(candidate=candidate, source=source,
        domain=parent.domain, revision=parent.revision, verified_at=now)
    policy = ObservationPromotionPolicyV1(schema_version=OBSERVATION_POLICY_SCHEMA_VERSION,
        tenant_id=source.tenant_id, campaign_id=source.campaign_id, engagement_id=source.engagement_id,
        authority_sha256=source.authority_sha256, target_ids=authority.target_ids,
        producer_registry_sha256=TRUSTED_OBSERVATION_PRODUCER_REGISTRY_SHA256,
        lifecycle_epoch=authority.lifecycle_epoch, policy_revocation_epoch=authority.policy_revocation_epoch,
        roe_revocation_epoch=authority.roe_revocation_epoch, kill_switch_epoch=authority.kill_switch_epoch,
        max_age_seconds=120)
    promotion = promote_observation(candidate, evidence, policy, now=now)
    trusted = promotion.trusted_observation
    if trusted is None:
        raise ChildParentConflict("canonical_child_observation_" + promotion.reason_code)
    history = evaluate_observation_history((trusted,))
    request = ReplanRequestV1(schema_version=REPLAN_REQUEST_SCHEMA_VERSION,
        request_id="canonical-child-" + canonical_planning_sha256((command.tenant_id, command.campaign_id,
                                                                  command.idempotency_key))[:32],
        tenant_id=command.tenant_id, campaign_id=command.campaign_id, engagement_id=source.engagement_id,
        parent_revision_id=parent.revision.revision_id, parent_revision_sha256=parent.revision.revision_sha256,
        parent_admission_receipt_id=parent.admission_receipt.receipt_id,
        parent_admission_receipt_sha256=parent.admission_receipt.receipt_sha256,
        observation_history=history, consumed_replans=consumed_replans, requested_at=now)
    result = prepare_owned_bounded_replan(request=request, parent_revision=parent.revision,
        parent_admission_receipt=parent.admission_receipt, authority=authority, lifecycle=lifecycle,
        domain=parent.domain, residual_budget=residual_budget, now=now, parent_completion_source=source)
    if result.proposal is None:
        raise ChildParentConflict("canonical_child_" + result.reason_code)
    proof = prove_canonical_child_subset(parent=parent.revision, child=result.proposal.child_revision,
        domain=parent.domain, completed_parent_node_ids=(source.node_id,),
        observed_values=(FactValueV1(candidate.fact_id, candidate.value),), observation_history_sha256=history.history_sha256)
    return CanonicalChildPreparationV1(candidate, promotion, result.proposal, proof)
