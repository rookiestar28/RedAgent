"""Pure deterministic preparation of independently validated child campaign plans."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from redagent_platform.campaign_service.admission import (
    build_plan_envelope_subset_proof,
    calculate_plan_budget,
)
from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.admission_contracts import (
    AdmissionOutcome,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityEnvelopeV2,
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
)
from redagent_platform.campaign_service.planning.contracts import (
    FactValueV1,
    PlanningDomainV1,
    ValidationLimitsV1,
    WorldStateV1,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.search_contracts import (
    ATTACK_PATH_DAG_SCHEMA_VERSION,
    AttackPathDagRevisionV1,
    AttackPathPlannerOutcome,
    PlannerSearchLimitsV1,
)
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan
from redagent_platform.campaign_service.planning.owned_sequential import (
    OWNED_SEQUENTIAL_PLANNER_SHA256,
    OWNED_SEQUENTIAL_PLANNER_VERSION,
    OWNED_SEQUENTIAL_VALIDATOR_SHA256,
    OWNED_SEQUENTIAL_VALIDATOR_VERSION,
    derive_owned_sequential_search_limits,
    plan_owned_sequential_attack_path,
    validate_owned_sequential_candidate_plan,
)
from redagent_platform.campaign_service.child_replan_contracts import prove_canonical_child_subset
from redagent_platform.campaign_service.dag_execution_contracts import DagRunState
from redagent_platform.campaign_service.trusted_observations import OwnedCompletionSourceV1
from redagent_platform.campaign_service.replanning_contracts import (
    REPLAN_PROPOSAL_SCHEMA_VERSION,
    REPLAN_RESULT_SCHEMA_VERSION,
    BoundedReplanProposalV1,
    BoundedReplanResultV1,
    AcceptedBoundedReplanV1,
    NodeSubstitutionV1,
    ReplanOutcome,
    ReplanRequestV1,
    _build_accepted_bounded_replan,
)


def bind_replan_admission(
    *,
    proposal: BoundedReplanProposalV1,
    admission_receipt: PlanAdmissionReceiptV1,
    now: datetime,
) -> AcceptedBoundedReplanV1:
    if not isinstance(proposal, BoundedReplanProposalV1) or not isinstance(
        admission_receipt, PlanAdmissionReceiptV1
    ):
        raise ValueError("replan_admission_input_invalid")
    _aware(now)
    if (
        admission_receipt.receipt_id == proposal.parent_admission_receipt_id
        or admission_receipt.receipt_sha256 == proposal.parent_admission_receipt_sha256
    ):
        # CRITICAL: a child is new execution authority and can never inherit the parent's receipt.
        raise ValueError("replan_parent_admission_transfer_forbidden")
    child = proposal.child_revision
    certificate = proposal.validation_certificate
    if (
        admission_receipt.outcome is not AdmissionOutcome.ADMITTED
        or admission_receipt.tenant_id != child.tenant_id
        or admission_receipt.campaign_id != proposal.campaign_id
        or admission_receipt.engagement_id != proposal.engagement_id
        or admission_receipt.plan_sha256 != child.candidate_plan.plan_sha256
        or admission_receipt.authority_sha256 != child.authority_sha256
        or admission_receipt.domain_sha256 != child.domain_sha256
        or admission_receipt.certificate_sha256 != certificate.certificate_sha256
        or admission_receipt.validator_version != certificate.validator_version
        or admission_receipt.validator_sha256 != certificate.validator_sha256
        or admission_receipt.subset_proof_sha256 != proposal.subset_proof.proof_sha256
        or admission_receipt.pre_residual_budget_sha256 != proposal.residual_budget.budget_sha256
        or admission_receipt.reserved_budget != proposal.planned_budget
        or admission_receipt.reservation_id is None
        or admission_receipt.lifecycle_epoch != proposal.lifecycle_epoch
        or admission_receipt.policy_revocation_epoch != proposal.policy_revocation_epoch
        or admission_receipt.roe_revocation_epoch != proposal.roe_revocation_epoch
        or admission_receipt.kill_switch_epoch != proposal.kill_switch_epoch
        or not admission_receipt.issued_at <= now < admission_receipt.expires_at
    ):
        raise ValueError("replan_child_admission_binding_mismatch")
    return _build_accepted_bounded_replan(
        proposal=proposal,
        child_admission_receipt_id=admission_receipt.receipt_id,
        child_admission_receipt_sha256=admission_receipt.receipt_sha256,
        reservation_id=admission_receipt.reservation_id,
    )


def prepare_bounded_replan(
    *,
    request: ReplanRequestV1,
    parent_revision: AttackPathDagRevisionV1,
    parent_admission_receipt: PlanAdmissionReceiptV1,
    authority: CampaignAuthorityEnvelopeV2,
    lifecycle: CampaignAuthorityLifecycleV2,
    domain: PlanningDomainV1,
    residual_budget: CampaignBudgetVectorV1,
    now: datetime,
) -> BoundedReplanResultV1:
    return _prepare_bounded_replan(
        request=request, parent_revision=parent_revision, parent_admission_receipt=parent_admission_receipt,
        authority=authority, lifecycle=lifecycle, domain=domain, residual_budget=residual_budget, now=now,
    )


def prepare_owned_bounded_replan(
    *, request: ReplanRequestV1, parent_revision: AttackPathDagRevisionV1,
    parent_admission_receipt: PlanAdmissionReceiptV1, authority: CampaignAuthorityEnvelopeV2,
    lifecycle: CampaignAuthorityLifecycleV2, domain: PlanningDomainV1,
    residual_budget: CampaignBudgetVectorV1, now: datetime,
    parent_completion_source: OwnedCompletionSourceV1 | None = None,
) -> BoundedReplanResultV1:
    parent_admission_at = now
    if parent_completion_source is not None:
        source = parent_completion_source
        if (not isinstance(source, OwnedCompletionSourceV1) or source.tenant_id != request.tenant_id
                or source.campaign_id != request.campaign_id or source.authority_sha256 != authority.authority_sha256
                or source.parent_revision_sha256 != parent_revision.revision_sha256 or source.domain_sha256 != domain.domain_sha256
                or source.plan_sha256 != parent_revision.candidate_plan.plan_sha256
                or source.snapshot.state not in {DagRunState.COMPLETED, DagRunState.CONTAINED}
                or source.snapshot.current_node_id is not None or source.verified_at > now
                or source.effect_receipt.completed_at is None or source.effect_receipt.completed_at > now
                or not parent_admission_receipt.issued_at <= source.effect_receipt.started_at <= source.effect_receipt.completed_at < parent_admission_receipt.expires_at
                or len(request.observation_history.trusted_observations) != 1):
            return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_historical_parent_source_invalid")
        observation = request.observation_history.trusted_observations[0]
        if (observation.source_execution_run_id != source.snapshot.execution_run_id or observation.source_node_id != source.node_id
                or observation.candidate.observed_at != source.effect_receipt.completed_at
                or observation.candidate.source_result_sha256 != source.effect_receipt.receipt_sha256
                or observation.candidate.evidence_sha256 != source.effect_receipt.receipt_sha256):
            return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_historical_parent_observation_invalid")
        parent_admission_at = source.effect_receipt.completed_at
    result = _prepare_bounded_replan(
        request=request, parent_revision=parent_revision, parent_admission_receipt=parent_admission_receipt,
        authority=authority, lifecycle=lifecycle, domain=domain, residual_budget=residual_budget, now=now,
        _owned_sequential=True,
        _parent_admission_at=parent_admission_at,
    )
    if result.proposal is None:
        return result
    observations = request.observation_history.trusted_observations
    completed_node_ids: list[str] = []
    for observation in observations:
        if observation.source_node_id is None:
            return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_strict_parent_subset_required")
        completed_node_ids.append(observation.source_node_id)
    try:
        prove_canonical_child_subset(
            parent=parent_revision, child=result.proposal.child_revision, domain=domain,
            completed_parent_node_ids=tuple(completed_node_ids),
            observed_values=tuple(FactValueV1(o.candidate.fact_id, o.candidate.value) for o in observations),
            observation_history_sha256=request.observation_history.history_sha256,
        )
    except ValueError:
        return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_strict_parent_subset_required")
    return result


def _prepare_bounded_replan(
    *, request: ReplanRequestV1, parent_revision: AttackPathDagRevisionV1,
    parent_admission_receipt: PlanAdmissionReceiptV1, authority: CampaignAuthorityEnvelopeV2,
    lifecycle: CampaignAuthorityLifecycleV2, domain: PlanningDomainV1,
    residual_budget: CampaignBudgetVectorV1, now: datetime, _owned_sequential: bool = False,
    _parent_admission_at: datetime | None = None,
) -> BoundedReplanResultV1:
    if (
        not isinstance(request, ReplanRequestV1)
        or not isinstance(parent_revision, AttackPathDagRevisionV1)
        or not isinstance(parent_admission_receipt, PlanAdmissionReceiptV1)
        or not isinstance(authority, CampaignAuthorityEnvelopeV2)
        or not isinstance(lifecycle, CampaignAuthorityLifecycleV2)
        or not isinstance(domain, PlanningDomainV1)
        or not isinstance(residual_budget, CampaignBudgetVectorV1)
    ):
        raise ValueError("replan_input_invalid")
    _aware(now)
    if _parent_admission_at is not None:
        _aware(_parent_admission_at)
        if not _owned_sequential or _parent_admission_at > now:
            raise ValueError("replan_historical_parent_clock_forbidden")
    parent_admission_at = now if _parent_admission_at is None else _parent_admission_at
    if _owned_sequential and (
        parent_revision.planner_version != OWNED_SEQUENTIAL_PLANNER_VERSION
        or parent_revision.planner_sha256 != OWNED_SEQUENTIAL_PLANNER_SHA256
        or parent_admission_receipt.validator_version != OWNED_SEQUENTIAL_VALIDATOR_VERSION
        or parent_admission_receipt.validator_sha256 != OWNED_SEQUENTIAL_VALIDATOR_SHA256
    ):
        return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_owned_profile_binding_mismatch")
    if _owned_sequential:
        try:
            search_limits = derive_owned_sequential_search_limits(domain, authority)
        except ValueError:
            return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_owned_profile_invalid")
    else:
        search_limits = derive_replan_search_limits(authority)
    if (
        request.parent_revision_id != parent_revision.revision_id
        or request.parent_revision_sha256 != parent_revision.revision_sha256
        or request.tenant_id != parent_revision.tenant_id
        or request.engagement_id != parent_revision.engagement_id
        or parent_revision.authority_sha256 != authority.authority_sha256
        or parent_revision.domain_sha256 != domain.domain_sha256
    ):
        return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_parent_binding_mismatch")
    if (
        parent_admission_receipt.outcome is not AdmissionOutcome.ADMITTED
        or request.parent_admission_receipt_id != parent_admission_receipt.receipt_id
        or request.parent_admission_receipt_sha256 != parent_admission_receipt.receipt_sha256
        or parent_admission_receipt.tenant_id != request.tenant_id
        or parent_admission_receipt.campaign_id != request.campaign_id
        or parent_admission_receipt.engagement_id != request.engagement_id
        or parent_admission_receipt.plan_sha256 != parent_revision.candidate_plan.plan_sha256
        or parent_admission_receipt.authority_sha256 != parent_revision.authority_sha256
        or parent_admission_receipt.domain_sha256 != parent_revision.domain_sha256
        # CRITICAL: only the sealed owned-source wrapper may supply historical completion; ordinary replanning needs a current parent grant.
        or not parent_admission_receipt.issued_at <= parent_admission_at < parent_admission_receipt.expires_at
    ):
        # CRITICAL: a same-campaign receipt for another plan is not parent execution authority.
        return _result(
            request,
            ReplanOutcome.MANUAL_REVIEW_REQUIRED,
            "replan_parent_admission_binding_mismatch",
        )
    lifecycle_error = _current_lifecycle_error(authority, lifecycle, now=now)
    if lifecycle_error is not None:
        return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, lifecycle_error)
    if request.consumed_replans >= authority.bounds.max_replans:
        return _result(request, ReplanOutcome.REPLAN_LIMIT_EXHAUSTED, "replan_limit_exhausted")
    history = request.observation_history
    if history.conflicted_fact_keys:
        return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_observation_conflict")
    if not history.trusted_observations:
        return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_trusted_observation_required")
    for observation in history.trusted_observations:
        candidate = observation.candidate
        if (
            candidate.tenant_id != request.tenant_id
            or candidate.campaign_id != request.campaign_id
            or candidate.engagement_id != request.engagement_id
            or candidate.authority_sha256 != authority.authority_sha256
            or candidate.target_id not in authority.target_ids
            or candidate.lifecycle_epoch != lifecycle.lifecycle_epoch
            or candidate.policy_revocation_epoch != lifecycle.policy_revocation_epoch
            or candidate.roe_revocation_epoch != lifecycle.roe_revocation_epoch
            or candidate.kill_switch_epoch != lifecycle.kill_switch_epoch
        ):
            return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_observation_binding_mismatch")
        if observation.promoted_at > now or now >= candidate.expires_at:
            return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_observation_expired")
        if _owned_sequential and (
            (now - candidate.observed_at).total_seconds() > 120
            or (candidate.expires_at - candidate.observed_at).total_seconds() > 120
            or candidate.expires_at > authority.expires_at
        ):
            return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_owned_observation_freshness_invalid")

    initial_state = _observation_state(parent_revision.candidate_plan.initial_state, history.trusted_observations)
    if _owned_sequential:
        try:
            planned = plan_owned_sequential_attack_path(domain, authority, initial_state, search_limits)
        except ValueError:
            return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_owned_profile_invalid")
    else:
        planned = plan_attack_path(domain, authority, initial_state, search_limits)
    if planned.outcome is not AttackPathPlannerOutcome.PLAN_FOUND or planned.revision is None:
        return _result(request, ReplanOutcome.NO_PLAN, f"replan_{planned.outcome.value}")
    child_revision = _bind_child_revision(
        planned.revision,
        parent_revision=parent_revision,
        observation_history_sha256=history.history_sha256,
    )
    search_receipt = replace(planned.receipt, found_revision_sha256=child_revision.revision_sha256)
    # CRITICAL: closed profile predicate checks use the fixed semantic ceiling, not a node/retry count.
    validation_limits = ValidationLimitsV1(2, 1, 32) if _owned_sequential else ValidationLimitsV1(
        max_nodes=authority.bounds.max_nodes,
        max_edges=authority.bounds.max_nodes,
        max_state_transitions=min(
            10_000_000,
            authority.bounds.max_nodes * (authority.bounds.max_retries_per_node + 1),
        ),
    )
    validator = validate_owned_sequential_candidate_plan if _owned_sequential else validate_candidate_plan
    certificate = validator(
        child_revision.candidate_plan,
        domain,
        authority,
        limits=validation_limits,
        validated_at=now,
    )
    subset_proof = build_plan_envelope_subset_proof(
        authority=authority,
        revision=child_revision,
        certificate=certificate,
    )
    if not certificate.admissible or not subset_proof.admissible:
        return _result(request, ReplanOutcome.MANUAL_REVIEW_REQUIRED, "replan_validation_not_valid")
    try:
        planned_budget = calculate_plan_budget(child_revision, domain)
    except ValueError:
        return _result(request, ReplanOutcome.EXPANSION_REQUIRED, "replan_budget_unprovable")
    # CRITICAL: every expansion, including a budget reset, pauses for new human-signed authority.
    if not planned_budget.fits_within(residual_budget):
        return _result(request, ReplanOutcome.EXPANSION_REQUIRED, "replan_residual_budget_exceeded")
    invalidated, retained, substitutions = _node_delta(parent_revision, child_revision)
    proposal = BoundedReplanProposalV1(
        schema_version=REPLAN_PROPOSAL_SCHEMA_VERSION,
        request_sha256=request.request_sha256,
        campaign_id=request.campaign_id,
        engagement_id=request.engagement_id,
        parent_revision_id=parent_revision.revision_id,
        parent_revision_sha256=parent_revision.revision_sha256,
        parent_plan_sha256=parent_revision.candidate_plan.plan_sha256,
        parent_authority_sha256=parent_revision.authority_sha256,
        parent_domain_sha256=parent_revision.domain_sha256,
        parent_admission_receipt_id=request.parent_admission_receipt_id,
        parent_admission_receipt_sha256=request.parent_admission_receipt_sha256,
        child_revision=child_revision,
        observation_history_sha256=history.history_sha256,
        trusted_observation_sha256s=tuple(
            sorted(item.observation_sha256 for item in history.trusted_observations)
        ),
        invalidated_parent_node_ids=invalidated,
        retained_parent_node_ids=retained,
        substitutions=substitutions,
        residual_budget=residual_budget,
        planned_budget=planned_budget,
        validation_certificate=certificate,
        subset_proof=subset_proof,
        search_receipt=search_receipt,
        replan_sequence=request.consumed_replans + 1,
        lifecycle_epoch=lifecycle.lifecycle_epoch,
        policy_revocation_epoch=lifecycle.policy_revocation_epoch,
        roe_revocation_epoch=lifecycle.roe_revocation_epoch,
        kill_switch_epoch=lifecycle.kill_switch_epoch,
    )
    return BoundedReplanResultV1(
        schema_version=REPLAN_RESULT_SCHEMA_VERSION,
        request_sha256=request.request_sha256,
        outcome=ReplanOutcome.CHILD_PROPOSED,
        reason_code="child_proposed",
        proposal=proposal,
    )


def derive_replan_search_limits(authority: CampaignAuthorityEnvelopeV2) -> PlannerSearchLimitsV1:
    if not isinstance(authority, CampaignAuthorityEnvelopeV2):
        raise ValueError("replan_search_authority_required")
    bounds = authority.bounds
    # CRITICAL: autonomous callers cannot widen search; limits derive only from signed authority.
    return PlannerSearchLimitsV1(
        max_expanded_states=bounds.max_nodes,
        max_generated_states=min(10_000_000, bounds.max_nodes * bounds.max_width),
        max_frontier=bounds.max_frontier,
        max_search_ticks=min(1_000_000_000, bounds.max_search_seconds * 1_000),
        max_memory_units=min(1_000_000_000, bounds.max_nodes + bounds.max_frontier),
        max_action_variants=bounds.max_width,
    )


def _bind_child_revision(
    candidate: AttackPathDagRevisionV1,
    *,
    parent_revision: AttackPathDagRevisionV1,
    observation_history_sha256: str,
) -> AttackPathDagRevisionV1:
    child_id = "revision-" + canonical_planning_sha256(
        (
            "redagent.bounded-replan-child/v1",
            parent_revision.revision_sha256,
            observation_history_sha256,
            candidate.candidate_plan.plan_sha256,
            candidate.planner_sha256,
        )
    )[:24]
    return replace(
        candidate,
        schema_version=ATTACK_PATH_DAG_SCHEMA_VERSION,
        revision_id=child_id,
        parent_revision_id=parent_revision.revision_id,
    )


def _observation_state(initial: WorldStateV1, observations: tuple[object, ...]) -> WorldStateV1:
    values = {item.fact_id: item.value for item in initial.values}
    for observation in observations:
        candidate = observation.candidate  # type: ignore[attr-defined]
        if candidate.fact_id not in values:
            raise ValueError("replan_observation_fact_unknown")
        values[candidate.fact_id] = candidate.value
    return WorldStateV1(tuple(FactValueV1(fact_id, value) for fact_id, value in sorted(values.items())))


def _node_key(node: object) -> tuple[object, ...]:
    return (
        node.operator_id,  # type: ignore[attr-defined]
        node.target_id,  # type: ignore[attr-defined]
        node.environment,  # type: ignore[attr-defined]
        node.arguments,  # type: ignore[attr-defined]
    )


def _node_delta(
    parent: AttackPathDagRevisionV1,
    child: AttackPathDagRevisionV1,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[NodeSubstitutionV1, ...]]:
    child_by_key = {_node_key(node): node for node in child.candidate_plan.nodes}
    invalidated: list[str] = []
    retained: list[str] = []
    substitutions: list[NodeSubstitutionV1] = []
    for node in parent.candidate_plan.nodes:
        replacement = child_by_key.get(_node_key(node))
        if replacement is None:
            invalidated.append(node.node_id)
        else:
            retained.append(node.node_id)
            if replacement.node_id != node.node_id:
                substitutions.append(
                    NodeSubstitutionV1(node.node_id, replacement.node_id, "observation_state_rebind")
                )
    return (
        tuple(sorted(invalidated)),
        tuple(sorted(retained)),
        tuple(sorted(substitutions, key=lambda item: (item.parent_node_id, item.child_node_id))),
    )


def _current_lifecycle_error(
    authority: CampaignAuthorityEnvelopeV2,
    lifecycle: CampaignAuthorityLifecycleV2,
    *,
    now: datetime,
) -> str | None:
    if lifecycle.authority_sha256 != authority.authority_sha256:
        return "campaign_lifecycle_authority_mismatch"
    if lifecycle.tenant_id != authority.tenant_id or lifecycle.engagement_id != authority.engagement_id:
        return "campaign_lifecycle_scope_mismatch"
    if lifecycle.state is not CampaignAuthorityLifecycleState.ACTIVE:
        return "campaign_authority_not_active"
    if (
        lifecycle.lifecycle_epoch != authority.lifecycle_epoch
        or lifecycle.policy_revocation_epoch != authority.policy_revocation_epoch
        or lifecycle.roe_revocation_epoch != authority.roe_revocation_epoch
        or lifecycle.kill_switch_epoch != authority.kill_switch_epoch
    ):
        return "campaign_lifecycle_epoch_mismatch"
    if not lifecycle.observed_at <= now < lifecycle.valid_until:
        return "campaign_lifecycle_observation_expired"
    if not authority.valid_from <= now < authority.expires_at:
        return "campaign_authority_expired"
    return None


def _result(
    request: ReplanRequestV1,
    outcome: ReplanOutcome,
    reason_code: str,
) -> BoundedReplanResultV1:
    return BoundedReplanResultV1(
        schema_version=REPLAN_RESULT_SCHEMA_VERSION,
        request_sha256=request.request_sha256,
        outcome=outcome,
        reason_code=reason_code,
        proposal=None,
    )


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("replan_now_timezone_required")
