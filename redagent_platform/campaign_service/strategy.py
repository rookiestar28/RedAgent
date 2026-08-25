"""Pure compat_121 deterministic strategy decision and bounded plan construction."""

from __future__ import annotations

from datetime import datetime, timedelta

from redagent_platform.agent_kernel.contracts import ProjectedTool, ToolKind
from redagent_platform.agent_kernel.registry import canonical_projected_tool_sha256
from redagent_platform.campaign_service.contracts import (
    AuthorityContextV1,
    CandidateDispositionV1,
    ConditionalSuccessorV1,
    CollectionState,
    DecisionContextSnapshotV1,
    InvalidationState,
    ModelStrategyProposalV1,
    ObservationKind,
    PlanActionV1,
    PlanRevisionV1,
    PromotedCapabilitySemanticsV1,
    StrategyBudgetV1,
    StrategyDecisionReceiptV1,
    StrategyObjectiveKind,
    StrategyObjectiveV1,
    StrategyOutcome,
    StrategySignalsV1,
    TruthValue,
    _validated_plan_revision,
    _validated_strategy_receipt,
    canonical_sha256,
)


DECISION_TABLE_REVISION = 1
_ZAP = "zap-controlled-runtime"
_NUCLEI = "nuclei-trusted-runtime"
_EXPECTED = {
    _ZAP: ("target_allowlist", "http_header", "high"),
    _NUCLEI: ("target_allowlist", "none", "high"),
}
_GLOBAL_STOPS = ("objective-satisfied", "budget-exhausted")


def decide_strategy(
    *,
    objective: StrategyObjectiveV1,
    snapshot: DecisionContextSnapshotV1,
    authority: AuthorityContextV1,
    projections: tuple[ProjectedTool, ...],
    budget: StrategyBudgetV1,
    signals: StrategySignalsV1,
    model_proposal: ModelStrategyProposalV1 | None,
    now: datetime,
) -> tuple[StrategyDecisionReceiptV1, PlanRevisionV1 | None]:
    """Return one deterministic receipt and at most one width-1/depth-2 plan."""
    _validate_inputs(
        objective=objective,
        snapshot=snapshot,
        authority=authority,
        projections=projections,
        now=now,
    )
    semantics = {item.binding_key.capability_id: item for item in snapshot.semantics}
    projected = {item.source_capability_id: item for item in projections}
    preferred = (
        _ZAP if objective.kind is StrategyObjectiveKind.HTTP_POSTURE else _NUCLEI
    )
    other = _NUCLEI if preferred == _ZAP else _ZAP

    if signals.stop_reason is not None:
        receipt = _build_receipt(
            objective=objective,
            snapshot=snapshot,
            authority=authority,
            semantics=semantics,
            preferred=preferred,
            outcome=StrategyOutcome.STOP,
            matched_rule="operational-stop",
            reason=signals.stop_reason,
            selected=None,
            successor=None,
        )
        _validate_model_proposal(model_proposal, receipt)
        _validate_strategy_result_structure(receipt=receipt, plan=None)
        return receipt, None

    terminal_reason = _terminal_outcome_reason(snapshot)
    if terminal_reason is not None:
        receipt = _build_receipt(
            objective=objective,
            snapshot=snapshot,
            authority=authority,
            semantics=semantics,
            preferred=preferred,
            outcome=StrategyOutcome.STOP,
            matched_rule="terminal-outcome-stop",
            reason=terminal_reason,
            selected=None,
            successor=None,
        )
        _validate_model_proposal(model_proposal, receipt)
        _validate_strategy_result_structure(receipt=receipt, plan=None)
        return receipt, None

    if not _budget_allows_primary(budget):
        receipt = _build_receipt(
            objective=objective,
            snapshot=snapshot,
            authority=authority,
            semantics=semantics,
            preferred=preferred,
            outcome=StrategyOutcome.STOP,
            matched_rule="budget-stop",
            reason="budget_exhausted",
            selected=None,
            successor=None,
        )
        _validate_model_proposal(model_proposal, receipt)
        _validate_strategy_result_structure(receipt=receipt, plan=None)
        return receipt, None

    if snapshot.collection_state is not CollectionState.COMPLETE and not snapshot.observations:
        receipt = _build_receipt(
            objective=objective,
            snapshot=snapshot,
            authority=authority,
            semantics=semantics,
            preferred=preferred,
            outcome=StrategyOutcome.SKIP,
            matched_rule="incomplete-skip",
            reason="insufficient_observation",
            selected=None,
            successor=None,
        )
        _validate_model_proposal(model_proposal, receipt)
        _validate_strategy_result_structure(receipt=receipt, plan=None)
        return receipt, None

    if _objective_satisfied(objective, snapshot):
        receipt = _build_receipt(
            objective=objective,
            snapshot=snapshot,
            authority=authority,
            semantics=semantics,
            preferred=preferred,
            outcome=StrategyOutcome.STOP,
            matched_rule="satisfied-stop",
            reason="objective_satisfied",
            selected=None,
            successor=None,
        )
        _validate_model_proposal(model_proposal, receipt)
        _validate_strategy_result_structure(receipt=receipt, plan=None)
        return receipt, None

    preferred_inconclusive = _has_inconclusive_outcome(snapshot, preferred)
    other_inconclusive = _has_inconclusive_outcome(snapshot, other)
    if preferred_inconclusive and other_inconclusive:
        receipt = _build_receipt(
            objective=objective,
            snapshot=snapshot,
            authority=authority,
            semantics=semantics,
            preferred=preferred,
            outcome=StrategyOutcome.STOP,
            matched_rule="all-inconclusive-stop",
            reason="all_candidates_inconclusive",
            selected=None,
            successor=None,
        )
        _validate_model_proposal(model_proposal, receipt)
        _validate_strategy_result_structure(receipt=receipt, plan=None)
        return receipt, None

    switched_after_inconclusive = preferred_inconclusive
    if switched_after_inconclusive:
        preferred, other = other, preferred

    successor_already_inconclusive = (
        preferred_inconclusive if switched_after_inconclusive else other_inconclusive
    )
    successor_capability = (
        other
        if not successor_already_inconclusive
        and budget.max_depth >= 2
        and budget.max_operations >= 2
        else None
    )
    selected_binding = canonical_sha256(semantics[preferred].binding_key)
    receipt = _build_receipt(
        objective=objective,
        snapshot=snapshot,
        authority=authority,
        semantics=semantics,
        preferred=preferred,
        outcome=StrategyOutcome.SELECT,
        matched_rule=(
            "select-after-inconclusive"
            if switched_after_inconclusive
            else "select-http-posture"
            if objective.kind is StrategyObjectiveKind.HTTP_POSTURE
            else "select-header-assertion"
        ),
        reason=(
            "primary_switched_after_inconclusive"
            if switched_after_inconclusive
            else "primary_selected"
        ),
        selected=selected_binding,
        successor=successor_capability,
        ineligible_reason=(
            "existing_inconclusive"
            if successor_already_inconclusive
            else "successor_budget_unavailable"
        ),
    )
    _validate_model_proposal(model_proposal, receipt)

    primary = _action(semantics[preferred], projected[preferred], budget)
    successor = None
    if successor_capability is not None:
        successor = ConditionalSuccessorV1(
            condition=(
                "explicit_corroboration"
                if objective.require_corroboration
                else "fresh_inconclusive_or_insufficient_observation"
            ),
            action=_action(
                semantics[successor_capability], projected[successor_capability], budget
            ),
        )
    plan_values: dict[str, object] = {
        "schema_version": "redagent.r121-plan-revision/v1",
        "plan_id": f"plan-{receipt.receipt_sha256[:24]}",
        "revision": 1,
        "tenant_id": objective.tenant_id,
        "engagement_id": objective.engagement_id,
        "target": objective.target,
        "objective_sha256": canonical_sha256(objective),
        "receipt_sha256": receipt.receipt_sha256,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "authority_sha256": snapshot.authority_sha256,
        "policy_revision": authority.policy_revision,
        "policy_sha256": authority.policy_sha256,
        "roe_version_id": authority.roe_version_id,
        "roe_sha256": authority.roe_sha256,
        "decision_table_revision": DECISION_TABLE_REVISION,
        "width": 1,
        "depth": 2 if successor is not None else 1,
        "primary": primary,
        "successor": successor,
    }
    plan = _validated_plan_revision(
        **plan_values,
        plan_sha256=canonical_sha256(plan_values),
    )
    _validate_strategy_result_structure(receipt=receipt, plan=plan)
    return receipt, plan


def validate_strategy_result(
    *,
    objective: StrategyObjectiveV1,
    current_snapshot: DecisionContextSnapshotV1,
    authority: AuthorityContextV1,
    projections: tuple[ProjectedTool, ...],
    budget: StrategyBudgetV1,
    signals: StrategySignalsV1,
    now: datetime,
    receipt: StrategyDecisionReceiptV1,
    plan: PlanRevisionV1 | None,
) -> None:
    """Recompute from current trusted inputs and reject any stale or forged result."""
    try:
        expected_receipt, expected_plan = decide_strategy(
            objective=objective,
            snapshot=current_snapshot,
            authority=authority,
            projections=projections,
            budget=budget,
            signals=signals,
            model_proposal=None,
            now=now,
        )
    except ValueError as exc:
        raise ValueError("r121_result_not_current") from exc
    if receipt != expected_receipt or plan != expected_plan:
        raise ValueError("r121_result_not_current")


def _validate_strategy_result_structure(
    *, receipt: StrategyDecisionReceiptV1, plan: PlanRevisionV1 | None
) -> None:
    if canonical_sha256(receipt.objective) != receipt.objective_sha256:
        raise ValueError("r121_receipt_objective_hash_mismatch")
    if (
        receipt.snapshot.snapshot_sha256 != receipt.snapshot_sha256
        or receipt.snapshot.capability_section_sha256 != receipt.capability_section_sha256
        or receipt.snapshot.trusted_section_sha256 != receipt.trusted_section_sha256
        or receipt.snapshot.authority_sha256 != receipt.authority_sha256
        or receipt.snapshot.target_mapping_sha256 != receipt.target_mapping_sha256
    ):
        raise ValueError("r121_receipt_snapshot_hash_mismatch")
    if receipt.receipt_sha256 != canonical_sha256(receipt.canonical_body()):
        raise ValueError("r121_receipt_digest_mismatch")
    if receipt.outcome is StrategyOutcome.SELECT:
        if plan is None:
            raise ValueError("r121_selected_plan_required")
        if plan.receipt_sha256 != receipt.receipt_sha256:
            raise ValueError("r121_plan_receipt_mismatch")
        if plan.objective_sha256 != receipt.objective_sha256:
            raise ValueError("r121_plan_objective_mismatch")
        if (
            plan.snapshot_sha256 != receipt.snapshot_sha256
            or plan.authority_sha256 != receipt.authority_sha256
            or plan.policy_revision != receipt.policy_revision
            or plan.policy_sha256 != receipt.policy_sha256
            or plan.roe_version_id != receipt.roe_version_id
            or plan.roe_sha256 != receipt.roe_sha256
            or plan.decision_table_revision != receipt.decision_table_revision
        ):
            raise ValueError("r121_plan_receipt_authority_mismatch")
        if plan.primary.binding_key_sha256 != receipt.selected_binding_sha256:
            raise ValueError("r121_plan_selection_mismatch")
        if plan.plan_sha256 != canonical_sha256(plan.canonical_body()):
            raise ValueError("r121_plan_digest_mismatch")
        if plan.width != 1 or plan.depth not in {1, 2}:
            raise ValueError("r121_plan_bounds_invalid")
        if plan.successor is not None and (
            plan.successor.action.binding_key_sha256 == plan.primary.binding_key_sha256
        ):
            raise ValueError("r121_plan_successor_redundant")
    elif plan is not None:
        raise ValueError("r121_nonselected_plan_forbidden")


def _validate_inputs(
    *,
    objective: StrategyObjectiveV1,
    snapshot: DecisionContextSnapshotV1,
    authority: AuthorityContextV1,
    projections: tuple[ProjectedTool, ...],
    now: datetime,
) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("r121_now_timezone_required")
    if (
        objective.tenant_id != authority.tenant_id
        or objective.engagement_id != authority.engagement_id
        or objective.target != authority.target
    ):
        raise ValueError("r121_objective_scope_mismatch")
    authority_sha256 = canonical_sha256(authority)
    if snapshot.authority_sha256 != authority_sha256:
        raise ValueError("r121_snapshot_authority_mismatch")
    if snapshot.target_mapping_sha256 != authority.target_mapping_sha256:
        raise ValueError("r121_snapshot_mapping_mismatch")
    if not authority.issued_at <= now < authority.expires_at:
        raise ValueError("r121_authority_not_current")
    if authority.policy_status != "allowed" or authority.roe_status != "approved":
        raise ValueError("r121_authority_denied")
    if now < snapshot.snapshot_at:
        raise ValueError("r121_snapshot_from_future")
    if canonical_sha256(snapshot.semantics) != snapshot.capability_section_sha256:
        raise ValueError("r121_snapshot_capability_digest_mismatch")
    expected_trusted = canonical_sha256({
        "collection_state": snapshot.collection_state,
        "observations": snapshot.observations,
        "evidence_facts": snapshot.evidence_facts,
        "finding_facts": snapshot.finding_facts,
        "dispositions": snapshot.dispositions,
        "conflicts": snapshot.conflicts,
    })
    if expected_trusted != snapshot.trusted_section_sha256:
        raise ValueError("r121_snapshot_trusted_digest_mismatch")
    semantics = {item.binding_key.capability_id: item for item in snapshot.semantics}
    if set(semantics) != set(_EXPECTED) or len(snapshot.semantics) != 2:
        raise ValueError("r121_semantics_set_mismatch")
    freshness = min(item.definition.freshness_seconds for item in snapshot.semantics)
    if now - snapshot.snapshot_at >= timedelta(seconds=freshness):
        raise ValueError("r121_snapshot_stale")
    for item in snapshot.semantics:
        if (
            item.promotion_status != "promoted"
            or item.revoked_at is not None
            or not item.promoted_at <= now < item.expires_at
        ):
            raise ValueError("r121_semantics_not_current")
    _validate_fact_currency(snapshot=snapshot, semantics=semantics, now=now)
    projected = {item.source_capability_id: item for item in projections}
    if set(projected) != set(_EXPECTED) or len(projections) != 2:
        raise ValueError("r121_projection_set_mismatch")
    for capability_id, sidecar in semantics.items():
        tool = projected[capability_id]
        expected_network, expected_credential, expected_approval = _EXPECTED[capability_id]
        if (
            tool.tool_kind is not ToolKind.PROPOSAL
            or tool.source_capability_revision != sidecar.binding_key.capability_revision
            or tool.adapter_id != sidecar.binding_key.adapter_id
            or tool.adapter_version != sidecar.binding_key.adapter_version
            or tool.network_mode != expected_network
            or tool.credential_class != expected_credential
            or tool.approval_tier != expected_approval
            or canonical_projected_tool_sha256(tool) != sidecar.binding_key.projection_sha256
        ):
            raise ValueError("r121_projection_binding_mismatch")


def _budget_allows_primary(budget: StrategyBudgetV1) -> bool:
    return (
        budget.max_elapsed_seconds >= 30
        and budget.max_operations >= 1
        and budget.max_targets == 1
        and budget.max_evidence_bytes >= 4096
        and budget.max_depth >= 1
    )


def _objective_satisfied(
    objective: StrategyObjectiveV1, snapshot: DecisionContextSnapshotV1
) -> bool:
    for item in snapshot.observations:
        if item.truth not in {TruthValue.TRUE, TruthValue.FALSE}:
            continue
        if objective.kind is StrategyObjectiveKind.SECURITY_HEADER_ASSERTION:
            if (
                item.kind in {
                    ObservationKind.SECURITY_HEADER_PRESENT,
                    ObservationKind.SECURITY_HEADER_MISSING,
                }
                and item.object.reference_id == objective.header_code
            ):
                return True
        elif item.kind in {
            ObservationKind.TARGET_REACHABILITY,
            ObservationKind.HTTP_RESPONSE_STATUS,
            ObservationKind.SECURITY_HEADER_PRESENT,
            ObservationKind.SECURITY_HEADER_MISSING,
        }:
            return True
    return False


def _has_inconclusive_outcome(
    snapshot: DecisionContextSnapshotV1, capability_id: str
) -> bool:
    return any(
        item.kind is ObservationKind.CAPABILITY_OUTCOME
        and item.object.reference_id == capability_id
        and item.truth is TruthValue.TRUE
        and item.value_code == "inconclusive"
        for item in snapshot.observations
    )


def _terminal_outcome_reason(snapshot: DecisionContextSnapshotV1) -> str | None:
    outcomes = {
        item.value_code
        for item in snapshot.observations
        if item.kind is ObservationKind.CAPABILITY_OUTCOME
        and item.truth is TruthValue.TRUE
    }
    if "failed" in outcomes:
        return "capability_failed"
    if "cancelled" in outcomes:
        return "capability_cancelled"
    return None


def _validate_fact_currency(
    *,
    snapshot: DecisionContextSnapshotV1,
    semantics: dict[str, PromotedCapabilitySemanticsV1],
    now: datetime,
) -> None:
    by_binding = {
        canonical_sha256(sidecar.binding_key): sidecar for sidecar in semantics.values()
    }
    evidence_by_ref = {
        (item.evidence.reference_id, item.evidence.sha256): item
        for item in snapshot.evidence_facts
    }
    for observation in snapshot.observations:
        sidecar = by_binding.get(observation.binding_key_sha256)
        evidence = evidence_by_ref.get(
            (observation.evidence.reference_id, observation.evidence.sha256)
        )
        if sidecar is None or evidence is None:
            raise ValueError("r121_observation_binding_or_evidence_mismatch")
        freshness = timedelta(seconds=sidecar.definition.freshness_seconds)
        if (
            not observation.observed_at <= now < observation.expires_at
            or now - observation.observed_at >= freshness
            or not evidence.finalized_at <= now < evidence.expires_at
            or evidence.invalidation_state is not InvalidationState.CURRENT
        ):
            raise ValueError("r121_observation_or_evidence_not_current")


def _build_receipt(
    *,
    objective: StrategyObjectiveV1,
    snapshot: DecisionContextSnapshotV1,
    authority: AuthorityContextV1,
    semantics: dict[str, PromotedCapabilitySemanticsV1],
    preferred: str,
    outcome: StrategyOutcome,
    matched_rule: str,
    reason: str,
    selected: str | None,
    successor: str | None,
    ineligible_reason: str = "not_actionable",
) -> StrategyDecisionReceiptV1:
    dispositions = tuple(sorted((
        CandidateDispositionV1(
            binding_key_sha256=canonical_sha256(sidecar.binding_key),
            capability_id=capability_id,
            eligible=(
                outcome is StrategyOutcome.SELECT
                and (
                    selected == canonical_sha256(sidecar.binding_key)
                    or capability_id == successor
                )
            ),
            deterministic_priority=1 if capability_id == preferred else 2,
            matched_rule=matched_rule,
            reason=(
                "selected_candidate"
                if selected == canonical_sha256(sidecar.binding_key)
                else "eligible_successor"
                if capability_id == successor
                else ineligible_reason
                if outcome is StrategyOutcome.SELECT
                else reason
            ),
        )
        for capability_id, sidecar in semantics.items()
    ), key=lambda item: item.binding_key_sha256))
    values: dict[str, object] = {
        "schema_version": "redagent.r121-strategy-receipt/v1",
        "objective": objective,
        "objective_sha256": canonical_sha256(objective),
        "snapshot": snapshot,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "capability_section_sha256": snapshot.capability_section_sha256,
        "trusted_section_sha256": snapshot.trusted_section_sha256,
        "authority_sha256": snapshot.authority_sha256,
        "target_mapping_sha256": snapshot.target_mapping_sha256,
        "policy_revision": authority.policy_revision,
        "policy_sha256": authority.policy_sha256,
        "roe_version_id": authority.roe_version_id,
        "roe_sha256": authority.roe_sha256,
        "decision_table_revision": DECISION_TABLE_REVISION,
        "candidates": dispositions,
        "outcome": outcome,
        "matched_rule": matched_rule,
        "reason": reason,
        "selected_binding_sha256": selected,
    }
    return _validated_strategy_receipt(
        **values,
        receipt_sha256=canonical_sha256(values),
    )


def _action(
    sidecar: PromotedCapabilitySemanticsV1,
    projection: ProjectedTool,
    budget: StrategyBudgetV1,
) -> PlanActionV1:
    return PlanActionV1(
        binding_key_sha256=canonical_sha256(sidecar.binding_key),
        capability_id=sidecar.binding_key.capability_id,
        profile_id=sidecar.binding_key.profile_id,
        projection_sha256=sidecar.binding_key.projection_sha256,
        approval_class=projection.approval_tier,
        evidence_schemas=sidecar.definition.evidence_schemas,
        budget=budget,
        cleanup=sidecar.definition.cleanup,
        stop_predicates=tuple(sorted(set((*sidecar.definition.stop_conditions, *_GLOBAL_STOPS)))),
    )


def _validate_model_proposal(
    proposal: ModelStrategyProposalV1 | None,
    receipt: StrategyDecisionReceiptV1,
) -> None:
    if proposal is not None and (
        proposal.outcome is not receipt.outcome
        or proposal.selected_binding_sha256 != receipt.selected_binding_sha256
    ):
        raise ValueError("r121_model_proposal_mismatch")
