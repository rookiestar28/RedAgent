"""Explicit closed owned-sequential profile; generic planner/validator semantics stay unchanged."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib

from redagent_platform.campaign_service.authority_envelope import CampaignAuthorityEnvelopeV2
from redagent_platform.campaign_service.child_replan_contracts import OWNED_COMPLETION_FACTS
from redagent_platform.campaign_service.registry import closed_execution_binding_for
from redagent_platform.campaign_service.planning.contracts import (
    CandidatePlanV1, PlanValidationCertificateV1, PlanningDomainV1, ScalarType, ValidationLimitsV1,
    ValidationResult, WorldStateV1, canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search import _search_attack_path
from redagent_platform.campaign_service.planning.search_contracts import (
    AttackPathPlannerResultV1, PlannerSearchLimitsV1,
)
from redagent_platform.campaign_service.planning.validation import _certificate, _validate_candidate_plan


OWNED_SEQUENTIAL_PLANNER_VERSION = "redagent-owned-sequential-planner.v1"
OWNED_SEQUENTIAL_PLANNER_SHA256 = hashlib.sha256(
    b"redagent-owned-sequential-planner/v1:deterministic-baseline-fixed-profiles-chain-two-whole-minute-request-proof"
).hexdigest()
OWNED_SEQUENTIAL_VALIDATOR_VERSION = "redagent-owned-sequential-validator.v1"
OWNED_SEQUENTIAL_VALIDATOR_SHA256 = hashlib.sha256(
    b"redagent-owned-sequential-validator/v1:independent-default-state-authority-checks-fixed-profiles-chain-two-whole-minute-request-proof"
).hexdigest()


def _domain_error(domain: PlanningDomainV1, authority: CampaignAuthorityEnvelopeV2) -> str | None:
    if not isinstance(domain, PlanningDomainV1) or not isinstance(authority, CampaignAuthorityEnvelopeV2):
        return "owned_sequential_input_invalid"
    bounds = authority.bounds
    if (not 1 <= len(domain.operators) <= 2 or len(authority.target_ids) != 1
            or bounds.max_width != 1 or bounds.max_nodes > 2 or bounds.max_depth > 2
            or bounds.max_rate_per_minute != 60 or bounds.max_concurrency != 1
            or bounds.max_requests > 60 or bounds.max_duration_seconds > 180 or bounds.max_replans > 1):
        return "owned_sequential_scope_invalid"
    seen = set()
    for operator in domain.operators:
        capability = operator.capability
        fact = OWNED_COMPLETION_FACTS.get(capability.capability_id)
        profile = "zap-passive-v1" if capability.capability_id == "zap-controlled-runtime" else "nuclei-http-header-v1"
        if (fact is None or capability.capability_id in seen or capability.capability_revision != 3
                or capability.profile_id != profile or capability.profile_revision != 1):
            return "owned_sequential_capability_invalid"
        current = closed_execution_binding_for(capability.capability_id)
        # CRITICAL: logical profile names alone admit substituted adapters or stale bundles; pin the complete registry identity.
        if any(getattr(capability, name) != getattr(current, name) for name in (
            "capability_revision", "adapter_id", "adapter_version", "profile_id", "profile_revision",
            "profile_sha256", "bundle_id", "bundle_revision", "bundle_sha256",
        )):
            return "owned_sequential_capability_invalid"
        seen.add(capability.capability_id)
        if (len(operator.parameters) != 1 or operator.target_parameter_name != "target"
                or operator.parameters[0].name != "target" or not operator.parameters[0].required
                or not operator.parameters[0].binds_target or operator.parameters[0].value_type is not ScalarType.STRING
                or operator.parameters[0].allowed_values or operator.parameters[0].minimum is not None
                or operator.parameters[0].maximum is not None or operator.unsupported_condition_ids):
            return "owned_sequential_parameter_contract_invalid"
        if (operator.effect_class.value != "read_only_observation" or operator.data_access_class.value != "metadata_only"
                or operator.credential_class.value != "none" or not operator.executable
                or operator.cleanup_mode.value != "required"
                or tuple(e.value for e in operator.supported_environments) != ("synthetic_loopback",)):
            return "owned_sequential_effect_class_invalid"
        if (operator.max_duration_seconds != 60 or operator.max_requests != 20
                or operator.max_rate_per_minute != 60 or operator.concurrency_weight != 1 or operator.max_retries != 0
                or operator.max_rate_per_minute > authority.bounds.max_rate_per_minute):
            return "owned_sequential_fixed_bound_invalid"
        minimum_evidence = (10 if capability.capability_id == "zap-controlled-runtime" else 2) * 1024 * 1024
        if operator.max_evidence_bytes != minimum_evidence or operator.max_data_bytes != 20 * 1024 * 1024:
            return "owned_sequential_evidence_bound_invalid"
        if (len(operator.effects) != 1 or operator.effects[0].fact_id != fact
                or operator.effects[0].value.value_type is not ScalarType.BOOLEAN
                or operator.effects[0].value.value is not True or operator.observation_fact_ids != (fact,)):
            return "owned_sequential_completion_fact_invalid"
    return None


def derive_owned_sequential_search_limits(
    domain: PlanningDomainV1, authority: CampaignAuthorityEnvelopeV2,
) -> PlannerSearchLimitsV1:
    reason = _domain_error(domain, authority)
    if reason is not None:
        raise ValueError(reason)
    actions, nodes = len(domain.operators), authority.bounds.max_nodes
    # CRITICAL: catalog/retained-label/proposal allocations are distinct from width1 physical execution.
    return PlannerSearchLimitsV1(
        max_expanded_states=nodes, max_generated_states=nodes * actions,
        max_frontier=1, max_action_variants=actions,
        max_memory_units=actions + (nodes + 1) + 1 + 4 * nodes + 2,
        max_search_ticks=min(authority.bounds.max_search_seconds * 1000, 10000),
    )


def _chain_error(plan: CandidatePlanV1, domain: PlanningDomainV1, authority: CampaignAuthorityEnvelopeV2) -> str | None:
    if not isinstance(plan, CandidatePlanV1) or not 1 <= len(plan.nodes) <= 2:
        return "owned_sequential_chain_required"
    expected = {(a.node_id, b.node_id) for a, b in zip(plan.nodes, plan.nodes[1:])}
    if (len(plan.edges) != len(expected)
            or {(e.source_node_id, e.target_node_id) for e in plan.edges} != expected
            or tuple(n.order for n in plan.nodes) != tuple(range(len(plan.nodes)))):
        return "owned_sequential_chain_required"
    operators = {o.operator_id: o for o in domain.operators}
    if any(n.operator_id not in operators for n in plan.nodes):
        return "owned_sequential_operator_unknown"
    requests = sum(operators[n.operator_id].max_requests for n in plan.nodes)
    if requests > min(authority.bounds.max_requests, authority.bounds.max_rate_per_minute):
        return "owned_sequential_aggregate_rate_exceeded"
    return None


def plan_owned_sequential_attack_path(
    domain: PlanningDomainV1, authority: CampaignAuthorityEnvelopeV2,
    initial_state: WorldStateV1, limits: PlannerSearchLimitsV1,
) -> AttackPathPlannerResultV1:
    reason = _domain_error(domain, authority)
    if reason is not None:
        raise ValueError(reason)
    # CRITICAL: private peak accounting is reachable only through this fixed-profile versioned contract.
    result = _search_attack_path(domain, authority, initial_state, limits, _owned_peak_rate=True)
    revision = result.revision
    if revision is not None:
        reason = _chain_error(revision.candidate_plan, domain, authority)
        if reason is not None:
            raise ValueError(reason)
        revision = replace(revision, planner_version=OWNED_SEQUENTIAL_PLANNER_VERSION,
                           planner_sha256=OWNED_SEQUENTIAL_PLANNER_SHA256,
                           revision_id="revision-" + canonical_planning_sha256(
                               (OWNED_SEQUENTIAL_PLANNER_SHA256, revision.candidate_plan.plan_sha256))[:24])
    receipt = replace(result.receipt, planner_version=OWNED_SEQUENTIAL_PLANNER_VERSION,
                      planner_sha256=OWNED_SEQUENTIAL_PLANNER_SHA256,
                      found_revision_sha256=None if revision is None else revision.revision_sha256)
    return replace(result, revision=revision, receipt=receipt)


def validate_owned_sequential_candidate_plan(
    plan: CandidatePlanV1, domain: PlanningDomainV1, authority: CampaignAuthorityEnvelopeV2,
    *, limits: ValidationLimitsV1, validated_at: datetime,
) -> PlanValidationCertificateV1:
    if not isinstance(plan, CandidatePlanV1) or not isinstance(domain, PlanningDomainV1) or not isinstance(authority, CampaignAuthorityEnvelopeV2):
        raise ValueError("owned_sequential_input_invalid")
    reason = _domain_error(domain, authority) or _chain_error(plan, domain, authority)
    if reason is not None:
        certificate = _certificate(plan, domain, authority, validated_at, ValidationResult.INVALID,
                                   (), {(reason, None)}, None)
    else:
        # CRITICAL: simple-chain and whole-plan request proof precede peak accounting; no failure is waived.
        certificate = _validate_candidate_plan(plan, domain, authority, limits=limits,
                                               validated_at=validated_at, _owned_peak_rate=True)
    return replace(certificate, validator_version=OWNED_SEQUENTIAL_VALIDATOR_VERSION,
                   validator_sha256=OWNED_SEQUENTIAL_VALIDATOR_SHA256)
