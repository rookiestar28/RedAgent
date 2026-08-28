from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.campaign_service.authority_envelope import (
    CampaignApproverRequirementV2,
    CampaignAuthorityBoundsV2,
    CampaignAuthorityEnvelopeV2,
    CampaignCredentialClass,
    CampaignDataAccessClass,
    CampaignEffectClass,
    CampaignEnvironmentClass,
    CampaignSafetyRequirementsV2,
)
from redagent_platform.campaign_service.planning.contracts import (
    CandidatePlanV1,
    CapabilityIdentityV1,
    CapabilityOperatorV1,
    CleanupMode,
    FactAssignmentV1,
    FactDefinitionV1,
    FactValueV1,
    PlanEdgeV1,
    PlanJoinPolicy,
    PlanNodeV1,
    PlanningDomainV1,
    PlanningObjectiveV1,
    PredicateOperator,
    PredicateV1,
    ScalarType,
    ScalarValueV1,
    TypedParameterBindingV1,
    TypedParameterSpecV1,
    ValidationCounterexampleV1,
    ValidationLimitsV1,
    ValidationResult,
    WorldStateV1,
    canonical_planning_bytes,
)
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
NOW = datetime(2026, 8, 29, 8, 0, tzinfo=timezone.utc)


def scalar(value_type: ScalarType, value: bool | int | str) -> ScalarValueV1:
    return ScalarValueV1(value_type=value_type, value=value)


def predicate(
    fact_id: str,
    value_type: ScalarType,
    value: bool | int | str,
    operator: PredicateOperator = PredicateOperator.EQUALS,
) -> PredicateV1:
    return PredicateV1(
        fact_id=fact_id,
        operator=operator,
        expected=scalar(value_type, value),
    )


def capability() -> CapabilityIdentityV1:
    return CapabilityIdentityV1(
        capability_id="artifact-posture",
        capability_revision=1,
        adapter_id="redagent-canonical-artifact",
        adapter_version="1.0.0",
        execution_manifest_sha256=SHA_A,
        profile_id="repository-snapshot",
        profile_revision=1,
        profile_sha256=SHA_B,
        bundle_id=None,
        bundle_revision=None,
        bundle_sha256=None,
    )


def operator(**overrides: object) -> CapabilityOperatorV1:
    values: dict[str, object] = {
        "schema_version": "redagent.capability-operator/v1",
        "operator_id": "collect-artifact-posture",
        "capability": capability(),
        "parameters": (
            TypedParameterSpecV1(
                name="target",
                value_type=ScalarType.STRING,
                required=True,
                allowed_values=(),
                minimum=None,
                maximum=None,
                binds_target=True,
            ),
        ),
        "preconditions": (predicate("authorized", ScalarType.BOOLEAN, True),),
        "effects": (FactAssignmentV1("posture-collected", scalar(ScalarType.BOOLEAN, True)),),
        "effect_class": CampaignEffectClass.READ_ONLY_OBSERVATION,
        "executable": True,
        "target_parameter_name": "target",
        "data_access_class": CampaignDataAccessClass.METADATA_ONLY,
        "credential_class": CampaignCredentialClass.NONE,
        "supported_environments": (CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,),
        "max_duration_seconds": 10,
        "max_requests": 1,
        "max_rate_per_minute": 1,
        "concurrency_weight": 1,
        "max_retries": 0,
        "max_risk_micropoints": 10,
        "max_cost_microunits": 100,
        "max_evidence_bytes": 1_024,
        "max_data_bytes": 512,
        "idempotent": True,
        "cleanup_mode": CleanupMode.REQUIRED,
        "observation_fact_ids": ("posture-collected",),
        "unsupported_condition_ids": (),
    }
    values.update(overrides)
    return CapabilityOperatorV1(**values)  # type: ignore[arg-type]


def domain(**overrides: object) -> PlanningDomainV1:
    values: dict[str, object] = {
        "schema_version": "redagent.planning-domain/v1",
        "domain_id": "artifact-posture-domain",
        "domain_revision": 1,
        "facts": (
            FactDefinitionV1("authorized", ScalarType.BOOLEAN, ()),
            FactDefinitionV1("finding-count", ScalarType.INTEGER, ()),
            FactDefinitionV1("posture-collected", ScalarType.BOOLEAN, ()),
        ),
        "operators": (operator(),),
        "invariants": (predicate("authorized", ScalarType.BOOLEAN, True),),
        "objective": PlanningObjectiveV1(
            objective_id="collect-posture",
            required_predicates=(predicate("posture-collected", ScalarType.BOOLEAN, True),),
            forbidden_predicates=(predicate("authorized", ScalarType.BOOLEAN, False),),
        ),
    }
    values.update(overrides)
    return PlanningDomainV1(**values)  # type: ignore[arg-type]


def world() -> WorldStateV1:
    return WorldStateV1(
        values=(
            FactValueV1("authorized", scalar(ScalarType.BOOLEAN, True)),
            FactValueV1("finding-count", scalar(ScalarType.INTEGER, 0)),
            FactValueV1("posture-collected", scalar(ScalarType.BOOLEAN, False)),
        )
    )


def plan(current_domain: PlanningDomainV1 | None = None, **overrides: object) -> CandidatePlanV1:
    current_domain = current_domain or domain()
    values: dict[str, object] = {
        "schema_version": "redagent.candidate-plan/v1",
        "plan_id": "plan-a",
        "tenant_id": "tenant-a",
        "engagement_id": "engagement-a",
        "authority_sha256": SHA_C,
        "domain_sha256": current_domain.domain_sha256,
        "objective_id": "collect-posture",
        "initial_state": world(),
        "nodes": (
            PlanNodeV1(
                schema_version="redagent.plan-node/v1",
                node_id="node-a",
                operator_id="collect-artifact-posture",
                target_id="target-a",
                environment=CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,
                arguments=(TypedParameterBindingV1("target", scalar(ScalarType.STRING, "target-a")),),
                order=0,
                join_policy=PlanJoinPolicy.ALL,
            ),
        ),
        "edges": (),
    }
    values.update(overrides)
    return CandidatePlanV1(**values)  # type: ignore[arg-type]


def test_scalar_types_are_exact_and_never_coerce_bool_as_integer() -> None:
    assert scalar(ScalarType.BOOLEAN, True).value is True
    assert scalar(ScalarType.INTEGER, 7).value == 7
    assert scalar(ScalarType.STRING, "target-a").value == "target-a"
    with pytest.raises(ValueError, match="planning_scalar_value_type_mismatch"):
        scalar(ScalarType.INTEGER, True)
    with pytest.raises(ValueError, match="planning_scalar_string_invalid"):
        scalar(ScalarType.STRING, "curl https://example.invalid")


def test_domain_and_plan_are_canonical_immutable_and_digest_bound() -> None:
    first_domain = domain()
    first_plan = plan(first_domain)
    assert first_domain.domain_sha256 == domain().domain_sha256
    assert first_plan.plan_sha256 == plan(first_domain).plan_sha256
    assert b'"operator_id":"collect-artifact-posture"' in canonical_planning_bytes(first_domain)
    assert first_plan.domain_sha256 == first_domain.domain_sha256
    with pytest.raises(FrozenInstanceError):
        first_plan.plan_id = "changed"  # type: ignore[misc]
    assert replace(first_plan, tenant_id="tenant-b").plan_sha256 != first_plan.plan_sha256


def test_domain_rejects_unknown_versions_noncanonical_catalogs_and_unknown_facts() -> None:
    with pytest.raises(ValueError, match="planning_domain_schema_unsupported"):
        replace(domain(), schema_version="redagent.planning-domain/v2")
    with pytest.raises(ValueError, match="planning_domain_facts_not_canonical"):
        domain(facts=tuple(reversed(domain().facts)))
    unknown = replace(operator(), preconditions=(predicate("missing", ScalarType.BOOLEAN, True),))
    with pytest.raises(ValueError, match="planning_domain_fact_unknown"):
        domain(operators=(unknown,))


def test_operator_rejects_contradictory_effects_and_missing_cleanup() -> None:
    contradictory = (
        FactAssignmentV1("posture-collected", scalar(ScalarType.BOOLEAN, False)),
        FactAssignmentV1("posture-collected", scalar(ScalarType.BOOLEAN, True)),
    )
    with pytest.raises(ValueError, match="capability_operator_effects_contradictory"):
        operator(effects=contradictory)
    with pytest.raises(ValueError, match="capability_operator_cleanup_required"):
        operator(cleanup_mode=CleanupMode.NONE)


def test_operator_contract_has_no_executable_or_opaque_extension_field() -> None:
    names = {field.name for field in fields(CapabilityOperatorV1)}
    assert not names.intersection(
        {"callback", "callable", "command", "code", "payload", "plugin", "transport", "arguments_mapping"}
    )


def test_plan_rejects_duplicate_nodes_edges_and_noncanonical_arguments() -> None:
    current = plan()
    with pytest.raises(ValueError, match="candidate_plan_node_duplicate"):
        replace(current, nodes=(current.nodes[0], current.nodes[0]))
    edge = PlanEdgeV1(
        schema_version="redagent.plan-edge/v1",
        edge_id="edge-a",
        source_node_id="node-a",
        target_node_id="node-b",
        conditions=(),
    )
    with pytest.raises(ValueError, match="candidate_plan_edge_duplicate"):
        replace(current, edges=(edge, edge))


def test_validation_limits_are_strict_positive_bounded_integers() -> None:
    limits = ValidationLimitsV1(max_nodes=10, max_edges=20, max_state_transitions=100)
    assert limits.max_state_transitions == 100
    with pytest.raises(ValueError, match="validation_limit_max_nodes_invalid"):
        replace(limits, max_nodes=True)  # type: ignore[arg-type]


def authority(**overrides: object) -> CampaignAuthorityEnvelopeV2:
    values: dict[str, object] = {
        "schema_version": "redagent.campaign-authority-envelope/v2",
        "canonicalization_version": "redagent.canonical-json/v1",
        "envelope_id": "authority-a",
        "tenant_id": "tenant-a",
        "engagement_id": "engagement-a",
        "target_ids": ("target-a",),
        "capability_ids": ("artifact-posture",),
        "objective_ids": ("collect-posture",),
        "success_condition_ids": ("posture-collected",),
        "allowed_effect_classes": (CampaignEffectClass.READ_ONLY_OBSERVATION,),
        "forbidden_effect_classes": (CampaignEffectClass.DISRUPTIVE,),
        "allowed_data_access_classes": (CampaignDataAccessClass.METADATA_ONLY,),
        "allowed_credential_classes": (CampaignCredentialClass.NONE,),
        "allowed_environment_classes": (CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,),
        "valid_from": NOW,
        "expires_at": NOW + timedelta(minutes=1),
        "bounds": CampaignAuthorityBoundsV2(
            max_duration_seconds=60,
            max_search_seconds=10,
            max_depth=4,
            max_width=4,
            max_nodes=8,
            max_frontier=4,
            max_replans=1,
            max_retries_per_node=1,
            max_requests=10,
            max_rate_per_minute=10,
            max_concurrency=2,
            max_risk_micropoints=1_000,
            max_cost_microunits=10_000,
            max_evidence_bytes=10_000,
            max_data_bytes=10_000,
        ),
        "required_approvers": (CampaignApproverRequirementV2("approver-a", "campaign-owner"),),
        "safety_requirements": CampaignSafetyRequirementsV2(
            evidence_required=True,
            report_safe_redaction_required=True,
            cleanup_required=True,
            containment_required=True,
            terminal_receipt_required=True,
            stop_on_authority_drift=True,
        ),
        "policy_bundle_sha256": SHA_A,
        "policy_revision": "policy-a",
        "policy_revocation_epoch": 1,
        "roe_sha256": SHA_B,
        "roe_revocation_epoch": 1,
        "lifecycle_epoch": 1,
        "kill_switch_epoch": 1,
        "nonce": "authority-nonce-a",
        "parent_authority_sha256": None,
        "expansion_requires_new_approval": True,
    }
    values.update(overrides)
    return CampaignAuthorityEnvelopeV2(**values)  # type: ignore[arg-type]


def bound_plan(current_domain: PlanningDomainV1 | None = None, **overrides: object) -> CandidatePlanV1:
    current_domain = current_domain or domain()
    values: dict[str, object] = {"authority_sha256": authority().authority_sha256}
    values.update(overrides)
    return plan(current_domain, **values)


def limits(**overrides: int) -> ValidationLimitsV1:
    values = {"max_nodes": 100, "max_edges": 200, "max_state_transitions": 1_000}
    values.update(overrides)
    return ValidationLimitsV1(**values)


def counterexample_codes(certificate: object) -> tuple[str, ...]:
    return tuple(item.code for item in certificate.counterexamples)  # type: ignore[attr-defined]


def test_independent_validator_emits_deterministic_admissible_certificate() -> None:
    current_domain = domain()
    current_plan = bound_plan(current_domain)
    first = validate_candidate_plan(
        current_plan,
        current_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    repeated = validate_candidate_plan(
        current_plan,
        current_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert first.result is ValidationResult.VALID
    assert first.admissible is True
    assert first.certificate_sha256 == repeated.certificate_sha256
    assert first.plan_sha256 == current_plan.plan_sha256
    assert first.domain_sha256 == current_domain.domain_sha256
    assert first.authority_sha256 == authority().authority_sha256


@pytest.mark.parametrize(
    ("plan_overrides", "code"),
    (
        ({"tenant_id": "tenant-b"}, "binding_mismatch:tenant_id"),
        ({"engagement_id": "engagement-b"}, "binding_mismatch:engagement_id"),
        ({"authority_sha256": SHA_C}, "binding_mismatch:authority_sha256"),
        ({"domain_sha256": SHA_C}, "binding_mismatch:domain_sha256"),
        ({"objective_id": "other-objective"}, "binding_mismatch:objective_id"),
    ),
)
def test_validator_rejects_digest_identity_and_objective_substitution(
    plan_overrides: dict[str, object], code: str
) -> None:
    current_domain = domain()
    certificate = validate_candidate_plan(
        bound_plan(current_domain, **plan_overrides),
        current_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert certificate.result is ValidationResult.INVALID
    assert certificate.admissible is False
    assert code in counterexample_codes(certificate)


@pytest.mark.parametrize("unknown", (False, True))
def test_false_or_unknown_precondition_never_satisfies_operator(unknown: bool) -> None:
    values = list(world().values)
    values[0] = FactValueV1(
        "authorized",
        None if unknown else scalar(ScalarType.BOOLEAN, False),
    )
    current_domain = domain()
    certificate = validate_candidate_plan(
        bound_plan(current_domain, initial_state=WorldStateV1(tuple(values))),
        current_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert certificate.result is ValidationResult.INVALID
    assert ("operator_precondition_unknown" if unknown else "operator_precondition_false") in counterexample_codes(
        certificate
    )


def test_validator_applies_domain_effects_and_rejects_unsatisfied_goal_or_invariant() -> None:
    false_effect = replace(
        operator(),
        effects=(FactAssignmentV1("posture-collected", scalar(ScalarType.BOOLEAN, False)),),
    )
    goal_domain = domain(operators=(false_effect,))
    goal_certificate = validate_candidate_plan(
        bound_plan(goal_domain),
        goal_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert "objective_not_satisfied" in counterexample_codes(goal_certificate)

    invariant_effect = replace(
        operator(),
        effects=(
            FactAssignmentV1("authorized", scalar(ScalarType.BOOLEAN, False)),
            FactAssignmentV1("posture-collected", scalar(ScalarType.BOOLEAN, True)),
        ),
    )
    invariant_domain = domain(operators=(invariant_effect,))
    invariant_certificate = validate_candidate_plan(
        bound_plan(invariant_domain),
        invariant_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert "domain_invariant_violated" in counterexample_codes(invariant_certificate)


def test_initial_domain_invariant_is_checked_before_any_repairing_effect() -> None:
    repairing_operator = replace(
        operator(),
        preconditions=(predicate("posture-collected", ScalarType.BOOLEAN, False),),
        effects=(
            FactAssignmentV1("authorized", scalar(ScalarType.BOOLEAN, True)),
            FactAssignmentV1("posture-collected", scalar(ScalarType.BOOLEAN, True)),
        ),
    )
    current_domain = domain(operators=(repairing_operator,))
    initial_values = tuple(
        FactValueV1(item.fact_id, scalar(ScalarType.BOOLEAN, False)) if item.fact_id == "authorized" else item
        for item in world().values
    )
    certificate = validate_candidate_plan(
        bound_plan(current_domain, initial_state=WorldStateV1(initial_values)),
        current_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert certificate.result is ValidationResult.INVALID
    assert "domain_invariant_violated" in counterexample_codes(certificate)


def test_intermediate_forbidden_state_cannot_be_repaired_into_validity() -> None:
    disable = replace(
        operator(),
        operator_id="disable-authorization",
        effects=(FactAssignmentV1("authorized", scalar(ScalarType.BOOLEAN, False)),),
        observation_fact_ids=("authorized",),
    )
    restore = replace(
        operator(),
        operator_id="restore-authorization",
        preconditions=(predicate("authorized", ScalarType.BOOLEAN, False),),
        effects=(
            FactAssignmentV1("authorized", scalar(ScalarType.BOOLEAN, True)),
            FactAssignmentV1("posture-collected", scalar(ScalarType.BOOLEAN, True)),
        ),
        observation_fact_ids=("authorized", "posture-collected"),
    )
    current_domain = domain(operators=(disable, restore), invariants=())
    template = bound_plan(current_domain).nodes[0]
    first = replace(template, node_id="node-a", operator_id=disable.operator_id, order=0)
    second = replace(template, node_id="node-b", operator_id=restore.operator_id, order=1)
    edge = PlanEdgeV1(
        schema_version="redagent.plan-edge/v1",
        edge_id="edge-a-b",
        source_node_id="node-a",
        target_node_id="node-b",
        conditions=(predicate("authorized", ScalarType.BOOLEAN, False),),
    )
    current_plan = bound_plan(current_domain, nodes=(first, second), edges=(edge,))
    certificate = validate_candidate_plan(
        current_plan,
        current_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert certificate.result is ValidationResult.INVALID
    assert "objective_forbidden_state" in counterexample_codes(certificate)


def test_validator_rejects_unknown_operator_target_argument_and_scope_expansion() -> None:
    current_domain = domain()
    current = bound_plan(current_domain)
    node = current.nodes[0]
    mutations = (
        (replace(node, operator_id="unknown-operator"), "operator_unknown"),
        (replace(node, target_id="target-b"), "authority_target_denied"),
        (
            replace(
                node,
                arguments=(TypedParameterBindingV1("target", scalar(ScalarType.STRING, "target-b")),),
            ),
            "operator_target_binding_mismatch",
        ),
    )
    for mutated_node, code in mutations:
        certificate = validate_candidate_plan(
            replace(current, nodes=(mutated_node,)),
            current_domain,
            authority(),
            limits=limits(),
            validated_at=NOW + timedelta(seconds=30),
        )
        assert certificate.result is ValidationResult.INVALID
        assert code in counterexample_codes(certificate)

    widened_operator = replace(operator(), effect_class=CampaignEffectClass.DISRUPTIVE)
    widened_domain = domain(operators=(widened_operator,))
    widened = validate_candidate_plan(
        bound_plan(widened_domain),
        widened_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert "authority_effect_denied" in counterexample_codes(widened)


@pytest.mark.parametrize(
    ("authority_overrides", "code"),
    (
        ({"capability_ids": ("other-capability",)}, "authority_capability_denied"),
        ({"success_condition_ids": ("other-condition",)}, "authority_success_condition_denied"),
        ({"allowed_data_access_classes": (CampaignDataAccessClass.REPORT_SAFE,)}, "authority_data_access_denied"),
        ({"allowed_credential_classes": (CampaignCredentialClass.SCOPED_READ,)}, "authority_credential_denied"),
        ({"allowed_environment_classes": (CampaignEnvironmentClass.OWNED_STAGING,)}, "authority_environment_denied"),
    ),
)
def test_authority_catalog_and_scope_dimensions_fail_closed(authority_overrides: dict[str, object], code: str) -> None:
    current_domain = domain()
    current_authority = authority(**authority_overrides)
    current_plan = plan(current_domain, authority_sha256=current_authority.authority_sha256)
    certificate = validate_candidate_plan(
        current_plan,
        current_domain,
        current_authority,
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert certificate.result is ValidationResult.INVALID
    assert code in counterexample_codes(certificate)


def test_expired_authority_and_unknown_forbidden_state_fail_closed() -> None:
    current_domain = domain()
    expired = validate_candidate_plan(
        bound_plan(current_domain),
        current_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(minutes=2),
    )
    assert "authority_time_window_invalid" in counterexample_codes(expired)

    unknown_values = tuple(
        FactValueV1(item.fact_id, None) if item.fact_id == "authorized" else item for item in world().values
    )
    unknown_forbidden = validate_candidate_plan(
        bound_plan(current_domain, initial_state=WorldStateV1(unknown_values)),
        current_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert "objective_forbidden_state_unknown" in counterexample_codes(unknown_forbidden)


@pytest.mark.parametrize(
    ("operator_overrides", "code"),
    (
        ({"max_duration_seconds": 61}, "authority_bound_exceeded:max_duration_seconds"),
        ({"max_requests": 11}, "authority_bound_exceeded:max_requests"),
        ({"max_rate_per_minute": 11}, "authority_bound_exceeded:max_rate_per_minute"),
        ({"concurrency_weight": 3}, "authority_bound_exceeded:max_concurrency"),
        ({"max_retries": 2}, "authority_bound_exceeded:max_retries_per_node"),
        ({"max_risk_micropoints": 1_001}, "authority_bound_exceeded:max_risk_micropoints"),
        ({"max_cost_microunits": 10_001}, "authority_bound_exceeded:max_cost_microunits"),
        ({"max_evidence_bytes": 10_001}, "authority_bound_exceeded:max_evidence_bytes"),
        ({"max_data_bytes": 10_001}, "authority_bound_exceeded:max_data_bytes"),
    ),
)
def test_each_operator_resource_expansion_is_rejected(operator_overrides: dict[str, object], code: str) -> None:
    widened_domain = domain(operators=(operator(**operator_overrides),))
    certificate = validate_candidate_plan(
        bound_plan(widened_domain),
        widened_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert certificate.result is ValidationResult.INVALID
    assert code in counterexample_codes(certificate)


def two_node_plan(current_domain: PlanningDomainV1) -> CandidatePlanV1:
    first = bound_plan(current_domain).nodes[0]
    second = replace(first, node_id="node-b", order=1)
    edge = PlanEdgeV1(
        schema_version="redagent.plan-edge/v1",
        edge_id="edge-a-b",
        source_node_id="node-a",
        target_node_id="node-b",
        conditions=(predicate("posture-collected", ScalarType.BOOLEAN, True),),
    )
    return bound_plan(current_domain, nodes=(first, second), edges=(edge,))


def test_graph_endpoint_cycle_order_and_unreachable_mutations_fail_closed() -> None:
    current_domain = domain()
    current = two_node_plan(current_domain)
    cases = (
        (
            replace(
                current,
                edges=(replace(current.edges[0], target_node_id="missing-node"),),
            ),
            "graph_edge_endpoint_unknown",
        ),
        (
            replace(
                current,
                edges=(
                    current.edges[0],
                    PlanEdgeV1(
                        schema_version="redagent.plan-edge/v1",
                        edge_id="edge-b-a",
                        source_node_id="node-b",
                        target_node_id="node-a",
                        conditions=(),
                    ),
                ),
            ),
            "graph_cycle_or_order_invalid",
        ),
        (
            replace(
                current,
                edges=(
                    replace(
                        current.edges[0],
                        conditions=(predicate("authorized", ScalarType.BOOLEAN, False),),
                    ),
                ),
            ),
            "graph_node_unreachable",
        ),
    )
    for mutated, code in cases:
        certificate = validate_candidate_plan(
            mutated,
            current_domain,
            authority(),
            limits=limits(),
            validated_at=NOW + timedelta(seconds=30),
        )
        assert certificate.result is ValidationResult.INVALID
        assert code in counterexample_codes(certificate)


def test_resource_proof_limit_returns_non_admissible_unknown() -> None:
    current_domain = domain()
    certificate = validate_candidate_plan(
        two_node_plan(current_domain),
        current_domain,
        authority(),
        limits=limits(max_nodes=1),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert certificate.result is ValidationResult.UNKNOWN
    assert certificate.admissible is False
    assert certificate.bounded_reason == "validation_resource_limit:max_nodes"


def test_forbidden_objective_checks_are_charged_to_transition_proof_limit() -> None:
    forbidden = tuple(
        sorted(
            (
                predicate("finding-count", ScalarType.INTEGER, value, PredicateOperator.GREATER_THAN)
                for value in range(1, 11)
            ),
            key=lambda item: canonical_planning_bytes(item.expected),
        )
    )
    current_domain = domain(
        objective=PlanningObjectiveV1(
            objective_id="collect-posture",
            required_predicates=(predicate("posture-collected", ScalarType.BOOLEAN, True),),
            forbidden_predicates=forbidden,
        )
    )
    certificate = validate_candidate_plan(
        bound_plan(current_domain),
        current_domain,
        authority(),
        limits=limits(max_state_transitions=8),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert certificate.result is ValidationResult.UNKNOWN
    assert certificate.bounded_reason == "validation_resource_limit:max_state_transitions"


def test_unsupported_semantics_are_unknown_and_aggregate_rate_is_bounded() -> None:
    unsupported_domain = domain(operators=(operator(unsupported_condition_ids=("custom-semantics",)),))
    unsupported = validate_candidate_plan(
        bound_plan(unsupported_domain),
        unsupported_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert unsupported.result is ValidationResult.UNKNOWN
    assert unsupported.admissible is False
    assert unsupported.bounded_reason == "validation_unsupported_operator_semantics"

    rate_domain = domain(operators=(operator(max_rate_per_minute=6),))
    aggregate_rate = validate_candidate_plan(
        two_node_plan(rate_domain),
        rate_domain,
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert "authority_bound_exceeded:max_rate_per_minute" in counterexample_codes(aggregate_rate)


def test_certificate_digest_prevents_tenant_or_result_substitution() -> None:
    certificate = validate_candidate_plan(
        bound_plan(),
        domain(),
        authority(),
        limits=limits(),
        validated_at=NOW + timedelta(seconds=30),
    )
    assert replace(certificate, tenant_id="tenant-b").certificate_sha256 != certificate.certificate_sha256
    assert replace(certificate, authority_sha256=SHA_A).certificate_sha256 != certificate.certificate_sha256
    assert replace(certificate, domain_sha256=SHA_B).certificate_sha256 != certificate.certificate_sha256
    assert replace(certificate, plan_sha256=SHA_C).certificate_sha256 != certificate.certificate_sha256
    assert (
        replace(
            certificate,
            result=ValidationResult.INVALID,
            counterexamples=(ValidationCounterexampleV1("tampered_result", None),),
        ).certificate_sha256
        != certificate.certificate_sha256
    )
