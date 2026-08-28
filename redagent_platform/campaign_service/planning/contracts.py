"""Canonical typed planning-domain and validation-certificate contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, cast

from redagent_platform.campaign_service.authority_envelope import (
    CampaignCredentialClass,
    CampaignDataAccessClass,
    CampaignEffectClass,
    CampaignEnvironmentClass,
)


PLANNING_DOMAIN_SCHEMA_VERSION = "redagent.planning-domain/v1"
CAPABILITY_OPERATOR_SCHEMA_VERSION = "redagent.capability-operator/v1"
CANDIDATE_PLAN_SCHEMA_VERSION = "redagent.candidate-plan/v1"
PLAN_NODE_SCHEMA_VERSION = "redagent.plan-node/v1"
PLAN_EDGE_SCHEMA_VERSION = "redagent.plan-edge/v1"
PLAN_VALIDATION_CERTIFICATE_SCHEMA_VERSION = "redagent.plan-validation-certificate/v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_SAFE_STRING = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ScalarType(str, Enum):
    BOOLEAN = "boolean"
    INTEGER = "integer"
    STRING = "string"


class PredicateOperator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"


class CleanupMode(str, Enum):
    NONE = "none"
    REQUIRED = "required"
    COMPENSATING = "compensating"


class PlanJoinPolicy(str, Enum):
    ALL = "all"
    ANY = "any"


class ValidationResult(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ScalarValueV1:
    value_type: ScalarType
    value: bool | int | str

    def __post_init__(self) -> None:
        if not isinstance(self.value_type, ScalarType):
            raise ValueError("planning_scalar_type_invalid")
        exact = {
            ScalarType.BOOLEAN: type(self.value) is bool,
            ScalarType.INTEGER: type(self.value) is int,
            ScalarType.STRING: type(self.value) is str,
        }
        if not exact[self.value_type]:
            raise ValueError("planning_scalar_value_type_mismatch")
        if self.value_type is ScalarType.INTEGER and not -(2**63) <= cast(int, self.value) < 2**63:
            raise ValueError("planning_scalar_integer_invalid")
        if self.value_type is ScalarType.STRING and not _SAFE_STRING.fullmatch(cast(str, self.value)):
            raise ValueError("planning_scalar_string_invalid")


@dataclass(frozen=True, slots=True)
class FactDefinitionV1:
    fact_id: str
    value_type: ScalarType
    allowed_values: tuple[ScalarValueV1, ...]

    def __post_init__(self) -> None:
        _identifier("planning_fact_id", self.fact_id)
        if not isinstance(self.value_type, ScalarType):
            raise ValueError("planning_fact_type_invalid")
        _canonical_tuple(
            "planning_fact_allowed_values",
            self.allowed_values,
            _scalar_sort_key,
            maximum=128,
            allow_empty=True,
        )
        if any(item.value_type is not self.value_type for item in self.allowed_values):
            raise ValueError("planning_fact_allowed_value_type_mismatch")


@dataclass(frozen=True, slots=True)
class PredicateV1:
    fact_id: str
    operator: PredicateOperator
    expected: ScalarValueV1

    def __post_init__(self) -> None:
        _identifier("planning_predicate_fact_id", self.fact_id)
        if not isinstance(self.operator, PredicateOperator) or not isinstance(self.expected, ScalarValueV1):
            raise ValueError("planning_predicate_invalid")
        if self.expected.value_type is not ScalarType.INTEGER and self.operator not in {
            PredicateOperator.EQUALS,
            PredicateOperator.NOT_EQUALS,
        }:
            raise ValueError("planning_predicate_operator_type_mismatch")


@dataclass(frozen=True, slots=True)
class FactAssignmentV1:
    fact_id: str
    value: ScalarValueV1

    def __post_init__(self) -> None:
        _identifier("planning_assignment_fact_id", self.fact_id)
        if not isinstance(self.value, ScalarValueV1):
            raise ValueError("planning_assignment_value_invalid")


@dataclass(frozen=True, slots=True)
class TypedParameterSpecV1:
    name: str
    value_type: ScalarType
    required: bool
    allowed_values: tuple[ScalarValueV1, ...]
    minimum: int | None
    maximum: int | None
    binds_target: bool

    def __post_init__(self) -> None:
        _identifier("operator_parameter_name", self.name)
        if not isinstance(self.value_type, ScalarType):
            raise ValueError("operator_parameter_type_invalid")
        if type(self.required) is not bool or type(self.binds_target) is not bool:
            raise ValueError("operator_parameter_flag_invalid")
        _canonical_tuple(
            "operator_parameter_allowed_values",
            self.allowed_values,
            _scalar_sort_key,
            maximum=128,
            allow_empty=True,
        )
        if any(item.value_type is not self.value_type for item in self.allowed_values):
            raise ValueError("operator_parameter_allowed_value_type_mismatch")
        if (self.minimum is not None or self.maximum is not None) and self.value_type is not ScalarType.INTEGER:
            raise ValueError("operator_parameter_range_type_mismatch")
        for name, value in (("minimum", self.minimum), ("maximum", self.maximum)):
            if value is not None and type(value) is not int:
                raise ValueError(f"operator_parameter_{name}_invalid")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("operator_parameter_range_invalid")
        if self.binds_target and self.value_type is not ScalarType.STRING:
            raise ValueError("operator_target_parameter_type_invalid")


@dataclass(frozen=True, slots=True)
class TypedParameterBindingV1:
    name: str
    value: ScalarValueV1

    def __post_init__(self) -> None:
        _identifier("plan_argument_name", self.name)
        if not isinstance(self.value, ScalarValueV1):
            raise ValueError("plan_argument_value_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class CapabilityIdentityV1:
    capability_id: str
    capability_revision: int
    adapter_id: str
    adapter_version: str
    execution_manifest_sha256: str
    profile_id: str
    profile_revision: int
    profile_sha256: str
    bundle_id: str | None
    bundle_revision: int | None
    bundle_sha256: str | None

    def __post_init__(self) -> None:
        for name in ("capability_id", "adapter_id", "adapter_version", "profile_id"):
            _identifier(f"operator_{name}", getattr(self, name))
        _integer("operator_capability_revision", self.capability_revision, 1, 1_000_000)
        _integer("operator_profile_revision", self.profile_revision, 1, 1_000_000)
        _sha256("operator_execution_manifest_sha256", self.execution_manifest_sha256)
        _sha256("operator_profile_sha256", self.profile_sha256)
        bundle = (self.bundle_id, self.bundle_revision, self.bundle_sha256)
        if any(item is not None for item in bundle):
            if any(item is None for item in bundle):
                raise ValueError("operator_bundle_binding_incomplete")
            _identifier("operator_bundle_id", self.bundle_id)
            _integer("operator_bundle_revision", self.bundle_revision, 1, 1_000_000)
            _sha256("operator_bundle_sha256", self.bundle_sha256)

    @property
    def identity_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class CapabilityOperatorV1:
    # CRITICAL: keep this schema closed and data-only; opaque action fields would bypass independent proof.
    schema_version: str
    operator_id: str
    capability: CapabilityIdentityV1
    parameters: tuple[TypedParameterSpecV1, ...]
    preconditions: tuple[PredicateV1, ...]
    effects: tuple[FactAssignmentV1, ...]
    effect_class: CampaignEffectClass
    executable: bool
    target_parameter_name: str | None
    data_access_class: CampaignDataAccessClass
    credential_class: CampaignCredentialClass
    supported_environments: tuple[CampaignEnvironmentClass, ...]
    max_duration_seconds: int
    max_requests: int
    max_rate_per_minute: int
    concurrency_weight: int
    max_retries: int
    max_risk_micropoints: int
    max_cost_microunits: int
    max_evidence_bytes: int
    max_data_bytes: int
    idempotent: bool
    cleanup_mode: CleanupMode
    observation_fact_ids: tuple[str, ...]
    unsupported_condition_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != CAPABILITY_OPERATOR_SCHEMA_VERSION:
            raise ValueError("capability_operator_schema_unsupported")
        _identifier("capability_operator_id", self.operator_id)
        if not isinstance(self.capability, CapabilityIdentityV1):
            raise ValueError("capability_operator_identity_invalid")
        _canonical_tuple("capability_operator_parameters", self.parameters, lambda item: item.name, maximum=64)
        _canonical_tuple("capability_operator_preconditions", self.preconditions, _predicate_sort_key, maximum=256)
        if not isinstance(self.effects, tuple) or not self.effects or len(self.effects) > 256:
            raise ValueError("capability_operator_effects_invalid")
        effect_ids = tuple(item.fact_id for item in self.effects if isinstance(item, FactAssignmentV1))
        if len(effect_ids) != len(self.effects) or len(set(effect_ids)) != len(effect_ids):
            raise ValueError("capability_operator_effects_contradictory")
        if tuple(sorted(self.effects, key=lambda item: item.fact_id)) != self.effects:
            raise ValueError("capability_operator_effects_not_canonical")
        if not isinstance(self.effect_class, CampaignEffectClass):
            raise ValueError("capability_operator_effect_class_invalid")
        if type(self.executable) is not bool or type(self.idempotent) is not bool:
            raise ValueError("capability_operator_flag_invalid")
        if self.target_parameter_name is not None:
            _identifier("capability_operator_target_parameter", self.target_parameter_name)
        target_specs = tuple(item for item in self.parameters if item.binds_target)
        if self.executable and (len(target_specs) != 1 or self.target_parameter_name != target_specs[0].name):
            raise ValueError("capability_operator_target_binding_invalid")
        if not isinstance(self.data_access_class, CampaignDataAccessClass):
            raise ValueError("capability_operator_data_access_invalid")
        if not isinstance(self.credential_class, CampaignCredentialClass):
            raise ValueError("capability_operator_credential_invalid")
        _canonical_tuple(
            "capability_operator_environments",
            self.supported_environments,
            lambda item: item.value,
            maximum=16,
            allow_empty=False,
        )
        if any(not isinstance(item, CampaignEnvironmentClass) for item in self.supported_environments):
            raise ValueError("capability_operator_environment_invalid")
        for name, maximum in (
            ("max_duration_seconds", 31_536_000),
            ("max_requests", 10_000_000),
            ("max_rate_per_minute", 1_000_000),
            ("concurrency_weight", 100_000),
            ("max_retries", 10_000),
            ("max_risk_micropoints", 10**15),
            ("max_cost_microunits", 10**15),
            ("max_evidence_bytes", 10**15),
            ("max_data_bytes", 10**15),
        ):
            _integer(f"capability_operator_{name}", getattr(self, name), 0, maximum)
        if self.concurrency_weight < 1:
            raise ValueError("capability_operator_concurrency_weight_invalid")
        if not isinstance(self.cleanup_mode, CleanupMode):
            raise ValueError("capability_operator_cleanup_mode_invalid")
        if self.executable and self.cleanup_mode is CleanupMode.NONE:
            raise ValueError("capability_operator_cleanup_required")
        _closed_ids("capability_operator_observation_facts", self.observation_fact_ids, maximum=128)
        _closed_ids(
            "capability_operator_unsupported_conditions",
            self.unsupported_condition_ids,
            maximum=128,
            allow_empty=True,
        )

    @property
    def operator_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanningObjectiveV1:
    objective_id: str
    required_predicates: tuple[PredicateV1, ...]
    forbidden_predicates: tuple[PredicateV1, ...]

    def __post_init__(self) -> None:
        _identifier("planning_objective_id", self.objective_id)
        _canonical_tuple("planning_objective_required", self.required_predicates, _predicate_sort_key, maximum=256)
        _canonical_tuple(
            "planning_objective_forbidden",
            self.forbidden_predicates,
            _predicate_sort_key,
            maximum=256,
            allow_empty=True,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanningDomainV1:
    schema_version: str
    domain_id: str
    domain_revision: int
    facts: tuple[FactDefinitionV1, ...]
    operators: tuple[CapabilityOperatorV1, ...]
    invariants: tuple[PredicateV1, ...]
    objective: PlanningObjectiveV1

    def __post_init__(self) -> None:
        if self.schema_version != PLANNING_DOMAIN_SCHEMA_VERSION:
            raise ValueError("planning_domain_schema_unsupported")
        _identifier("planning_domain_id", self.domain_id)
        _integer("planning_domain_revision", self.domain_revision, 1, 1_000_000)
        _canonical_tuple("planning_domain_facts", self.facts, lambda item: item.fact_id, maximum=1_024)
        _canonical_tuple("planning_domain_operators", self.operators, lambda item: item.operator_id, maximum=1_024)
        _canonical_tuple(
            "planning_domain_invariants", self.invariants, _predicate_sort_key, maximum=1_024, allow_empty=True
        )
        if not isinstance(self.objective, PlanningObjectiveV1):
            raise ValueError("planning_domain_objective_invalid")
        definitions = {item.fact_id: item for item in self.facts}
        for operator in self.operators:
            for predicate in operator.preconditions:
                _validate_predicate_against_facts(predicate, definitions)
            for assignment in operator.effects:
                _validate_assignment_against_facts(assignment, definitions)
            for fact_id in operator.observation_fact_ids:
                if fact_id not in definitions:
                    raise ValueError("planning_domain_fact_unknown")
        for predicate in (*self.invariants, *self.objective.required_predicates, *self.objective.forbidden_predicates):
            _validate_predicate_against_facts(predicate, definitions)

    @property
    def domain_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True)
class FactValueV1:
    fact_id: str
    value: ScalarValueV1 | None

    def __post_init__(self) -> None:
        _identifier("world_fact_id", self.fact_id)
        if self.value is not None and not isinstance(self.value, ScalarValueV1):
            raise ValueError("world_fact_value_invalid")


@dataclass(frozen=True, slots=True)
class WorldStateV1:
    values: tuple[FactValueV1, ...]

    def __post_init__(self) -> None:
        _canonical_tuple("world_state_values", self.values, lambda item: item.fact_id, maximum=4_096)

    @property
    def state_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanNodeV1:
    schema_version: str
    node_id: str
    operator_id: str
    target_id: str
    environment: CampaignEnvironmentClass
    arguments: tuple[TypedParameterBindingV1, ...]
    order: int
    join_policy: PlanJoinPolicy

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_NODE_SCHEMA_VERSION:
            raise ValueError("plan_node_schema_unsupported")
        for name in ("node_id", "operator_id", "target_id"):
            _identifier(f"plan_node_{name}", getattr(self, name))
        if not isinstance(self.environment, CampaignEnvironmentClass):
            raise ValueError("plan_node_environment_invalid")
        _canonical_tuple("plan_node_arguments", self.arguments, lambda item: item.name, maximum=64, allow_empty=True)
        _integer("plan_node_order", self.order, 0, 1_000_000)
        if not isinstance(self.join_policy, PlanJoinPolicy):
            raise ValueError("plan_node_join_policy_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanEdgeV1:
    schema_version: str
    edge_id: str
    source_node_id: str
    target_node_id: str
    conditions: tuple[PredicateV1, ...]

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_EDGE_SCHEMA_VERSION:
            raise ValueError("plan_edge_schema_unsupported")
        for name in ("edge_id", "source_node_id", "target_node_id"):
            _identifier(f"plan_edge_{name}", getattr(self, name))
        _canonical_tuple("plan_edge_conditions", self.conditions, _predicate_sort_key, maximum=128, allow_empty=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class CandidatePlanV1:
    schema_version: str
    plan_id: str
    tenant_id: str
    engagement_id: str
    authority_sha256: str
    domain_sha256: str
    objective_id: str
    initial_state: WorldStateV1
    nodes: tuple[PlanNodeV1, ...]
    edges: tuple[PlanEdgeV1, ...]

    def __post_init__(self) -> None:
        if self.schema_version != CANDIDATE_PLAN_SCHEMA_VERSION:
            raise ValueError("candidate_plan_schema_unsupported")
        for name in ("plan_id", "tenant_id", "engagement_id", "objective_id"):
            _identifier(f"candidate_plan_{name}", getattr(self, name))
        _sha256("candidate_plan_authority_sha256", self.authority_sha256)
        _sha256("candidate_plan_domain_sha256", self.domain_sha256)
        if not isinstance(self.initial_state, WorldStateV1):
            raise ValueError("candidate_plan_initial_state_invalid")
        if not isinstance(self.nodes, tuple) or not self.nodes:
            raise ValueError("candidate_plan_nodes_invalid")
        node_ids = tuple(item.node_id for item in self.nodes if isinstance(item, PlanNodeV1))
        if len(node_ids) != len(self.nodes):
            raise ValueError("candidate_plan_nodes_invalid")
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("candidate_plan_node_duplicate")
        if tuple(sorted(self.nodes, key=lambda item: (item.order, item.node_id))) != self.nodes:
            raise ValueError("candidate_plan_nodes_not_canonical")
        if not isinstance(self.edges, tuple) or any(not isinstance(item, PlanEdgeV1) for item in self.edges):
            raise ValueError("candidate_plan_edges_invalid")
        edge_ids = tuple(item.edge_id for item in self.edges)
        if len(set(edge_ids)) != len(edge_ids):
            raise ValueError("candidate_plan_edge_duplicate")
        if tuple(sorted(self.edges, key=lambda item: item.edge_id)) != self.edges:
            raise ValueError("candidate_plan_edges_not_canonical")

    @property
    def plan_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True)
class ValidationLimitsV1:
    max_nodes: int
    max_edges: int
    max_state_transitions: int

    def __post_init__(self) -> None:
        for name in ("max_nodes", "max_edges", "max_state_transitions"):
            _integer(f"validation_limit_{name}", getattr(self, name), 1, 10_000_000)


@dataclass(frozen=True, slots=True)
class ValidationCounterexampleV1:
    code: str
    subject_id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not re.fullmatch(r"^[a-z][a-z0-9_:]{0,149}$", self.code):
            raise ValueError("validation_counterexample_code_invalid")
        if self.subject_id is not None:
            _identifier("validation_counterexample_subject", self.subject_id)


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanValidationCertificateV1:
    schema_version: str
    validator_version: str
    validator_sha256: str
    tenant_id: str
    engagement_id: str
    authority_sha256: str
    domain_sha256: str
    plan_sha256: str
    validated_at: datetime
    result: ValidationResult
    checked_invariant_ids: tuple[str, ...]
    counterexamples: tuple[ValidationCounterexampleV1, ...]
    bounded_reason: str | None

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_VALIDATION_CERTIFICATE_SCHEMA_VERSION:
            raise ValueError("plan_validation_certificate_schema_unsupported")
        for name in ("validator_version", "tenant_id", "engagement_id"):
            _identifier(f"plan_validation_{name}", getattr(self, name))
        for name in ("validator_sha256", "authority_sha256", "domain_sha256", "plan_sha256"):
            _sha256(f"plan_validation_{name}", getattr(self, name))
        _aware("plan_validation_validated_at", self.validated_at)
        if not isinstance(self.result, ValidationResult):
            raise ValueError("plan_validation_result_invalid")
        _closed_ids("plan_validation_checked_invariants", self.checked_invariant_ids, maximum=1_024, allow_empty=True)
        _canonical_tuple(
            "plan_validation_counterexamples",
            self.counterexamples,
            lambda item: (item.code, item.subject_id or ""),
            maximum=4_096,
            allow_empty=True,
        )
        if self.bounded_reason is not None:
            if not re.fullmatch(r"^[a-z][a-z0-9_:]{0,149}$", self.bounded_reason):
                raise ValueError("plan_validation_bounded_reason_invalid")
        if self.result is ValidationResult.VALID and (self.counterexamples or self.bounded_reason is not None):
            raise ValueError("plan_validation_valid_certificate_invalid")
        if self.result is ValidationResult.INVALID and (not self.counterexamples or self.bounded_reason is not None):
            raise ValueError("plan_validation_invalid_certificate_invalid")
        if self.result is ValidationResult.UNKNOWN and self.bounded_reason is None:
            raise ValueError("plan_validation_unknown_reason_required")

    @property
    def admissible(self) -> bool:
        # CRITICAL: UNKNOWN is evidence of an incomplete proof and must never become admission authority.
        return self.result is ValidationResult.VALID

    @property
    def certificate_sha256(self) -> str:
        # CRITICAL: every admission-relevant field must remain inside the canonical certificate digest.
        return canonical_planning_sha256(self)


def canonical_planning_bytes(value: object) -> bytes:
    return json.dumps(
        _normalize(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_planning_sha256(value: object) -> str:
    return hashlib.sha256(canonical_planning_bytes(value)).hexdigest()


def _validate_predicate_against_facts(predicate: PredicateV1, definitions: dict[str, FactDefinitionV1]) -> None:
    definition = definitions.get(predicate.fact_id)
    if definition is None:
        raise ValueError("planning_domain_fact_unknown")
    if predicate.expected.value_type is not definition.value_type:
        raise ValueError("planning_domain_predicate_type_mismatch")
    if definition.allowed_values and predicate.expected not in definition.allowed_values:
        raise ValueError("planning_domain_predicate_value_not_allowed")


def _validate_assignment_against_facts(assignment: FactAssignmentV1, definitions: dict[str, FactDefinitionV1]) -> None:
    definition = definitions.get(assignment.fact_id)
    if definition is None:
        raise ValueError("planning_domain_fact_unknown")
    if assignment.value.value_type is not definition.value_type:
        raise ValueError("planning_domain_assignment_type_mismatch")
    if definition.allowed_values and assignment.value not in definition.allowed_values:
        raise ValueError("planning_domain_assignment_value_not_allowed")


def _canonical_tuple(
    name: str,
    values: tuple[Any, ...],
    key: Any,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> None:
    if (
        not isinstance(values, tuple)
        or (not allow_empty and not values)
        or len(values) > maximum
        or len(set(key(item) for item in values)) != len(values)
    ):
        raise ValueError(f"{name}_invalid")
    if tuple(sorted(values, key=key)) != values:
        raise ValueError(f"{name}_not_canonical")


def _closed_ids(name: str, values: tuple[str, ...], *, maximum: int, allow_empty: bool = False) -> None:
    _canonical_tuple(name, values, lambda item: item, maximum=maximum, allow_empty=allow_empty)
    for value in values:
        _identifier(name, value)


def _scalar_sort_key(value: ScalarValueV1) -> tuple[str, bytes]:
    if not isinstance(value, ScalarValueV1):
        raise ValueError("planning_scalar_value_invalid")
    return value.value_type.value, canonical_planning_bytes(value)


def _predicate_sort_key(value: PredicateV1) -> tuple[str, str, bytes]:
    if not isinstance(value, PredicateV1):
        raise ValueError("planning_predicate_invalid")
    return value.fact_id, value.operator.value, canonical_planning_bytes(value.expected)


def _normalize(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return _normalize(asdict(cast(Any, value)))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        _aware("planning_canonical_datetime", value)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_normalize(item) for item in value]
    return value


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _integer(name: str, value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")
