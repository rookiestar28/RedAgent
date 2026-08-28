"""Immutable, non-executable compat_119 assessment-intelligence contracts."""

from __future__ import annotations

import builtins
from dataclasses import InitVar, asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, cast

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PATH = re.compile(r"^/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]+$")
_SNAPSHOT_VALIDATION_TOKEN = object()
_R121_VALIDATION_TOKEN = object()
_DETECTION_VALIDATION_TOKEN = object()
_ATTACK_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_HEADER_CODES = frozenset({"content-security-policy", "x-content-type-options"})
_OBSERVATION_OBJECT_KINDS = frozenset(
    {"target", "http-response", "security-header", "capability", "evidence"}
)
_OUTCOME_CODES = frozenset({"succeeded", "failed", "cancelled", "inconclusive"})
_FINDING_DISPOSITIONS = frozenset({
    "needs_review", "confirmed", "false_positive", "risk_accepted", "duplicate",
    "mitigated", "out_of_scope", "closed",
})
_RETEST_STATES = frozenset({"not_requested", "requested", "passed", "failed"})


class ObservationKind(str, Enum):
    TARGET_REACHABILITY = "target_reachability"
    HTTP_RESPONSE_STATUS = "http_response_status"
    SECURITY_HEADER_PRESENT = "security_header_present"
    SECURITY_HEADER_MISSING = "security_header_missing"
    CAPABILITY_OUTCOME = "capability_outcome"
    EVIDENCE_IDENTITY = "evidence_identity"


class TruthValue(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"
    NOT_OBSERVED = "not_observed"


class Completeness(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class CollectionState(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class TrustLevel(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DetectionSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionDisposition(str, Enum):
    UNCONFIRMED = "unconfirmed"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


class DetectionPromotionKind(str, Enum):
    HUMAN_REVIEW = "human_review"
    DETERMINISTIC_CORRELATION = "deterministic_correlation"


class TelemetrySource(str, Enum):
    SIEM = "siem"
    EDR = "edr"
    CLOUD_AUDIT = "cloud_audit"
    APPLICATION_LOG = "application_log"
    NETWORK_SENSOR = "network_sensor"


class InvalidationState(str, Enum):
    CURRENT = "current"
    INVALIDATED = "invalidated"
    REVOKED = "revoked"


class TargetMappingStatus(str, Enum):
    PROMOTED = "promoted"
    NEEDS_REVIEW = "needs_review"


@dataclass(frozen=True, slots=True, kw_only=True)
class TypedReferenceV1:
    kind: str
    reference_id: str
    sha256: str

    def __post_init__(self) -> None:
        _identifier("reference_kind", self.kind)
        _identifier("reference_id", self.reference_id)
        _sha256("reference_sha256", self.sha256)


@dataclass(frozen=True, slots=True, kw_only=True)
class CapabilitySemanticsDefinitionV1:
    schema_version: str
    semantics_id: str
    revision: int
    target_class: str
    environment_class: str
    preconditions: tuple[str, ...]
    observation_kinds: tuple[ObservationKind, ...]
    effects: tuple[str, ...]
    risk_class: str
    noise_class: str
    cost_class: str
    duration_class: str
    evidence_schemas: tuple[str, ...]
    cleanup: str
    compensation: str
    stop_conditions: tuple[str, ...]
    freshness_seconds: int
    qualification: str
    deprecation: str

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r119-capability-semantics/v1":
            raise ValueError("r119_semantics_schema_invalid")
        _identifier("semantics_id", self.semantics_id)
        _positive_int("semantics_revision", self.revision)
        for identifier_name, identifier_value in (
            ("target_class", self.target_class),
            ("environment_class", self.environment_class),
            ("risk_class", self.risk_class),
            ("noise_class", self.noise_class),
            ("cost_class", self.cost_class),
            ("duration_class", self.duration_class),
            ("cleanup", self.cleanup),
            ("compensation", self.compensation),
            ("qualification", self.qualification),
            ("deprecation", self.deprecation),
        ):
            _identifier(identifier_name, identifier_value)
        _closed_identifiers("semantics_preconditions", self.preconditions, maximum=16)
        _closed_identifiers("semantics_effects", self.effects, maximum=8)
        _closed_identifiers("semantics_evidence_schemas", self.evidence_schemas, maximum=8)
        _closed_identifiers("semantics_stop_conditions", self.stop_conditions, maximum=8)
        if not self.observation_kinds or len(set(self.observation_kinds)) != len(self.observation_kinds):
            raise ValueError("r119_semantics_observation_kinds_invalid")
        if any(not isinstance(item, ObservationKind) for item in self.observation_kinds):
            raise ValueError("r119_semantics_observation_kinds_invalid")
        _bounded_int("semantics_freshness_seconds", self.freshness_seconds, 1, 86_400)

    @property
    def semantics_sha256(self) -> str:
        return canonical_sha256(self.canonical_body())

    def canonical_body(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class CapabilityBindingKeyV1:
    schema_version: str
    capability_id: str
    capability_revision: int
    execution_manifest_sha256: str
    adapter_id: str
    adapter_version: str
    profile_id: str
    profile_revision: int
    profile_sha256: str
    bundle_id: str | None
    bundle_revision: int | None
    bundle_sha256: str | None
    semantics_revision: int
    semantics_sha256: str
    normalized_output_sha256: str
    projection_revision: int
    projection_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r119-capability-binding/v1":
            raise ValueError("r119_binding_schema_invalid")
        for identifier_name, identifier_value in (
            ("binding_capability_id", self.capability_id),
            ("binding_adapter_id", self.adapter_id),
            ("binding_adapter_version", self.adapter_version),
            ("binding_profile_id", self.profile_id),
        ):
            _identifier(identifier_name, identifier_value)
        for revision_name, revision_value in (
            ("binding_capability_revision", self.capability_revision),
            ("binding_profile_revision", self.profile_revision),
            ("binding_semantics_revision", self.semantics_revision),
            ("binding_projection_revision", self.projection_revision),
        ):
            _positive_int(revision_name, revision_value)
        for digest_name, digest_value in (
            ("binding_execution_manifest_sha256", self.execution_manifest_sha256),
            ("binding_profile_sha256", self.profile_sha256),
            ("binding_semantics_sha256", self.semantics_sha256),
            ("binding_normalized_output_sha256", self.normalized_output_sha256),
            ("binding_projection_sha256", self.projection_sha256),
        ):
            _sha256(digest_name, digest_value)
        bundle_values = (self.bundle_id, self.bundle_revision, self.bundle_sha256)
        if any(value is None for value in bundle_values) and not all(value is None for value in bundle_values):
            raise ValueError("r119_binding_bundle_partial")
        if self.bundle_id is not None:
            _identifier("binding_bundle_id", self.bundle_id)
            _positive_int("binding_bundle_revision", self.bundle_revision)
            _sha256("binding_bundle_sha256", self.bundle_sha256)


@dataclass(frozen=True, slots=True, kw_only=True)
class PromotedCapabilitySemanticsV1:
    schema_version: str
    binding_key: CapabilityBindingKeyV1
    definition: CapabilitySemanticsDefinitionV1
    promotion_status: str
    promoted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r119-promoted-semantics/v1":
            raise ValueError("r119_promoted_semantics_schema_invalid")
        if self.promotion_status != "promoted":
            raise ValueError("r119_semantics_not_promoted")
        if self.binding_key.semantics_revision != self.definition.revision or (
            self.binding_key.semantics_sha256 != self.definition.semantics_sha256
        ):
            raise ValueError("r119_semantics_binding_mismatch")
        _window("r119_semantics", self.promoted_at, self.expires_at)
        if self.revoked_at is not None:
            _aware("r119_semantics_revoked_at", self.revoked_at)
            if not self.promoted_at <= self.revoked_at <= self.expires_at:
                raise ValueError("r119_semantics_revocation_time_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class TargetRouteV1:
    binding_key_sha256: str
    target_class: str
    application_class: str
    environment_class: str
    path_class: str

    def __post_init__(self) -> None:
        _sha256("target_route_binding_sha256", self.binding_key_sha256)
        for route_name, route_value in (
            ("target_route_target_class", self.target_class),
            ("target_route_application_class", self.application_class),
            ("target_route_environment_class", self.environment_class),
            ("target_route_path_class", self.path_class),
        ):
            _identifier(route_name, route_value)


@dataclass(frozen=True, slots=True, kw_only=True)
class TargetMappingV1:
    schema_version: str
    mapping_id: str
    revision: int
    status: TargetMappingStatus
    routes: tuple[TargetRouteV1, ...]

    def __post_init__(self) -> None:
        if self.schema_version not in {
            "redagent.r119-target-mapping/v1",
            "redagent.artifact-posture-target-mapping/v2",
        }:
            raise ValueError("r119_target_mapping_schema_invalid")
        _identifier("target_mapping_id", self.mapping_id)
        _positive_int("target_mapping_revision", self.revision)
        if not isinstance(self.status, TargetMappingStatus):
            raise ValueError("r119_target_mapping_status_invalid")
        expected_routes = (
            2 if self.schema_version == "redagent.r119-target-mapping/v1" else 3
        )
        if len(self.routes) != expected_routes or len(
            {route.binding_key_sha256 for route in self.routes}
        ) != expected_routes:
            raise ValueError("r119_target_mapping_routes_invalid")

    @property
    def mapping_sha256(self) -> str:
        return canonical_sha256(self.canonical_body())

    def canonical_body(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthorityContextV1:
    schema_version: str
    tenant_id: str
    engagement_id: str
    principal_id: str
    target: TypedReferenceV1
    target_mapping_sha256: str
    target_class: str
    application_class: str
    environment_class: str
    url_class: str
    roe_version_id: str
    roe_sha256: str
    roe_status: str
    policy_decision_id: str
    policy_revision: str
    policy_sha256: str
    policy_status: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r119-authority-context/v1":
            raise ValueError("r119_authority_schema_invalid")
        for identifier_name, identifier_value in (
            ("authority_tenant_id", self.tenant_id),
            ("authority_engagement_id", self.engagement_id),
            ("authority_principal_id", self.principal_id),
            ("authority_roe_version_id", self.roe_version_id),
            ("authority_policy_decision_id", self.policy_decision_id),
            ("authority_policy_revision", self.policy_revision),
            ("authority_target_class", self.target_class),
            ("authority_application_class", self.application_class),
            ("authority_environment_class", self.environment_class),
            ("authority_url_class", self.url_class),
        ):
            _identifier(identifier_name, identifier_value)
        for digest_name, digest_value in (
            ("authority_target_mapping_sha256", self.target_mapping_sha256),
            ("authority_roe_sha256", self.roe_sha256),
            ("authority_policy_sha256", self.policy_sha256),
        ):
            _sha256(digest_name, digest_value)
        if self.target.kind != "target":
            raise ValueError("r119_authority_target_kind_invalid")
        if self.roe_status != "approved" or self.policy_status != "allowed":
            raise ValueError("r119_authority_denied")
        _window("r119_authority", self.issued_at, self.expires_at)


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceFactV1:
    schema_version: str
    tenant_id: str
    engagement_id: str
    binding_key_sha256: str
    target: TypedReferenceV1
    resource: TypedReferenceV1
    evidence: TypedReferenceV1
    job: TypedReferenceV1
    producer_adapter_id: str
    producer_revision: str
    producer_schema_id: str
    observation_kind: ObservationKind
    source_definition_id: str
    source_matcher_id: str
    source_path: str
    verified: bool
    redaction_state: str
    finalized_at: datetime
    expires_at: datetime
    invalidation_state: InvalidationState

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r119-evidence-fact/v1":
            raise ValueError("r119_evidence_schema_invalid")
        for name, value in (
            ("evidence_tenant_id", self.tenant_id),
            ("evidence_engagement_id", self.engagement_id),
            ("evidence_producer_adapter_id", self.producer_adapter_id),
            ("evidence_producer_revision", self.producer_revision),
            ("evidence_producer_schema_id", self.producer_schema_id),
            ("evidence_source_definition_id", self.source_definition_id),
            ("evidence_source_matcher_id", self.source_matcher_id),
            ("evidence_redaction_state", self.redaction_state),
        ):
            _identifier(name, value)
        if not isinstance(self.verified, bool):
            raise ValueError("r119_evidence_verified_invalid")
        if not isinstance(self.observation_kind, ObservationKind):
            raise ValueError("r119_evidence_observation_kind_invalid")
        _sha256("evidence_binding_key_sha256", self.binding_key_sha256)
        if not _SAFE_PATH.fullmatch(self.source_path):
            raise ValueError("r119_evidence_source_path_invalid")
        if (
            self.target.kind != "target"
            or self.resource.kind not in _OBSERVATION_OBJECT_KINDS
            or self.evidence.kind != "evidence"
            or self.job.kind != "job"
        ):
            raise ValueError("r119_evidence_reference_kind_invalid")
        if not isinstance(self.invalidation_state, InvalidationState):
            raise ValueError("r119_evidence_invalidation_invalid")
        _window("r119_evidence", self.finalized_at, self.expires_at)


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationFactV1:
    schema_version: str
    fact_id: str
    tenant_id: str
    engagement_id: str
    binding_key_sha256: str
    subject: TypedReferenceV1
    object: TypedReferenceV1
    kind: ObservationKind
    truth: TruthValue
    value_code: str | None
    source_adapter_id: str
    producer_revision: str
    producer_schema_id: str
    trust: TrustLevel
    confidence: Confidence
    evidence: TypedReferenceV1
    provenance_sha256: str
    observed_at: datetime
    valid_from: datetime
    ingested_at: datetime
    expires_at: datetime
    completeness: Completeness
    invalidation_state: InvalidationState

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r119-observation/v1":
            raise ValueError("r119_observation_contract_schema_invalid")
        for name, value in (
            ("observation_fact_id", self.fact_id),
            ("observation_tenant_id", self.tenant_id),
            ("observation_engagement_id", self.engagement_id),
            ("observation_source_adapter_id", self.source_adapter_id),
            ("observation_producer_revision", self.producer_revision),
            ("observation_producer_schema_id", self.producer_schema_id),
        ):
            _identifier(name, value)
        _sha256("observation_binding_key_sha256", self.binding_key_sha256)
        _sha256("observation_provenance_sha256", self.provenance_sha256)
        if not isinstance(self.kind, ObservationKind) or not isinstance(self.truth, TruthValue):
            raise ValueError("r119_observation_kind_or_truth_invalid")
        if not isinstance(self.trust, TrustLevel) or not isinstance(self.confidence, Confidence):
            raise ValueError("r119_observation_trust_invalid")
        if not isinstance(self.completeness, Completeness) or not isinstance(
            self.invalidation_state, InvalidationState
        ):
            raise ValueError("r119_observation_state_invalid")
        if self.subject.kind != "target" or self.evidence.kind != "evidence":
            raise ValueError("r119_observation_reference_kind_invalid")
        _observation_value(self.kind, self.truth, self.value_code)
        if self.kind is ObservationKind.TARGET_REACHABILITY and self.object != self.subject:
            raise ValueError("r119_observation_object_mismatch")
        if self.kind is ObservationKind.HTTP_RESPONSE_STATUS and (
            self.object.kind != "http-response" or self.object.reference_id != "response-status"
        ):
            raise ValueError("r119_observation_object_mismatch")
        if self.kind in {
            ObservationKind.SECURITY_HEADER_PRESENT,
            ObservationKind.SECURITY_HEADER_MISSING,
        } and (
            self.object.kind != "security-header"
            or self.object.reference_id not in _HEADER_CODES
            or (self.value_code is not None and self.object.reference_id != self.value_code)
        ):
            raise ValueError("r119_observation_object_mismatch")
        if self.kind is ObservationKind.CAPABILITY_OUTCOME and self.object.kind != "capability":
            raise ValueError("r119_observation_object_mismatch")
        if self.kind is ObservationKind.EVIDENCE_IDENTITY and self.object != self.evidence:
            raise ValueError("r119_observation_object_mismatch")
        for timestamp_name, timestamp_value in (
            ("observation_observed_at", self.observed_at),
            ("observation_valid_from", self.valid_from),
            ("observation_ingested_at", self.ingested_at),
            ("observation_expires_at", self.expires_at),
        ):
            _aware(timestamp_name, timestamp_value)
        if not self.valid_from <= self.observed_at <= self.ingested_at < self.expires_at:
            raise ValueError("r119_observation_time_invalid")

    def identity_body(self) -> tuple[builtins.object, ...]:
        return (
            self.tenant_id,
            self.engagement_id,
            self.binding_key_sha256,
            self.subject.kind,
            self.subject.reference_id,
            self.subject.sha256,
            self.object.kind,
            self.object.reference_id,
            self.object.sha256,
            self.kind.value,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionPromotionV1:
    kind: DetectionPromotionKind
    proof_ref: TypedReferenceV1
    promoted_at: datetime
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        if _validation_token is not _DETECTION_VALIDATION_TOKEN:
            raise ValueError("detection_promotion_factory_required")
        if not isinstance(self.kind, DetectionPromotionKind):
            raise ValueError("detection_promotion_kind_invalid")
        expected_kind = (
            "human-review"
            if self.kind is DetectionPromotionKind.HUMAN_REVIEW
            else "correlation-receipt"
        )
        if self.proof_ref.kind != expected_kind:
            raise ValueError("detection_promotion_reference_invalid")
        _aware("detection_promoted_at", self.promoted_at)


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionObservationV1:
    schema_version: str
    observation_id: str
    tenant_id: str
    engagement_id: str
    correlation_key: str
    capability_id: str
    source: TelemetrySource
    source_system: str
    attack_technique_id: str
    attack_version: str
    confidence: Confidence
    severity: DetectionSeverity
    disposition: DetectionDisposition
    promotion: DetectionPromotionV1 | None
    evidence_ref: TypedReferenceV1
    observed_at: datetime
    ingested_at: datetime
    expires_at: datetime
    ocsf_class_uid: int | None
    ocsf_category_uid: int | None
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        # CRITICAL: detection observations are factory-minted; raw alert text is never a field.
        if _validation_token is not _DETECTION_VALIDATION_TOKEN:
            raise ValueError("detection_observation_factory_required")
        if self.schema_version != "redagent.detection-observation/v1":
            raise ValueError("detection_observation_schema_invalid")
        for name, value in (
            ("detection_observation_id", self.observation_id),
            ("detection_tenant_id", self.tenant_id),
            ("detection_engagement_id", self.engagement_id),
            ("detection_correlation_key", self.correlation_key),
            ("detection_capability_id", self.capability_id),
            ("detection_source_system", self.source_system),
            ("detection_attack_version", self.attack_version),
        ):
            _identifier(name, value)
        if not isinstance(self.source, TelemetrySource):
            raise ValueError("detection_source_invalid")
        if not _ATTACK_TECHNIQUE_ID.fullmatch(self.attack_technique_id):
            raise ValueError("detection_attack_technique_invalid")
        if not isinstance(self.confidence, Confidence) or not isinstance(
            self.severity, DetectionSeverity
        ):
            raise ValueError("detection_scoring_invalid")
        if not isinstance(self.disposition, DetectionDisposition):
            raise ValueError("detection_disposition_invalid")
        if self.disposition is DetectionDisposition.UNCONFIRMED:
            if self.promotion is not None:
                raise ValueError("detection_unconfirmed_promotion_forbidden")
        elif not isinstance(self.promotion, DetectionPromotionV1):
            raise ValueError("detection_promotion_required")
        if self.evidence_ref.kind != "evidence":
            raise ValueError("detection_evidence_reference_invalid")
        for timestamp_name, timestamp_value in (
            ("detection_observed_at", self.observed_at),
            ("detection_ingested_at", self.ingested_at),
            ("detection_expires_at", self.expires_at),
        ):
            _aware(timestamp_name, timestamp_value)
        if not self.observed_at <= self.ingested_at < self.expires_at:
            raise ValueError("detection_observation_time_invalid")
        if (self.ocsf_class_uid, self.ocsf_category_uid) not in {
            (None, None),
            (2004, 2),
        }:
            raise ValueError("detection_ocsf_finding_shape_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionCorrelationDispositionV1:
    schema_version: str
    tenant_id: str
    engagement_id: str
    correlation_key: str
    attack_technique_id: str
    input_observation_bindings: tuple[tuple[str, str], ...]
    correlated: bool
    qualified_observation_ids: tuple[str, ...]
    excluded: tuple[tuple[str, str], ...]
    evaluated_at: datetime
    max_age_seconds: int
    correlation_sha256: str
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        if _validation_token is not _DETECTION_VALIDATION_TOKEN:
            raise ValueError("detection_correlation_factory_required")
        if self.schema_version != "redagent.detection-correlation/v1":
            raise ValueError("detection_correlation_schema_invalid")
        _identifier("detection_correlation_tenant", self.tenant_id)
        _identifier("detection_correlation_engagement", self.engagement_id)
        _identifier("detection_correlation_key", self.correlation_key)
        if not _ATTACK_TECHNIQUE_ID.fullmatch(self.attack_technique_id):
            raise ValueError("detection_correlation_technique_invalid")
        if not isinstance(self.correlated, bool):
            raise ValueError("detection_correlation_result_invalid")
        if tuple(sorted(set(self.input_observation_bindings))) != self.input_observation_bindings:
            raise ValueError("detection_correlation_input_bindings_invalid")
        input_ids: list[str] = []
        for observation_id, observation_sha256 in self.input_observation_bindings:
            _identifier("detection_correlation_input_observation", observation_id)
            _sha256("detection_correlation_input_observation_sha256", observation_sha256)
            input_ids.append(observation_id)
        if len(set(input_ids)) != len(input_ids):
            raise ValueError("detection_correlation_input_identity_conflict")
        if tuple(sorted(set(self.qualified_observation_ids))) != self.qualified_observation_ids:
            raise ValueError("detection_correlation_qualified_invalid")
        for observation_id in self.qualified_observation_ids:
            _identifier("detection_correlation_observation", observation_id)
        if tuple(sorted(set(self.excluded))) != self.excluded:
            raise ValueError("detection_correlation_excluded_invalid")
        for observation_id, reason in self.excluded:
            _identifier("detection_correlation_observation", observation_id)
            _identifier("detection_correlation_reason", reason)
        if self.correlated != bool(self.qualified_observation_ids):
            raise ValueError("detection_correlation_count_mismatch")
        _aware("detection_correlation_evaluated_at", self.evaluated_at)
        _bounded_int("detection_correlation_max_age", self.max_age_seconds, 1, 3600)
        _sha256("detection_correlation_sha256", self.correlation_sha256)
        if self.correlation_sha256 != canonical_sha256(self.canonical_body()):
            raise ValueError("detection_correlation_digest_mismatch")

    def canonical_body(self) -> dict[str, object]:
        return {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field not in {"correlation_sha256", "_validation_token"}
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingFactV1:
    schema_version: str
    fact_id: str
    tenant_id: str
    engagement_id: str
    binding_key_sha256: str
    target: TypedReferenceV1
    resource: TypedReferenceV1
    import_session: TypedReferenceV1
    occurrence: TypedReferenceV1
    issue: TypedReferenceV1
    evidence: TypedReferenceV1
    source_adapter_id: str
    producer_revision: str
    source_schema_id: str
    observation_kind: ObservationKind
    source_definition_id: str
    source_matcher_id: str
    source_path: str
    import_state: str
    occurrence_state: str
    disposition: str
    disposition_revision: int
    retest_state: str
    observed_at: datetime
    updated_at: datetime
    expires_at: datetime
    invalidation_state: InvalidationState

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r119-finding-fact/v1":
            raise ValueError("r119_finding_schema_invalid")
        for identifier_name, identifier_value in (
            ("finding_fact_id", self.fact_id),
            ("finding_tenant_id", self.tenant_id),
            ("finding_engagement_id", self.engagement_id),
            ("finding_source_adapter_id", self.source_adapter_id),
            ("finding_producer_revision", self.producer_revision),
            ("finding_source_schema_id", self.source_schema_id),
            ("finding_source_definition_id", self.source_definition_id),
            ("finding_source_matcher_id", self.source_matcher_id),
            ("finding_import_state", self.import_state),
            ("finding_occurrence_state", self.occurrence_state),
            ("finding_disposition", self.disposition),
            ("finding_retest_state", self.retest_state),
        ):
            _identifier(identifier_name, identifier_value)
        _sha256("finding_binding_key_sha256", self.binding_key_sha256)
        if self.observation_kind is not ObservationKind.SECURITY_HEADER_MISSING:
            raise ValueError("r119_finding_observation_kind_invalid")
        if not _SAFE_PATH.fullmatch(self.source_path):
            raise ValueError("r119_finding_source_path_invalid")
        _positive_int("r119_finding_disposition_revision", self.disposition_revision)
        if self.disposition not in _FINDING_DISPOSITIONS or self.retest_state not in _RETEST_STATES:
            raise ValueError("r119_finding_state_invalid")
        if (
            self.target.kind != "target"
            or self.resource.kind not in _OBSERVATION_OBJECT_KINDS
            or self.import_session.kind != "finding-import"
            or self.occurrence.kind != "finding-occurrence"
            or self.issue.kind != "managed-issue"
            or self.evidence.kind != "evidence"
        ):
            raise ValueError("r119_finding_reference_kind_invalid")
        if not isinstance(self.invalidation_state, InvalidationState):
            raise ValueError("r119_finding_invalidation_invalid")
        for timestamp_name, timestamp_value in (
            ("finding_observed_at", self.observed_at),
            ("finding_updated_at", self.updated_at),
            ("finding_expires_at", self.expires_at),
        ):
            _aware(timestamp_name, timestamp_value)
        if not self.observed_at <= self.updated_at < self.expires_at:
            raise ValueError("r119_finding_time_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class FactDispositionV1:
    fact_sha256: str
    reason: str

    def __post_init__(self) -> None:
        _sha256("fact_disposition_sha256", self.fact_sha256)
        _identifier("fact_disposition_reason", self.reason)


@dataclass(frozen=True, slots=True, kw_only=True)
class FactConflictV1:
    identity_sha256: str
    fact_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        _sha256("fact_conflict_identity_sha256", self.identity_sha256)
        if len(self.fact_sha256s) < 2 or tuple(sorted(set(self.fact_sha256s))) != self.fact_sha256s:
            raise ValueError("r119_fact_conflict_invalid")
        for value in self.fact_sha256s:
            _sha256("fact_conflict_fact_sha256", value)


@dataclass(frozen=True, slots=True, kw_only=True)
class DecisionContextSnapshotV1:
    schema_version: str
    snapshot_at: datetime
    authority_sha256: str
    target_mapping_sha256: str
    collection_state: CollectionState
    semantics: tuple[PromotedCapabilitySemanticsV1, ...]
    observations: tuple[ObservationFactV1, ...]
    evidence_facts: tuple[EvidenceFactV1, ...]
    finding_facts: tuple[FindingFactV1, ...]
    dispositions: tuple[FactDispositionV1, ...]
    conflicts: tuple[FactConflictV1, ...]
    detection_observations: tuple[DetectionObservationV1, ...]
    capability_section_sha256: str
    trusted_section_sha256: str
    snapshot_sha256: str
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        if _validation_token is not _SNAPSHOT_VALIDATION_TOKEN:
            raise ValueError("r119_snapshot_factory_required")
        if self.schema_version not in {
            "redagent.r119-decision-context/v1",
            "redagent.detection-decision-context/v2",
            "redagent.artifact-posture-decision-context/v2",
        }:
            raise ValueError("r119_snapshot_schema_invalid")
        if (
            self.schema_version == "redagent.detection-decision-context/v2"
        ) != bool(self.detection_observations):
            raise ValueError("detection_snapshot_schema_mismatch")
        _aware("r119_snapshot_at", self.snapshot_at)
        if not isinstance(self.collection_state, CollectionState):
            raise ValueError("r119_collection_state_invalid")
        for name, value in (
            ("r119_snapshot_authority_sha256", self.authority_sha256),
            ("r119_snapshot_target_mapping_sha256", self.target_mapping_sha256),
            ("r119_snapshot_capability_section_sha256", self.capability_section_sha256),
            ("r119_snapshot_trusted_section_sha256", self.trusted_section_sha256),
            ("r119_snapshot_sha256", self.snapshot_sha256),
        ):
            _sha256(name, value)
        capability_expected = canonical_sha256(self.semantics)
        trusted_body: dict[str, object] = {
            "collection_state": self.collection_state,
            "observations": self.observations,
            "evidence_facts": self.evidence_facts,
            "finding_facts": self.finding_facts,
            "dispositions": self.dispositions,
            "conflicts": self.conflicts,
        }
        if self.detection_observations:
            trusted_body["detection_observations"] = self.detection_observations
        trusted_expected = canonical_sha256(trusted_body)
        snapshot_expected = canonical_sha256(
            {
                "schema_version": self.schema_version,
                "snapshot_at": self.snapshot_at,
                "authority_sha256": self.authority_sha256,
                "target_mapping_sha256": self.target_mapping_sha256,
                "capability_section_sha256": self.capability_section_sha256,
                "trusted_section_sha256": self.trusted_section_sha256,
            }
        )
        if (
            self.capability_section_sha256 != capability_expected
            or self.trusted_section_sha256 != trusted_expected
            or self.snapshot_sha256 != snapshot_expected
        ):
            raise ValueError("r119_snapshot_digest_mismatch")

    def canonical_body(self) -> dict[str, object]:
        body = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field != "_validation_token"
        }
        if self.schema_version != "redagent.detection-decision-context/v2":
            body.pop("detection_observations")
        return body


class StrategyObjectiveKind(str, Enum):
    HTTP_POSTURE = "http_posture"
    SECURITY_HEADER_ASSERTION = "security_header_assertion"
    REPOSITORY_SNAPSHOT_POSTURE = "repository_snapshot_posture"


class StrategyOutcome(str, Enum):
    SELECT = "select"
    SKIP = "skip"
    STOP = "stop"


@dataclass(frozen=True, slots=True, kw_only=True)
class StrategyObjectiveV1:
    schema_version: str
    objective_id: str
    tenant_id: str
    engagement_id: str
    target: TypedReferenceV1
    kind: StrategyObjectiveKind
    header_code: str | None
    require_corroboration: bool
    artifact_receipt: TypedReferenceV1 | None = None

    def __post_init__(self) -> None:
        if self.schema_version not in {
            "redagent.r121-objective/v1",
            "redagent.artifact-posture-objective/v2",
        }:
            raise ValueError("r121_objective_schema_invalid")
        for name, value in (
            ("r121_objective_id", self.objective_id),
            ("r121_objective_tenant", self.tenant_id),
            ("r121_objective_engagement", self.engagement_id),
        ):
            _identifier(name, value)
        if self.target.kind != "target" or not isinstance(self.kind, StrategyObjectiveKind):
            raise ValueError("r121_objective_invalid")
        if not isinstance(self.require_corroboration, bool):
            raise ValueError("r121_objective_corroboration_invalid")
        if self.schema_version == "redagent.r121-objective/v1" and (
            self.kind is StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE
            or self.artifact_receipt is not None
        ):
            raise ValueError("r121_objective_schema_invalid")
        if self.schema_version == "redagent.artifact-posture-objective/v2" and (
            self.kind is not StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE
        ):
            raise ValueError("r121_objective_schema_invalid")
        if self.kind is StrategyObjectiveKind.SECURITY_HEADER_ASSERTION:
            if self.header_code != "x-content-type-options":
                raise ValueError("r121_objective_header_invalid")
        elif self.header_code is not None:
            raise ValueError("r121_objective_header_forbidden")
        if self.kind is StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE:
            if self.require_corroboration:
                raise ValueError("r121_objective_artifact_corroboration_forbidden")
        elif self.artifact_receipt is not None:
            raise ValueError("r121_objective_artifact_receipt_forbidden")

    def canonical_body(self) -> dict[str, object]:
        body = asdict(self)
        if self.schema_version == "redagent.r121-objective/v1":
            body.pop("artifact_receipt")
        return body


@dataclass(frozen=True, slots=True, kw_only=True)
class StrategyBudgetV1:
    max_elapsed_seconds: int
    max_operations: int
    max_targets: int
    max_evidence_bytes: int
    max_depth: int

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("elapsed", self.max_elapsed_seconds, 300),
            ("operations", self.max_operations, 2),
            ("targets", self.max_targets, 1),
            ("evidence", self.max_evidence_bytes, 1_048_576),
            ("depth", self.max_depth, 2),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValueError(f"r121_budget_{name}_invalid")


_R121_STOP_REASONS = frozenset({
    "policy_denied",
    "evidence_failure",
    "cleanup_failure",
    "infrastructure_failure",
    "attention_required",
})


@dataclass(frozen=True, slots=True, kw_only=True)
class StrategySignalsV1:
    stop_reason: str | None = None

    def __post_init__(self) -> None:
        if self.stop_reason is not None and self.stop_reason not in _R121_STOP_REASONS:
            raise ValueError("r121_signal_reason_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelStrategyProposalV1:
    schema_version: str
    outcome: StrategyOutcome
    selected_binding_sha256: str | None

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r121-model-proposal/v1":
            raise ValueError("r121_model_proposal_schema_invalid")
        if not isinstance(self.outcome, StrategyOutcome):
            raise ValueError("r121_model_proposal_outcome_invalid")
        if self.selected_binding_sha256 is not None:
            _sha256("r121_model_proposal_binding", self.selected_binding_sha256)
        if (self.outcome is StrategyOutcome.SELECT) != (self.selected_binding_sha256 is not None):
            raise ValueError("r121_model_proposal_selection_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class CandidateDispositionV1:
    binding_key_sha256: str
    capability_id: str
    eligible: bool
    deterministic_priority: int
    matched_rule: str
    reason: str

    def __post_init__(self) -> None:
        _sha256("r121_candidate_binding", self.binding_key_sha256)
        for name, value in (
            ("r121_candidate_capability", self.capability_id),
            ("r121_candidate_rule", self.matched_rule),
            ("r121_candidate_reason", self.reason),
        ):
            _identifier(name, value)
        if not isinstance(self.eligible, bool) or self.deterministic_priority not in {1, 2, 3}:
            raise ValueError("r121_candidate_disposition_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanActionV1:
    binding_key_sha256: str
    capability_id: str
    profile_id: str
    projection_sha256: str
    approval_class: str
    evidence_schemas: tuple[str, ...]
    budget: StrategyBudgetV1
    cleanup: str
    stop_predicates: tuple[str, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("r121_action_binding", self.binding_key_sha256),
            ("r121_action_projection", self.projection_sha256),
        ):
            _sha256(name, value)
        for name, value in (
            ("r121_action_capability", self.capability_id),
            ("r121_action_profile", self.profile_id),
            ("r121_action_approval", self.approval_class),
            ("r121_action_cleanup", self.cleanup),
        ):
            _identifier(name, value)
        _closed_identifiers("r121_action_evidence", self.evidence_schemas, maximum=8)
        _closed_identifiers("r121_action_stops", self.stop_predicates, maximum=8)
        if self.approval_class != "high":
            raise ValueError("r121_action_approval_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class ConditionalSuccessorV1:
    condition: str
    action: PlanActionV1

    def __post_init__(self) -> None:
        if self.condition not in {
            "explicit_corroboration",
            "fresh_inconclusive_or_insufficient_observation",
        }:
            raise ValueError("r121_successor_condition_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class StrategyDecisionReceiptV1:
    schema_version: str
    objective: StrategyObjectiveV1
    objective_sha256: str
    snapshot: DecisionContextSnapshotV1
    snapshot_sha256: str
    capability_section_sha256: str
    trusted_section_sha256: str
    authority_sha256: str
    target_mapping_sha256: str
    policy_revision: str
    policy_sha256: str
    roe_version_id: str
    roe_sha256: str
    decision_table_revision: int
    candidates: tuple[CandidateDispositionV1, ...]
    outcome: StrategyOutcome
    matched_rule: str
    reason: str
    selected_binding_sha256: str | None
    detection_disposition: DetectionCorrelationDispositionV1 | None
    coverage_matrix_sha256: str | None
    receipt_sha256: str
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        if _validation_token is not _R121_VALIDATION_TOKEN:
            raise ValueError("r121_receipt_factory_required")
        if self.schema_version not in {
            "redagent.r121-strategy-receipt/v1",
            "redagent.detection-strategy-receipt/v2",
            "redagent.artifact-posture-strategy-receipt/v2",
        }:
            raise ValueError("r121_receipt_schema_invalid")
        if not isinstance(self.objective, StrategyObjectiveV1):
            raise ValueError("r121_receipt_objective_invalid")
        if not isinstance(self.snapshot, DecisionContextSnapshotV1):
            raise ValueError("r121_receipt_snapshot_invalid")
        for name, value in (
            ("objective", self.objective_sha256), ("snapshot", self.snapshot_sha256),
            ("capability", self.capability_section_sha256), ("trusted", self.trusted_section_sha256),
            ("authority", self.authority_sha256), ("mapping", self.target_mapping_sha256),
            ("policy", self.policy_sha256), ("roe", self.roe_sha256),
            ("receipt", self.receipt_sha256),
        ):
            _sha256(f"r121_receipt_{name}", value)
        for name, value in (
            ("r121_receipt_policy_revision", self.policy_revision),
            ("r121_receipt_roe_version", self.roe_version_id),
            ("r121_receipt_rule", self.matched_rule),
            ("r121_receipt_reason", self.reason),
        ):
            _identifier(name, value)
        expected_table, expected_candidates = (
            (2, 3)
            if self.schema_version == "redagent.artifact-posture-strategy-receipt/v2"
            else (1, 2)
        )
        if (
            self.decision_table_revision != expected_table
            or len(self.candidates) != expected_candidates
        ):
            raise ValueError("r121_receipt_table_or_candidates_invalid")
        if canonical_sha256(self.objective) != self.objective_sha256:
            raise ValueError("r121_receipt_objective_hash_mismatch")
        # CRITICAL: the receipt must carry the exact compat_119 facts, not hash-only aliases.
        if (
            self.snapshot.snapshot_sha256 != self.snapshot_sha256
            or self.snapshot.capability_section_sha256 != self.capability_section_sha256
            or self.snapshot.trusted_section_sha256 != self.trusted_section_sha256
            or self.snapshot.authority_sha256 != self.authority_sha256
            or self.snapshot.target_mapping_sha256 != self.target_mapping_sha256
        ):
            raise ValueError("r121_receipt_snapshot_hash_mismatch")
        if tuple(sorted(self.candidates, key=lambda item: item.binding_key_sha256)) != self.candidates:
            raise ValueError("r121_receipt_candidates_not_canonical")
        if not isinstance(self.outcome, StrategyOutcome):
            raise ValueError("r121_receipt_outcome_invalid")
        if self.selected_binding_sha256 is not None:
            _sha256("r121_receipt_selected_binding", self.selected_binding_sha256)
        if (self.outcome is StrategyOutcome.SELECT) != (self.selected_binding_sha256 is not None):
            raise ValueError("r121_receipt_selection_invalid")
        if (self.detection_disposition is None) != (self.coverage_matrix_sha256 is None):
            raise ValueError("detection_receipt_binding_invalid")
        if self.schema_version == "redagent.r121-strategy-receipt/v1" and (
            self.snapshot.schema_version != "redagent.r119-decision-context/v1"
            or self.detection_disposition is not None
        ):
            raise ValueError("detection_receipt_schema_mismatch")
        if self.schema_version == "redagent.detection-strategy-receipt/v2" and (
            self.snapshot.schema_version != "redagent.detection-decision-context/v2"
        ):
            raise ValueError("detection_receipt_schema_mismatch")
        if self.schema_version == "redagent.artifact-posture-strategy-receipt/v2" and (
            self.snapshot.schema_version
            != "redagent.artifact-posture-decision-context/v2"
            or self.detection_disposition is not None
            or self.objective.schema_version
            not in {
                "redagent.r121-objective/v1",
                "redagent.artifact-posture-objective/v2",
            }
        ):
            raise ValueError("artifact_posture_receipt_schema_mismatch")
        if self.detection_disposition is not None:
            _sha256("detection_receipt_matrix", self.coverage_matrix_sha256)
        if self.receipt_sha256 != canonical_sha256(self.canonical_body()):
            raise ValueError("r121_receipt_digest_mismatch")

    def canonical_body(self) -> dict[str, object]:
        body = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field not in {"receipt_sha256", "_validation_token"}
        }
        if self.schema_version != "redagent.detection-strategy-receipt/v2":
            body.pop("detection_disposition")
            body.pop("coverage_matrix_sha256")
        return body


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanRevisionV1:
    schema_version: str
    plan_id: str
    revision: int
    tenant_id: str
    engagement_id: str
    target: TypedReferenceV1
    objective_sha256: str
    receipt_sha256: str
    snapshot_sha256: str
    authority_sha256: str
    policy_revision: str
    policy_sha256: str
    roe_version_id: str
    roe_sha256: str
    decision_table_revision: int
    width: int
    depth: int
    primary: PlanActionV1
    successor: ConditionalSuccessorV1 | None
    plan_sha256: str
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        if _validation_token is not _R121_VALIDATION_TOKEN:
            raise ValueError("r121_plan_factory_required")
        if self.schema_version not in {
            "redagent.r121-plan-revision/v1",
            "redagent.artifact-posture-plan-revision/v2",
        }:
            raise ValueError("r121_plan_schema_invalid")
        for name, value in (
            ("r121_plan_id", self.plan_id), ("r121_plan_tenant", self.tenant_id),
            ("r121_plan_engagement", self.engagement_id),
            ("r121_plan_policy_revision", self.policy_revision),
            ("r121_plan_roe_version", self.roe_version_id),
        ):
            _identifier(name, value)
        for name, value in (
            ("objective", self.objective_sha256), ("receipt", self.receipt_sha256),
            ("snapshot", self.snapshot_sha256), ("authority", self.authority_sha256),
            ("policy", self.policy_sha256), ("roe", self.roe_sha256),
            ("plan", self.plan_sha256),
        ):
            _sha256(f"r121_plan_{name}", value)
        expected_table = (
            2 if self.schema_version == "redagent.artifact-posture-plan-revision/v2" else 1
        )
        if (
            self.target.kind != "target"
            or self.revision != 1
            or self.decision_table_revision != expected_table
        ):
            raise ValueError("r121_plan_identity_invalid")
        if self.width != 1 or self.depth not in {1, 2}:
            raise ValueError("r121_plan_bounds_invalid")
        if (self.successor is None) != (self.depth == 1):
            raise ValueError("r121_plan_successor_depth_mismatch")
        if self.successor is not None and (
            self.successor.action.binding_key_sha256 == self.primary.binding_key_sha256
        ):
            raise ValueError("r121_plan_successor_redundant")
        if self.plan_sha256 != canonical_sha256(self.canonical_body()):
            raise ValueError("r121_plan_digest_mismatch")

    def canonical_body(self) -> dict[str, object]:
        return {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field not in {"plan_sha256", "_validation_token"}
        }


def _validated_strategy_receipt(**values: object) -> StrategyDecisionReceiptV1:
    return StrategyDecisionReceiptV1(**values, _validation_token=_R121_VALIDATION_TOKEN)  # type: ignore[arg-type]


def _validated_plan_revision(**values: object) -> PlanRevisionV1:
    return PlanRevisionV1(**values, _validation_token=_R121_VALIDATION_TOKEN)  # type: ignore[arg-type]


def _validated_decision_context_snapshot(**values: object) -> DecisionContextSnapshotV1:
    """Mint a snapshot only after the campaign context builder validates every input."""
    return DecisionContextSnapshotV1(
        _validation_token=_SNAPSHOT_VALIDATION_TOKEN,
        **cast(Any, values),
    )


def _validated_detection_promotion(**values: object) -> DetectionPromotionV1:
    return DetectionPromotionV1(
        _validation_token=_DETECTION_VALIDATION_TOKEN,
        **cast(Any, values),
    )


def _validated_detection_observation(**values: object) -> DetectionObservationV1:
    return DetectionObservationV1(
        _validation_token=_DETECTION_VALIDATION_TOKEN,
        **cast(Any, values),
    )


def _validated_detection_correlation(
    **values: object,
) -> DetectionCorrelationDispositionV1:
    return DetectionCorrelationDispositionV1(
        _validation_token=_DETECTION_VALIDATION_TOKEN,
        **cast(Any, values),
    )


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        _normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("r119_canonical_payload_too_large")
    return hashlib.sha256(encoded).hexdigest()


def _normalize(value: object) -> object:
    if isinstance(value, datetime):
        _aware("canonical_datetime", value)
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return value.value
    # IMPORTANT: additive detection fields must not drift frozen v1 canonical evidence.
    if isinstance(value, DecisionContextSnapshotV1):
        return _normalize(value.canonical_body())
    if isinstance(value, StrategyDecisionReceiptV1):
        return _normalize(value.canonical_body())
    if isinstance(value, StrategyObjectiveV1):
        return _normalize(value.canonical_body())
    if hasattr(value, "__dataclass_fields__"):
        return _normalize(asdict(cast(Any, value)))
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("r119_canonical_key_invalid")
        return {key: _normalize(item) for key, item in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [_normalize(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise ValueError("r119_canonical_type_invalid")


def _observation_value(kind: ObservationKind, truth: TruthValue, value: str | None) -> None:
    if truth in {TruthValue.UNKNOWN, TruthValue.NOT_OBSERVED}:
        if value is not None:
            raise ValueError("r119_observation_value_invalid")
        return
    if kind in {ObservationKind.SECURITY_HEADER_PRESENT, ObservationKind.SECURITY_HEADER_MISSING}:
        if value not in _HEADER_CODES:
            raise ValueError("r119_observation_value_invalid")
    elif kind is ObservationKind.HTTP_RESPONSE_STATUS:
        if value is None or not value.isdigit() or not 100 <= int(value) <= 599:
            raise ValueError("r119_observation_value_invalid")
    elif kind is ObservationKind.CAPABILITY_OUTCOME:
        if value not in _OUTCOME_CODES:
            raise ValueError("r119_observation_value_invalid")
    elif value is not None:
        raise ValueError("r119_observation_value_invalid")


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _positive_int(name: str, value: object) -> None:
    _bounded_int(name, value, 1, 2_147_483_647)


def _bounded_int(name: str, value: object, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _closed_identifiers(name: str, values: tuple[str, ...], *, maximum: int) -> None:
    if not values or len(values) > maximum or len(set(values)) != len(values):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value)


def _aware(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_invalid")


def _window(name: str, start: datetime, end: datetime) -> None:
    _aware(f"{name}_start", start)
    _aware(f"{name}_end", end)
    if not start < end:
        raise ValueError(f"{name}_window_invalid")
