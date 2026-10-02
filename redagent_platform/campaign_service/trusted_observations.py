"""Fail-closed trust promotion for provenance-backed campaign observations."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta
from enum import Enum
import re

from redagent_platform.campaign_service.dag_execution_contracts import (
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
)
from redagent_platform.campaign_service.dag_execution_service import DagExecutionStartMaterialV1
from redagent_platform.campaign_service.execution import (
    EffectReceiptV1,
    NodeObservedV1,
    ReconciliationState,
)
from redagent_platform.campaign_service.contracts import (
    DetectionCorrelationDispositionV1,
    DetectionDisposition,
    DetectionObservationV1,
    DetectionPromotionKind,
    canonical_sha256,
)
from redagent_platform.campaign_service.planning.contracts import (
    CapabilityIdentityV1,
    ScalarValueV1,
    ScalarType,
    PlanningDomainV1,
    WorldStateV1,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search_contracts import AttackPathDagRevisionV1
from redagent_platform.campaign_service.child_replan_contracts import OWNED_COMPLETION_FACTS
from redagent_platform.campaign_service.registry import closed_execution_binding_for


PREDICTED_STATE_SCHEMA_VERSION = "redagent.predicted-state/v1"
OBSERVATION_CANDIDATE_SCHEMA_VERSION = "redagent.observation-candidate/v1"
OBSERVATION_POLICY_SCHEMA_VERSION = "redagent.observation-promotion-policy/v1"
TRUSTED_OBSERVATION_SCHEMA_VERSION = "redagent.trusted-observation/v1"
OBSERVATION_PROMOTION_SCHEMA_VERSION = "redagent.observation-promotion-decision/v1"
OBSERVATION_HISTORY_SCHEMA_VERSION = "redagent.trusted-observation-history/v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,149}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,99}$")
_VERIFIED_EVIDENCE_TOKEN = object()
_TRUSTED_OBSERVATION_TOKEN = object()
_OWNED_COMPLETION_SOURCE_TOKEN = object()


class ObservationProducerKind(str, Enum):
    DETECTION_CORRELATION = "detection_correlation"
    DAG_RUNNER_RESULT = "dag_runner_result"
    MODEL_ASSERTION = "model_assertion"
    PLANNER_PREDICTION = "planner_prediction"
    UI_ASSERTION = "ui_assertion"
    UNVERIFIED_TELEMETRY = "unverified_telemetry"


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnedCompletionSourceV1:
    """Minted after canonical owner and exact backend bytes verification; never an API input."""

    tenant_id: str
    campaign_id: str
    engagement_id: str
    target_id: str
    authority_sha256: str
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    snapshot: DagExecutionSnapshotV1
    parent_revision_sha256: str
    domain_sha256: str
    plan_sha256: str
    node_id: str
    persisted_node_state: DagNodeState
    capability: CapabilityIdentityV1
    effect_receipt: EffectReceiptV1
    report_artifact_id: str
    report_sha256: str
    report_size_bytes: int
    evidence_owner_sha256: str
    cleanup_owner_sha256: str
    verified_at: datetime
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        # CRITICAL: receipt/report digests supplied by callers cannot replace canonical owner/backend verification.
        if _validation_token is not _OWNED_COMPLETION_SOURCE_TOKEN:
            raise ValueError("owned_completion_owner_factory_required")
        for name in ("tenant_id", "campaign_id", "engagement_id", "target_id", "node_id", "report_artifact_id"):
            _identifier("owned_completion_" + name, getattr(self, name))
        for name in ("authority_sha256", "parent_revision_sha256", "domain_sha256", "plan_sha256",
                     "report_sha256", "evidence_owner_sha256", "cleanup_owner_sha256"):
            _sha256("owned_completion_" + name, getattr(self, name))
        for name in ("lifecycle_epoch", "policy_revocation_epoch", "roe_revocation_epoch", "kill_switch_epoch"):
            _bounded_int("owned_completion_" + name, getattr(self, name), 0, 2_147_483_647)
        _bounded_int("owned_completion_report_size", self.report_size_bytes, 1, 1_048_576)
        _aware("owned_completion_verified_at", self.verified_at)
        if (not isinstance(self.snapshot, DagExecutionSnapshotV1)
                or self.snapshot.state not in {DagRunState.COMPLETED, DagRunState.CONTAINED}
                or self.snapshot.current_node_id is not None or self.snapshot.current_node_state is not None
                or self.persisted_node_state is not DagNodeState.CONFIRMED):
            raise ValueError("owned_completion_terminal_parent_required")
        receipt = self.effect_receipt
        if (not isinstance(receipt, EffectReceiptV1) or receipt.reconciliation_state is not ReconciliationState.CONFIRMED
                or receipt.completed_at is None or receipt.completed_at > self.verified_at
                or not receipt.adapter_accepted or not receipt.output_complete or receipt.external_contact_count != 0
                or receipt.cleanup_receipt_id is None or receipt.redispatch_permitted or receipt.failure_code is not None
                or self.report_artifact_id not in receipt.evidence_ids):
            raise ValueError("owned_completion_confirmed_cleanup_receipt_required")
        if not isinstance(self.capability, CapabilityIdentityV1) or self.capability.capability_id not in OWNED_COMPLETION_FACTS:
            raise ValueError("owned_completion_capability_invalid")
        current = closed_execution_binding_for(self.capability.capability_id)
        for name in ("capability_revision", "adapter_id", "adapter_version", "profile_id", "profile_revision",
                     "profile_sha256", "bundle_id", "bundle_revision", "bundle_sha256"):
            if getattr(self.capability, name) != getattr(current, name):
                raise ValueError("owned_completion_current_capability_required")

    @property
    def provenance_sha256(self) -> str:
        return canonical_planning_sha256(self)


class ObservationPromotionOutcome(str, Enum):
    TRUSTED = "trusted"
    PRODUCER_DENIED = "producer_denied"
    SCOPE_MISMATCH = "scope_mismatch"
    CAMPAIGN_DRIFT = "campaign_drift"
    PROVENANCE_INVALID = "provenance_invalid"
    FUTURE = "future"
    STALE = "stale"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class ObservationProducerIdentityV1:
    kind: ObservationProducerKind
    producer_id: str
    producer_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ObservationProducerKind):
            raise ValueError("observation_producer_kind_invalid")
        _identifier("observation_producer_id", self.producer_id)
        _identifier("observation_producer_version", self.producer_version)


@dataclass(frozen=True, slots=True, kw_only=True)
class PredictedStateV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    planner_sha256: str
    revision_sha256: str
    world_state: WorldStateV1

    def __post_init__(self) -> None:
        if self.schema_version != PREDICTED_STATE_SCHEMA_VERSION:
            raise ValueError("predicted_state_schema_unsupported")
        _identifier("predicted_state_tenant", self.tenant_id)
        _identifier("predicted_state_campaign", self.campaign_id)
        _sha256("predicted_state_planner", self.planner_sha256)
        _sha256("predicted_state_revision", self.revision_sha256)
        if not isinstance(self.world_state, WorldStateV1):
            raise ValueError("predicted_state_world_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationCandidateV1:
    schema_version: str
    observation_id: str
    tenant_id: str
    campaign_id: str
    engagement_id: str
    target_id: str
    authority_sha256: str
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    fact_id: str
    value: ScalarValueV1
    producer: ObservationProducerIdentityV1
    source_result_sha256: str
    evidence_sha256: str
    observed_at: datetime
    received_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != OBSERVATION_CANDIDATE_SCHEMA_VERSION:
            raise ValueError("observation_candidate_schema_unsupported")
        for name in (
            "observation_id",
            "tenant_id",
            "campaign_id",
            "engagement_id",
            "target_id",
            "fact_id",
        ):
            _identifier(f"observation_candidate_{name}", getattr(self, name))
        _sha256("observation_candidate_authority", self.authority_sha256)
        _sha256("observation_candidate_result", self.source_result_sha256)
        _sha256("observation_candidate_evidence", self.evidence_sha256)
        for name in (
            "lifecycle_epoch",
            "policy_revocation_epoch",
            "roe_revocation_epoch",
            "kill_switch_epoch",
        ):
            _bounded_int(f"observation_candidate_{name}", getattr(self, name), 0, 2_147_483_647)
        if not isinstance(self.value, ScalarValueV1) or not isinstance(
            self.producer, ObservationProducerIdentityV1
        ):
            raise ValueError("observation_candidate_value_or_producer_invalid")
        for name in ("observed_at", "received_at", "expires_at"):
            _aware(f"observation_candidate_{name}", getattr(self, name))
        if not self.observed_at <= self.received_at < self.expires_at:
            raise ValueError("observation_candidate_time_invalid")

    @property
    def candidate_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedObservationEvidenceV1:
    observation_sha256: str
    producer: ObservationProducerIdentityV1
    source_record_id: str
    source_execution_run_id: str | None
    source_node_id: str | None
    fact_id: str
    value: ScalarValueV1
    source_result_sha256: str
    evidence_sha256: str
    verification_sha256: str
    verified_at: datetime
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        # CRITICAL: a digest asserted by a caller is not provenance; only closed result verifiers mint this type.
        if _validation_token is not _VERIFIED_EVIDENCE_TOKEN:
            raise ValueError("verified_observation_evidence_factory_required")
        for name in (
            "observation_sha256",
            "source_result_sha256",
            "evidence_sha256",
            "verification_sha256",
        ):
            _sha256(f"verified_observation_{name}", getattr(self, name))
        if not isinstance(self.producer, ObservationProducerIdentityV1):
            raise ValueError("verified_observation_producer_invalid")
        _identifier("verified_observation_source_record", self.source_record_id)
        if (self.source_execution_run_id is None) != (self.source_node_id is None):
            raise ValueError("verified_observation_execution_source_incomplete")
        if self.source_execution_run_id is not None:
            _identifier("verified_observation_execution_run", self.source_execution_run_id)
            _identifier("verified_observation_source_node", self.source_node_id)
        _identifier("verified_observation_fact", self.fact_id)
        if not isinstance(self.value, ScalarValueV1):
            raise ValueError("verified_observation_value_invalid")
        _aware("verified_observation_time", self.verified_at)


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationPromotionPolicyV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    engagement_id: str
    authority_sha256: str
    target_ids: tuple[str, ...]
    producer_registry_sha256: str
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    max_age_seconds: int

    def __post_init__(self) -> None:
        if self.schema_version != OBSERVATION_POLICY_SCHEMA_VERSION:
            raise ValueError("observation_policy_schema_unsupported")
        for name in ("tenant_id", "campaign_id", "engagement_id"):
            _identifier(f"observation_policy_{name}", getattr(self, name))
        _sha256("observation_policy_authority", self.authority_sha256)
        _canonical_identifiers("observation_policy_targets", self.target_ids)
        _sha256("observation_policy_producer_registry", self.producer_registry_sha256)
        # CRITICAL: the policy binds the server-owned registry; callers cannot extend trust.
        if self.producer_registry_sha256 != TRUSTED_OBSERVATION_PRODUCER_REGISTRY_SHA256:
            raise ValueError("observation_policy_producer_registry_invalid")
        for name in (
            "lifecycle_epoch",
            "policy_revocation_epoch",
            "roe_revocation_epoch",
            "kill_switch_epoch",
        ):
            _bounded_int(f"observation_policy_{name}", getattr(self, name), 0, 2_147_483_647)
        _bounded_int("observation_policy_max_age", self.max_age_seconds, 1, 86_400)


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedObservationV1:
    schema_version: str
    candidate: ObservationCandidateV1
    source_record_id: str
    source_execution_run_id: str | None
    source_node_id: str | None
    provenance_sha256: str
    promoted_at: datetime
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        # CRITICAL: trusted truth has no public constructor path from planner/model/UI state.
        if _validation_token is not _TRUSTED_OBSERVATION_TOKEN:
            raise ValueError("trusted_observation_promotion_required")
        if self.schema_version != TRUSTED_OBSERVATION_SCHEMA_VERSION:
            raise ValueError("trusted_observation_schema_unsupported")
        if not isinstance(self.candidate, ObservationCandidateV1):
            raise ValueError("trusted_observation_candidate_invalid")
        _identifier("trusted_observation_source_record", self.source_record_id)
        if (self.source_execution_run_id is None) != (self.source_node_id is None):
            raise ValueError("trusted_observation_execution_source_incomplete")
        if self.source_execution_run_id is not None:
            _identifier("trusted_observation_execution_run", self.source_execution_run_id)
            _identifier("trusted_observation_source_node", self.source_node_id)
        _sha256("trusted_observation_provenance", self.provenance_sha256)
        _aware("trusted_observation_promoted_at", self.promoted_at)

    @property
    def observation_sha256(self) -> str:
        return canonical_planning_sha256(self)

    @property
    def fact_id(self) -> str:
        return self.candidate.fact_id

    @property
    def value(self) -> ScalarValueV1:
        return self.candidate.value

    @property
    def fact_key(self) -> str:
        candidate = self.candidate
        return f"{candidate.tenant_id}:{candidate.campaign_id}:{candidate.target_id}:{candidate.fact_id}"


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationPromotionDecisionV1:
    schema_version: str
    candidate_sha256: str
    outcome: ObservationPromotionOutcome
    reason_code: str
    trusted_observation: TrustedObservationV1 | None
    decided_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != OBSERVATION_PROMOTION_SCHEMA_VERSION:
            raise ValueError("observation_promotion_schema_unsupported")
        _sha256("observation_promotion_candidate", self.candidate_sha256)
        if not isinstance(self.outcome, ObservationPromotionOutcome):
            raise ValueError("observation_promotion_outcome_invalid")
        _reason("observation_promotion_reason", self.reason_code)
        _aware("observation_promotion_time", self.decided_at)
        if (self.outcome is ObservationPromotionOutcome.TRUSTED) != isinstance(
            self.trusted_observation, TrustedObservationV1
        ):
            raise ValueError("observation_promotion_trust_binding_invalid")
        if (
            self.trusted_observation is not None
            and self.trusted_observation.candidate.candidate_sha256 != self.candidate_sha256
        ):
            raise ValueError("observation_promotion_candidate_binding_invalid")

    @property
    def decision_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedObservationHistoryV1:
    schema_version: str
    trusted_observations: tuple[TrustedObservationV1, ...]
    conflicted_fact_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != OBSERVATION_HISTORY_SCHEMA_VERSION:
            raise ValueError("observation_history_schema_unsupported")
        if (
            not isinstance(self.trusted_observations, tuple)
            or any(not isinstance(item, TrustedObservationV1) for item in self.trusted_observations)
            or tuple(sorted(self.trusted_observations, key=lambda item: item.observation_sha256))
            != self.trusted_observations
        ):
            raise ValueError("observation_history_items_invalid")
        if tuple(sorted(set(self.conflicted_fact_keys))) != self.conflicted_fact_keys:
            raise ValueError("observation_history_conflicts_invalid")

    @property
    def history_sha256(self) -> str:
        return canonical_planning_sha256(self)


def verify_dag_node_observation_evidence(
    *,
    candidate: ObservationCandidateV1,
    request: DagWorkflowInputV1,
    snapshot: DagExecutionSnapshotV1,
    execution_material: DagExecutionStartMaterialV1,
    domain: PlanningDomainV1,
    revision: AttackPathDagRevisionV1,
    observed: NodeObservedV1,
    effect_receipt: EffectReceiptV1,
    node_id: str,
    verified_at: datetime,
) -> VerifiedObservationEvidenceV1:
    if not isinstance(candidate, ObservationCandidateV1) or not isinstance(
        request, DagWorkflowInputV1
    ) or not isinstance(snapshot, DagExecutionSnapshotV1) or not isinstance(
        execution_material, DagExecutionStartMaterialV1
    ) or not isinstance(domain, PlanningDomainV1) or not isinstance(
        revision, AttackPathDagRevisionV1
    ) or not isinstance(
        observed, NodeObservedV1
    ) or not isinstance(
        effect_receipt, EffectReceiptV1
    ):
        raise ValueError("observation_dag_evidence_input_invalid")
    _identifier("observation_dag_node", node_id)
    _aware("observation_dag_verified_at", verified_at)
    if candidate.producer != DAG_RESULT_PRODUCER_V1:
        raise ValueError("observation_dag_producer_invalid")
    matching_nodes = tuple(node for node in execution_material.nodes if node.node_id == node_id)
    matching_operators = (
        tuple(
            operator
            for operator in domain.operators
            if operator.operator_id == matching_nodes[0].operator_id
        )
        if len(matching_nodes) == 1
        else ()
    )
    if (
        request.tenant_id != candidate.tenant_id
        or request != execution_material.workflow_input
        or execution_material.workflow_request_sha256 != dag_workflow_request_sha256(request)
        or execution_material.tenant_id != candidate.tenant_id
        or execution_material.campaign_id != candidate.campaign_id
        or execution_material.engagement_id != candidate.engagement_id
        or execution_material.authority_sha256 != candidate.authority_sha256
        or execution_material.lifecycle_epoch != candidate.lifecycle_epoch
        or execution_material.policy_revocation_epoch != candidate.policy_revocation_epoch
        or execution_material.roe_revocation_epoch != candidate.roe_revocation_epoch
        or execution_material.kill_switch_epoch != candidate.kill_switch_epoch
        or execution_material.domain_sha256 != domain.domain_sha256
        or execution_material.plan_sha256 != revision.candidate_plan.plan_sha256
        or revision.domain_sha256 != domain.domain_sha256
        or len(matching_nodes) != 1
        or matching_nodes[0].target_id != candidate.target_id
        or len(matching_operators) != 1
        or matching_operators[0].capability.capability_id != matching_nodes[0].capability_id
        or snapshot.execution_run_id != request.execution_run_id
        or snapshot.workflow_request_sha256 != dag_workflow_request_sha256(request)
        or snapshot.current_node_id != node_id
    ):
        raise ValueError("observation_dag_scope_binding_mismatch")
    current_node_state = snapshot.current_node_state
    if current_node_state not in {DagNodeState.CONFIRMED, DagNodeState.NOT_APPLIED}:
        raise ValueError("observation_dag_node_not_terminal")
    assert current_node_state is not None
    terminal_node_state = DagNodeState(current_node_state)
    if (
        observed.effect_state != terminal_node_state.value
        or observed.effect_receipt_sha256 != effect_receipt.receipt_sha256
        or not observed.evidence_complete
        or not observed.reconciliation_complete
        or observed.receipt_state is not effect_receipt.reconciliation_state
        or effect_receipt.reconciliation_state
        not in {ReconciliationState.CONFIRMED, ReconciliationState.NOT_APPLIED}
    ):
        raise ValueError("observation_dag_confirmed_receipt_required")
    applied_assignments = {item.fact_id: item.value for item in matching_operators[0].effects}
    if effect_receipt.reconciliation_state is ReconciliationState.CONFIRMED:
        projected = applied_assignments
    else:
        initial = {
            item.fact_id: item.value
            for item in revision.candidate_plan.initial_state.values
            if item.value is not None
        }
        projected = {
            fact_id: initial[fact_id]
            for fact_id in applied_assignments
            if fact_id in initial
        }
    if candidate.fact_id not in projected or candidate.value != projected[candidate.fact_id]:
        raise ValueError("observation_dag_fact_projection_mismatch")
    if (
        effect_receipt.receipt_sha256 != candidate.source_result_sha256
        or effect_receipt.receipt_sha256 != candidate.evidence_sha256
    ):
        raise ValueError("observation_dag_result_binding_mismatch")
    if not candidate.received_at <= verified_at < candidate.expires_at:
        raise ValueError("observation_dag_evidence_time_invalid")
    verification_sha256 = canonical_planning_sha256(
        (
            candidate.candidate_sha256,
            request,
            snapshot,
            execution_material.workflow_request_sha256,
            matching_nodes[0].node_sha256,
            node_id,
            observed.observed_sha256,
            effect_receipt.receipt_sha256,
            candidate.fact_id,
            candidate.value,
            verified_at,
        )
    )
    return VerifiedObservationEvidenceV1(
        observation_sha256=candidate.candidate_sha256,
        producer=candidate.producer,
        source_record_id=effect_receipt.effect_id,
        source_execution_run_id=execution_material.execution_run_id,
        source_node_id=node_id,
        fact_id=candidate.fact_id,
        value=projected[candidate.fact_id],
        source_result_sha256=effect_receipt.receipt_sha256,
        evidence_sha256=effect_receipt.receipt_sha256,
        verification_sha256=verification_sha256,
        verified_at=verified_at,
        _validation_token=_VERIFIED_EVIDENCE_TOKEN,
    )


def verify_completed_owned_node_observation_evidence(
    *, candidate: ObservationCandidateV1, source: OwnedCompletionSourceV1,
    domain: PlanningDomainV1, revision: AttackPathDagRevisionV1, verified_at: datetime,
) -> VerifiedObservationEvidenceV1:
    if (not isinstance(candidate, ObservationCandidateV1) or not isinstance(source, OwnedCompletionSourceV1)
            or not isinstance(domain, PlanningDomainV1) or not isinstance(revision, AttackPathDagRevisionV1)):
        raise ValueError("owned_completion_observation_input_invalid")
    _aware("owned_completion_observation_time", verified_at)
    if source.verified_at > verified_at or not candidate.received_at <= verified_at < candidate.expires_at:
        raise ValueError("owned_completion_observation_time_invalid")
    if candidate.producer != DAG_RESULT_PRODUCER_V1:
        raise ValueError("owned_completion_producer_invalid")
    for name in ("tenant_id", "campaign_id", "engagement_id", "target_id", "authority_sha256",
                 "lifecycle_epoch", "policy_revocation_epoch", "roe_revocation_epoch", "kill_switch_epoch"):
        if getattr(candidate, name) != getattr(source, name):
            raise ValueError("owned_completion_scope_binding_mismatch")
    nodes = tuple(n for n in revision.candidate_plan.nodes if n.node_id == source.node_id)
    operators = tuple(o for o in domain.operators if len(nodes) == 1 and o.operator_id == nodes[0].operator_id)
    if (revision.revision_sha256 != source.parent_revision_sha256
            or revision.candidate_plan.plan_sha256 != source.plan_sha256
            or revision.domain_sha256 != domain.domain_sha256 or domain.domain_sha256 != source.domain_sha256
            or revision.tenant_id != source.tenant_id or revision.engagement_id != source.engagement_id
            or revision.authority_sha256 != source.authority_sha256 or len(nodes) != 1 or len(operators) != 1
            or nodes[0].target_id != source.target_id or operators[0].capability != source.capability):
        raise ValueError("owned_completion_parent_node_binding_mismatch")
    fact = OWNED_COMPLETION_FACTS[source.capability.capability_id]
    # CRITICAL: actual certified-profile completion is the only fact here; planned security/finding effects are not observations.
    if (candidate.fact_id != fact or candidate.value.value_type is not ScalarType.BOOLEAN
            or candidate.value.value is not True or candidate.observed_at != source.effect_receipt.completed_at
            or candidate.source_result_sha256 != source.effect_receipt.receipt_sha256
            or candidate.evidence_sha256 != source.effect_receipt.receipt_sha256):
        raise ValueError("owned_completion_fact_or_receipt_binding_mismatch")
    verification_sha256 = canonical_planning_sha256(
        ("redagent.owned-completion-observation/v1", candidate.candidate_sha256, source.provenance_sha256, verified_at)
    )
    return VerifiedObservationEvidenceV1(
        observation_sha256=candidate.candidate_sha256, producer=candidate.producer,
        source_record_id=source.effect_receipt.effect_id,
        source_execution_run_id=source.snapshot.execution_run_id, source_node_id=source.node_id,
        fact_id=fact, value=candidate.value, source_result_sha256=source.effect_receipt.receipt_sha256,
        evidence_sha256=source.effect_receipt.receipt_sha256, verification_sha256=verification_sha256,
        verified_at=verified_at, _validation_token=_VERIFIED_EVIDENCE_TOKEN,
    )


def verify_detection_correlation_evidence(
    *,
    candidate: ObservationCandidateV1,
    observation: DetectionObservationV1,
    correlation: DetectionCorrelationDispositionV1,
    execution_material: DagExecutionStartMaterialV1,
    domain: PlanningDomainV1,
    verified_at: datetime,
) -> VerifiedObservationEvidenceV1:
    if (
        not isinstance(candidate, ObservationCandidateV1)
        or not isinstance(observation, DetectionObservationV1)
        or not isinstance(correlation, DetectionCorrelationDispositionV1)
        or not isinstance(execution_material, DagExecutionStartMaterialV1)
        or not isinstance(domain, PlanningDomainV1)
    ):
        raise ValueError("observation_detection_evidence_input_invalid")
    _aware("observation_detection_verified_at", verified_at)
    if candidate.producer != DETECTION_CORRELATION_PRODUCER_V1:
        raise ValueError("observation_detection_producer_invalid")
    promotion = observation.promotion
    if (
        observation.disposition is not DetectionDisposition.CONFIRMED
        or promotion is None
        or promotion.kind is not DetectionPromotionKind.DETERMINISTIC_CORRELATION
        or promotion.proof_ref.sha256 != correlation.correlation_sha256
        or not correlation.correlated
    ):
        raise ValueError("observation_detection_correlation_not_confirmed")
    matching_nodes = tuple(
        node
        for node in execution_material.nodes
        if node.target_id == candidate.target_id and node.capability_id == observation.capability_id
    )
    matching_operators = tuple(
        operator
        for operator in domain.operators
        if any(node.operator_id == operator.operator_id for node in matching_nodes)
    )
    if (
        candidate.tenant_id != execution_material.tenant_id
        or candidate.campaign_id != execution_material.campaign_id
        or candidate.engagement_id != execution_material.engagement_id
        or candidate.authority_sha256 != execution_material.authority_sha256
        or candidate.lifecycle_epoch != execution_material.lifecycle_epoch
        or candidate.policy_revocation_epoch != execution_material.policy_revocation_epoch
        or candidate.roe_revocation_epoch != execution_material.roe_revocation_epoch
        or candidate.kill_switch_epoch != execution_material.kill_switch_epoch
        or execution_material.domain_sha256 != domain.domain_sha256
        or len(matching_nodes) != 1
        or len(matching_operators) != 1
        or observation.correlation_key.split(":", 1)[0] != execution_material.execution_run_id
        or candidate.tenant_id != observation.tenant_id
        or candidate.engagement_id != observation.engagement_id
        or observation.tenant_id != correlation.tenant_id
        or observation.engagement_id != correlation.engagement_id
        or observation.correlation_key != correlation.correlation_key
        or observation.attack_technique_id != correlation.attack_technique_id
        or candidate.source_result_sha256 != canonical_sha256(observation)
        or candidate.evidence_sha256 != observation.evidence_ref.sha256
    ):
        raise ValueError("observation_detection_correlation_binding_mismatch")
    definitions = {item.fact_id: item for item in domain.facts}
    fact = definitions.get(candidate.fact_id)
    if (
        candidate.fact_id not in matching_operators[0].observation_fact_ids
        or fact is None
        or fact.value_type is not ScalarType.BOOLEAN
        or candidate.value != ScalarValueV1(ScalarType.BOOLEAN, True)
    ):
        raise ValueError("observation_detection_fact_projection_mismatch")
    if not correlation.evaluated_at <= verified_at < observation.expires_at:
        raise ValueError("observation_detection_correlation_time_invalid")
    verification_sha256 = canonical_planning_sha256(
        (
            candidate.candidate_sha256,
            canonical_sha256(observation),
            correlation.correlation_sha256,
            execution_material.workflow_request_sha256,
            observation.evidence_ref.sha256,
            verified_at,
        )
    )
    return VerifiedObservationEvidenceV1(
        observation_sha256=candidate.candidate_sha256,
        producer=candidate.producer,
        source_record_id=observation.observation_id,
        source_execution_run_id=None,
        source_node_id=None,
        fact_id=candidate.fact_id,
        value=ScalarValueV1(ScalarType.BOOLEAN, True),
        source_result_sha256=candidate.source_result_sha256,
        evidence_sha256=candidate.evidence_sha256,
        verification_sha256=verification_sha256,
        verified_at=verified_at,
        _validation_token=_VERIFIED_EVIDENCE_TOKEN,
    )


def promote_observation(
    candidate: ObservationCandidateV1,
    evidence: VerifiedObservationEvidenceV1,
    policy: ObservationPromotionPolicyV1,
    *,
    now: datetime,
) -> ObservationPromotionDecisionV1:
    if not isinstance(candidate, ObservationCandidateV1):
        raise ValueError("trusted_observation_candidate_required")
    if not isinstance(evidence, VerifiedObservationEvidenceV1) or not isinstance(
        policy, ObservationPromotionPolicyV1
    ):
        raise ValueError("observation_promotion_input_invalid")
    _aware("observation_promotion_now", now)
    outcome = ObservationPromotionOutcome.TRUSTED
    reason = "trusted"
    if (
        evidence.observation_sha256 != candidate.candidate_sha256
        or evidence.producer != candidate.producer
        or evidence.fact_id != candidate.fact_id
        or evidence.value != candidate.value
        or evidence.source_result_sha256 != candidate.source_result_sha256
        or evidence.evidence_sha256 != candidate.evidence_sha256
    ):
        outcome, reason = ObservationPromotionOutcome.PROVENANCE_INVALID, "provenance_invalid"
    elif candidate.producer not in TRUSTED_OBSERVATION_PRODUCERS_V1:
        outcome, reason = ObservationPromotionOutcome.PRODUCER_DENIED, "producer_denied"
    elif (
        candidate.tenant_id != policy.tenant_id
        or candidate.campaign_id != policy.campaign_id
        or candidate.engagement_id != policy.engagement_id
        or candidate.target_id not in policy.target_ids
    ):
        outcome, reason = ObservationPromotionOutcome.SCOPE_MISMATCH, "scope_mismatch"
    elif (
        candidate.authority_sha256 != policy.authority_sha256
        or candidate.lifecycle_epoch != policy.lifecycle_epoch
        or candidate.policy_revocation_epoch != policy.policy_revocation_epoch
        or candidate.roe_revocation_epoch != policy.roe_revocation_epoch
        or candidate.kill_switch_epoch != policy.kill_switch_epoch
    ):
        outcome, reason = ObservationPromotionOutcome.CAMPAIGN_DRIFT, "campaign_drift"
    elif candidate.observed_at > now or candidate.received_at > now or evidence.verified_at > now:
        outcome, reason = ObservationPromotionOutcome.FUTURE, "future_observation"
    elif now >= candidate.expires_at:
        outcome, reason = ObservationPromotionOutcome.EXPIRED, "observation_expired"
    elif now - candidate.observed_at > timedelta(seconds=policy.max_age_seconds):
        outcome, reason = ObservationPromotionOutcome.STALE, "observation_stale"

    trusted: TrustedObservationV1 | None = None
    if outcome is ObservationPromotionOutcome.TRUSTED:
        trusted = TrustedObservationV1(
            schema_version=TRUSTED_OBSERVATION_SCHEMA_VERSION,
            candidate=candidate,
            source_record_id=evidence.source_record_id,
            source_execution_run_id=evidence.source_execution_run_id,
            source_node_id=evidence.source_node_id,
            provenance_sha256=evidence.verification_sha256,
            promoted_at=now,
            _validation_token=_TRUSTED_OBSERVATION_TOKEN,
        )
    return ObservationPromotionDecisionV1(
        schema_version=OBSERVATION_PROMOTION_SCHEMA_VERSION,
        candidate_sha256=candidate.candidate_sha256,
        outcome=outcome,
        reason_code=reason,
        trusted_observation=trusted,
        decided_at=now,
    )


def evaluate_observation_history(
    observations: tuple[TrustedObservationV1, ...],
) -> TrustedObservationHistoryV1:
    if not isinstance(observations, tuple) or any(
        not isinstance(item, TrustedObservationV1) for item in observations
    ):
        raise ValueError("observation_history_input_invalid")
    unique = {item.observation_sha256: item for item in observations}
    by_key: dict[str, list[TrustedObservationV1]] = {}
    for item in unique.values():
        by_key.setdefault(item.fact_key, []).append(item)
    conflicted = tuple(
        sorted(
            key
            for key, items in by_key.items()
            if len({canonical_planning_sha256(item.value) for item in items}) > 1
        )
    )
    accepted = tuple(
        sorted(
            (item for key, items in by_key.items() if key not in conflicted for item in items),
            key=lambda item: item.observation_sha256,
        )
    )
    return TrustedObservationHistoryV1(
        schema_version=OBSERVATION_HISTORY_SCHEMA_VERSION,
        trusted_observations=accepted,
        conflicted_fact_keys=conflicted,
    )


def _producer_key(value: ObservationProducerIdentityV1) -> tuple[str, str, str]:
    return value.kind.value, value.producer_id, value.producer_version


def _canonical_identifiers(name: str, values: tuple[str, ...]) -> None:
    if not isinstance(values, tuple) or not values or tuple(sorted(set(values))) != values:
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value)


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _reason(name: str, value: object) -> None:
    if not isinstance(value, str) or not _REASON.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _bounded_int(name: str, value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")


DAG_RESULT_PRODUCER_V1 = ObservationProducerIdentityV1(
    ObservationProducerKind.DAG_RUNNER_RESULT,
    "campaign-dag-effect-receipt",
    "redagent.r123-effect-receipt-v1",
)
DETECTION_CORRELATION_PRODUCER_V1 = ObservationProducerIdentityV1(
    ObservationProducerKind.DETECTION_CORRELATION,
    "detection-correlation",
    "redagent.detection-correlation-v1",
)
TRUSTED_OBSERVATION_PRODUCERS_V1 = tuple(
    sorted(
        (DAG_RESULT_PRODUCER_V1, DETECTION_CORRELATION_PRODUCER_V1),
        key=_producer_key,
    )
)
TRUSTED_OBSERVATION_PRODUCER_REGISTRY_SHA256 = canonical_planning_sha256(
    TRUSTED_OBSERVATION_PRODUCERS_V1
)
