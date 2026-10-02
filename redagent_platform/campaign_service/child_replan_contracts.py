"""Closed canonical child inputs and pure, non-authorizing capacity projections."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import re
from types import MappingProxyType
from typing import Any, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from redagent_platform.campaign_service.approval_contracts import AutonomousCampaignPlanPreviewResultV1

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.planning.contracts import (
    FactValueV1, PlanningDomainV1, ScalarType, canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search_contracts import AttackPathDagRevisionV1


CHILD_REQUEST_SCHEMA_VERSION = "redagent.autonomous-campaign-child-request/v1"
CHILD_LINEAGE_SCHEMA_VERSION = "redagent.autonomous-campaign-child-lineage/v1"
CAPACITY_COOLDOWN_SECONDS = 60
OWNED_COMPLETION_FACTS = MappingProxyType({
    "zap-controlled-runtime": "owned.zap.passive.completed",
    "nuclei-trusted-runtime": "owned.nuclei.header.completed",
})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CanonicalChildReplanStore(Protocol):
    async def stage_child(self, command: PrepareAutonomousCampaignChildV1, *, read_context: Any,
                          build_preview: Any, trusted_keys: Any) -> AutonomousCampaignPlanPreviewResultV1: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class PrepareAutonomousCampaignChildV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    actor_user_id: str
    expected_revision: int
    idempotency_key: str
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != CHILD_REQUEST_SCHEMA_VERSION:
            raise ValueError("child_request_schema_unsupported")
        for name, limit in (("tenant_id", 64), ("campaign_id", 64), ("actor_user_id", 64),
                            ("idempotency_key", 200), ("correlation_id", 100)):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) > limit or not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"child_request_{name}_invalid")
        if type(self.expected_revision) is not int or self.expected_revision < 1:
            raise ValueError("child_request_revision_invalid")
        _aware(self.occurred_at)


@dataclass(frozen=True, slots=True, kw_only=True)
class ChildReplanLineageV1:
    schema_version: str
    parent_execution_run_id: str
    parent_revision_sha256: str
    parent_admission_receipt_sha256: str
    observation_history_sha256: str
    proposal_sha256: str
    subset_proof_sha256: str
    settlement_sha256: str
    child_revision_sha256: str
    replan_sequence: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != CHILD_LINEAGE_SCHEMA_VERSION or type(self.replan_sequence) is not int or self.replan_sequence != 1:
            raise ValueError("child_lineage_schema_or_sequence_invalid")
        if not isinstance(self.parent_execution_run_id, str) or not _IDENTIFIER.fullmatch(self.parent_execution_run_id):
            raise ValueError("child_lineage_parent_execution_invalid")
        for name in ("parent_revision_sha256", "parent_admission_receipt_sha256", "observation_history_sha256",
                     "proposal_sha256", "subset_proof_sha256", "settlement_sha256", "child_revision_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ValueError(f"child_lineage_{name}_invalid")

    @property
    def lineage_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class CanonicalChildSubsetProofV1:
    parent_revision_sha256: str
    child_revision_sha256: str
    domain_sha256: str
    observation_history_sha256: str
    removed_parent_node_ids: tuple[str, ...]
    retained_parent_node_ids: tuple[str, ...]
    schema_version: str = "redagent.canonical-child-subset-proof/v1"

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.canonical-child-subset-proof/v1":
            raise ValueError("child_subset_schema_invalid")
        for name in ("parent_revision_sha256", "child_revision_sha256", "domain_sha256", "observation_history_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ValueError("child_subset_digest_invalid")
        for value in (self.removed_parent_node_ids, self.retained_parent_node_ids):
            if not isinstance(value, tuple) or len(value) != 1 or not isinstance(value[0], str) or not _IDENTIFIER.fullmatch(value[0]):
                raise ValueError("child_subset_nodes_invalid")
        if self.removed_parent_node_ids == self.retained_parent_node_ids:
            raise ValueError("child_subset_node_partition_invalid")

    @property
    def proof_sha256(self) -> str:
        return canonical_planning_sha256(self)


def prove_canonical_child_subset(
    *, parent: AttackPathDagRevisionV1, child: AttackPathDagRevisionV1,
    domain: PlanningDomainV1, completed_parent_node_ids: tuple[str, ...],
    observed_values: tuple[FactValueV1, ...], observation_history_sha256: str,
) -> CanonicalChildSubsetProofV1:
    """Prove shape/state narrowing; canonical owner separately proves the observation's physical origin."""
    if (not isinstance(parent, AttackPathDagRevisionV1) or not isinstance(child, AttackPathDagRevisionV1)
            or not isinstance(domain, PlanningDomainV1) or not isinstance(observation_history_sha256, str)
            or not _SHA256.fullmatch(observation_history_sha256)):
        raise ValueError("child_subset_input_invalid")
    if (child.parent_revision_id != parent.revision_id or child.tenant_id != parent.tenant_id
            or child.engagement_id != parent.engagement_id or child.authority_sha256 != parent.authority_sha256
            or child.domain_sha256 != parent.domain_sha256 or domain.domain_sha256 != parent.domain_sha256
            or child.objective_sha256 != parent.objective_sha256):
        raise ValueError("child_subset_parent_binding_mismatch")
    if len(parent.candidate_plan.nodes) != 2 or len(child.candidate_plan.nodes) != 1 or child.width != 1 or child.depth != 1:
        raise ValueError("child_subset_strict_shrink_required")
    if (not isinstance(completed_parent_node_ids, tuple) or len(completed_parent_node_ids) != 1
            or not isinstance(observed_values, tuple) or len(observed_values) != 1):
        raise ValueError("child_subset_completed_source_required")
    parent_nodes = {n.node_id: n for n in parent.candidate_plan.nodes}
    completed_id = completed_parent_node_ids[0]
    if completed_id not in parent_nodes:
        raise ValueError("child_subset_completed_node_unknown")
    operators = {o.operator_id: o for o in domain.operators}
    completed_operator = operators.get(parent_nodes[completed_id].operator_id)
    fact = None if completed_operator is None else OWNED_COMPLETION_FACTS.get(completed_operator.capability.capability_id)
    observed = observed_values[0]
    if (not isinstance(observed, FactValueV1) or observed.fact_id != fact or observed.value is None
            or observed.value.value_type is not ScalarType.BOOLEAN or observed.value.value is not True):
        raise ValueError("child_subset_observation_fact_invalid")
    expected_state = {v.fact_id: v.value for v in parent.candidate_plan.initial_state.values}
    if observed.fact_id not in expected_state:
        raise ValueError("child_subset_observation_fact_unknown")
    expected_state[observed.fact_id] = observed.value
    if {v.fact_id: v.value for v in child.candidate_plan.initial_state.values} != expected_state:
        raise ValueError("child_subset_invented_initial_state")
    child_node = child.candidate_plan.nodes[0]
    remaining = next(n for n in parent.candidate_plan.nodes if n.node_id != completed_id)
    def key(node):
        return node.operator_id, node.target_id, node.environment, node.arguments
    # CRITICAL: a human-envelope subset alone may add authorized work; child work must be the unchanged remaining parent tuple.
    if key(child_node) != key(remaining) or child.candidate_plan.edges:
        raise ValueError("child_subset_expansion_or_reexecution")
    if child.total_cost_microunits > parent.total_cost_microunits or child.total_risk_micropoints > parent.total_risk_micropoints:
        raise ValueError("child_subset_resource_expansion")
    return CanonicalChildSubsetProofV1(
        parent_revision_sha256=parent.revision_sha256, child_revision_sha256=child.revision_sha256,
        domain_sha256=domain.domain_sha256, observation_history_sha256=observation_history_sha256,
        removed_parent_node_ids=(completed_id,), retained_parent_node_ids=(remaining.node_id,),
    )


def project_sequential_child_residual(
    *,
    authorized: CampaignBudgetVectorV1,
    parent_charge: CampaignBudgetVectorV1,
    other_charges: tuple[CampaignBudgetVectorV1, ...],
    parent_completed_at: datetime,
    capacity_available_at: datetime,
    now: datetime,
) -> CampaignBudgetVectorV1:
    """Calculate a vector only; a canonical owner must first validate settlement provenance."""
    if not isinstance(authorized, CampaignBudgetVectorV1) or not isinstance(parent_charge, CampaignBudgetVectorV1):
        raise ValueError("child_capacity_budget_invalid")
    if not isinstance(other_charges, tuple) or any(not isinstance(v, CampaignBudgetVectorV1) for v in other_charges):
        raise ValueError("child_capacity_other_charges_invalid")
    for timestamp in (parent_completed_at, capacity_available_at, now):
        _aware(timestamp)
    if capacity_available_at < parent_completed_at + timedelta(seconds=CAPACITY_COOLDOWN_SECONDS) or now < capacity_available_at:
        raise ValueError("child_capacity_cooldown_not_satisfied")
    # CRITICAL: only settled peak occupancy reopens; refunding cumulative parent work multiplies authority.
    charged = replace(parent_charge, rate_per_minute=0, concurrency=0)
    for charge in other_charges:
        charged = charged.add(charge)
    return authorized.subtract(charged)


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("child_capacity_timezone_required")
