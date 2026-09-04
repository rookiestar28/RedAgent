"""Admission-bound construction of durable campaign DAG execution state."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Generic, Protocol, TypeVar

from redagent_platform.campaign_service.admission_contracts import (
    AdmissionOutcome,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.dag_execution import (
    DagFrontierOutcome,
    derive_dag_frontier,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionMode,
    DagNodeState,
    DagRunState,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
    deterministic_dag_workflow_id,
)
from redagent_platform.campaign_service.planning.contracts import (
    PlanValidationCertificateV1,
    PlanningDomainV1,
    ValidationResult,
    canonical_planning_bytes,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search_contracts import (
    AttackPathDagRevisionV1,
)
from redagent_platform.campaign_service.registry import closed_execution_registry


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DAG_CAPABILITY_KEYS = frozenset(
    {"zap-controlled-runtime@2", "nuclei-trusted-runtime@2"}
)


@dataclass(frozen=True, slots=True, kw_only=True)
class DagExecutionStartRequestV1:
    tenant_id: str
    principal_id: str
    campaign_id: str
    engagement_id: str
    execution_id: str
    idempotency_key: str
    revision: AttackPathDagRevisionV1
    domain: PlanningDomainV1
    certificate: PlanValidationCertificateV1
    admission_receipt: PlanAdmissionReceiptV1
    max_activity_attempts: int
    max_transitions: int

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "principal_id",
            "campaign_id",
            "engagement_id",
            "execution_id",
            "idempotency_key",
        ):
            _identifier(f"dag_start_{name}", getattr(self, name))
        if not isinstance(self.revision, AttackPathDagRevisionV1):
            raise ValueError("dag_start_revision_invalid")
        if not isinstance(self.domain, PlanningDomainV1):
            raise ValueError("dag_start_domain_invalid")
        if not isinstance(self.certificate, PlanValidationCertificateV1):
            raise ValueError("dag_start_certificate_invalid")
        if not isinstance(self.admission_receipt, PlanAdmissionReceiptV1):
            raise ValueError("dag_start_admission_invalid")
        _bounded("dag_start_activity_attempts", self.max_activity_attempts, 1, 5)
        _bounded("dag_start_transitions", self.max_transitions, 1, 10_000)


@dataclass(frozen=True, slots=True, kw_only=True)
class DagExecutionNodeMaterialV1:
    node_id: str
    node_order: int
    operator_id: str
    capability_id: str
    capability_revision: str
    target_id: str
    environment: str
    arguments_sha256: str
    incoming_edges_sha256: str
    join_sha256: str
    node_sha256: str
    node_state: DagNodeState

    def __post_init__(self) -> None:
        for name in (
            "node_id",
            "operator_id",
            "capability_id",
            "capability_revision",
            "target_id",
            "environment",
        ):
            _identifier(f"dag_node_{name}", getattr(self, name))
        _bounded("dag_node_order", self.node_order, 0, 2_147_483_647)
        for name in (
            "arguments_sha256",
            "incoming_edges_sha256",
            "join_sha256",
            "node_sha256",
        ):
            _digest(f"dag_node_{name}", getattr(self, name))
        if not isinstance(self.node_state, DagNodeState):
            raise ValueError("dag_node_state_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class DagExecutionStartMaterialV1:
    execution_run_id: str
    execution_id: str
    tenant_id: str
    principal_id: str
    campaign_id: str
    engagement_id: str
    admission_receipt_id: str
    reservation_id: str
    workflow_id: str
    idempotency_key: str
    workflow_request_sha256: str
    input_sha256: str
    input_payload: dict[str, object]
    signed_authority_sha256: str
    authority_sha256: str
    domain_sha256: str
    plan_sha256: str
    certificate_sha256: str
    admission_receipt_sha256: str
    reserved_budget_sha256: str
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    run_state: DagRunState
    max_transitions: int
    workflow_input: DagWorkflowInputV1
    nodes: tuple[DagExecutionNodeMaterialV1, ...]
    outbox_event_type: str
    outbox_payload: dict[str, object]

    def __post_init__(self) -> None:
        for name in (
            "execution_run_id",
            "execution_id",
            "tenant_id",
            "principal_id",
            "campaign_id",
            "engagement_id",
            "admission_receipt_id",
            "reservation_id",
            "workflow_id",
            "idempotency_key",
            "outbox_event_type",
        ):
            _identifier(f"dag_material_{name}", getattr(self, name))
        for name in (
            "workflow_request_sha256",
            "input_sha256",
            "signed_authority_sha256",
            "authority_sha256",
            "domain_sha256",
            "plan_sha256",
            "certificate_sha256",
            "admission_receipt_sha256",
            "reserved_budget_sha256",
        ):
            _digest(f"dag_material_{name}", getattr(self, name))
        if not isinstance(self.input_payload, dict) or not isinstance(
            self.outbox_payload, dict
        ):
            raise ValueError("dag_material_payload_invalid")
        if canonical_planning_sha256(self.input_payload) != self.input_sha256:
            raise ValueError("dag_material_input_digest_mismatch")
        if not isinstance(self.run_state, DagRunState):
            raise ValueError("dag_material_run_state_invalid")
        _bounded("dag_material_transitions", self.max_transitions, 1, 10_000)
        for name in (
            "lifecycle_epoch",
            "policy_revocation_epoch",
            "roe_revocation_epoch",
            "kill_switch_epoch",
        ):
            _bounded(f"dag_material_{name}", getattr(self, name), 0, 2_147_483_647)
        if (
            not isinstance(self.workflow_input, DagWorkflowInputV1)
            or dag_workflow_request_sha256(self.workflow_input)
            != self.workflow_request_sha256
            or self.workflow_input.execution_run_id != self.execution_run_id
            or self.workflow_input.input_sha256 != self.input_sha256
            or self.workflow_input.plan_sha256 != self.plan_sha256
        ):
            raise ValueError("dag_material_workflow_binding_mismatch")
        if not self.nodes or any(
            not isinstance(item, DagExecutionNodeMaterialV1) for item in self.nodes
        ):
            raise ValueError("dag_material_nodes_invalid")
        if tuple(item.node_order for item in self.nodes) != tuple(range(len(self.nodes))):
            raise ValueError("dag_material_node_order_invalid")
        if self.outbox_event_type != "campaign.dag.start.requested.v1":
            raise ValueError("dag_material_outbox_type_invalid")


_DagExecutionStartResult_co = TypeVar("_DagExecutionStartResult_co", covariant=True)
_DagExecutionStartResult = TypeVar("_DagExecutionStartResult")


class DagExecutionStartStore(Protocol[_DagExecutionStartResult_co]):
    async def start(
        self, material: DagExecutionStartMaterialV1, *, now: datetime
    ) -> _DagExecutionStartResult_co: ...


class DagExecutionStartService(Generic[_DagExecutionStartResult]):
    def __init__(
        self,
        mode: DagExecutionMode,
        store: DagExecutionStartStore[_DagExecutionStartResult],
    ) -> None:
        if not isinstance(mode, DagExecutionMode):
            raise ValueError("dag_execution_mode_invalid")
        self._mode = mode
        self._store = store

    async def start(
        self, request: DagExecutionStartRequestV1, *, now: datetime
    ) -> _DagExecutionStartResult:
        if self._mode is DagExecutionMode.DISABLED:
            raise RuntimeError("dag_execution_disabled")
        if not isinstance(request, DagExecutionStartRequestV1):
            raise ValueError("dag_start_request_invalid")
        _aware("dag_start_now", now)
        receipt = request.admission_receipt
        revision = request.revision
        plan = revision.candidate_plan
        certificate = request.certificate
        domain = request.domain
        if (
            receipt.tenant_id != request.tenant_id
            or receipt.campaign_id != request.campaign_id
            or receipt.engagement_id != request.engagement_id
            or revision.tenant_id != request.tenant_id
            or revision.engagement_id != request.engagement_id
            or plan.tenant_id != request.tenant_id
            or plan.engagement_id != request.engagement_id
            or certificate.tenant_id != request.tenant_id
            or certificate.engagement_id != request.engagement_id
        ):
            raise ValueError("dag_start_admission_binding_mismatch")
        if receipt.outcome is not AdmissionOutcome.ADMITTED:
            raise ValueError("dag_start_admission_denied")
        if not receipt.issued_at <= now < receipt.expires_at:
            raise ValueError("dag_start_admission_expired")
        if receipt.reservation_id is None or receipt.reserved_budget is None:
            raise ValueError("dag_start_reservation_missing")
        if certificate.result is not ValidationResult.VALID:
            raise ValueError("dag_start_certificate_denied")
        if certificate.validated_at > receipt.issued_at:
            raise ValueError("dag_start_certificate_after_admission")
        if (
            revision.authority_sha256 != receipt.authority_sha256
            or plan.authority_sha256 != receipt.authority_sha256
            or certificate.authority_sha256 != receipt.authority_sha256
            or revision.domain_sha256 != domain.domain_sha256
            or plan.domain_sha256 != domain.domain_sha256
            or certificate.domain_sha256 != domain.domain_sha256
            or receipt.domain_sha256 != domain.domain_sha256
            or certificate.plan_sha256 != plan.plan_sha256
            or receipt.plan_sha256 != plan.plan_sha256
            or receipt.certificate_sha256 != certificate.certificate_sha256
            or receipt.validator_version != certificate.validator_version
            or receipt.validator_sha256 != certificate.validator_sha256
        ):
            raise ValueError("dag_start_admission_digest_mismatch")
        frontier = derive_dag_frontier(revision, domain, ())
        if frontier.outcome is not DagFrontierOutcome.READY:
            raise ValueError("dag_start_frontier_not_ready")

        operators = {item.operator_id: item for item in domain.operators}
        nodes: list[DagExecutionNodeMaterialV1] = []
        for expected_order, node in enumerate(plan.nodes):
            if node.order != expected_order:
                raise ValueError("dag_start_node_order_invalid")
            operator = operators.get(node.operator_id)
            if operator is None or not operator.executable:
                raise ValueError("dag_start_operator_not_executable")
            capability = operator.capability
            capability_key = f"{capability.capability_id}@{capability.capability_revision}"
            if capability_key not in _DAG_CAPABILITY_KEYS:
                raise ValueError("dag_start_capability_not_closed")
            closed = closed_execution_registry().get(capability_key)
            if closed is None or (
                capability.adapter_id != closed.adapter_id
                or capability.adapter_version != closed.adapter_version
                or capability.profile_id != closed.profile_id
                or capability.profile_revision != closed.profile_revision
                or capability.profile_sha256 != closed.profile_sha256
                or capability.bundle_id != closed.bundle_id
                or capability.bundle_revision != closed.bundle_revision
                or capability.bundle_sha256 != closed.bundle_sha256
                or node.environment not in operator.supported_environments
            ):
                raise ValueError("dag_start_capability_binding_mismatch")
            incoming = tuple(
                edge for edge in plan.edges if edge.target_node_id == node.node_id
            )
            nodes.append(
                DagExecutionNodeMaterialV1(
                    node_id=node.node_id,
                    node_order=node.order,
                    operator_id=node.operator_id,
                    capability_id=capability.capability_id,
                    capability_revision=str(capability.capability_revision),
                    target_id=node.target_id,
                    environment=node.environment.value,
                    arguments_sha256=canonical_planning_sha256(node.arguments),
                    incoming_edges_sha256=canonical_planning_sha256(incoming),
                    join_sha256=canonical_planning_sha256(
                        {"join_policy": node.join_policy.value}
                    ),
                    node_sha256=canonical_planning_sha256(node),
                    node_state=DagNodeState.PENDING,
                )
            )

        input_payload = json.loads(
            canonical_planning_bytes(
                {
                    "schema_version": DAG_EXECUTION_SCHEMA_VERSION,
                    "execution_id": request.execution_id,
                    "principal_id": request.principal_id,
                    "revision": revision,
                    "domain": domain,
                    "certificate": certificate,
                    "admission_receipt": receipt,
                }
            )
        )
        input_sha256 = canonical_planning_sha256(input_payload)
        stable = hashlib.sha256(
            (
                f"campaign-dag-run-v1\0{request.tenant_id}\0{request.campaign_id}\0"
                f"{receipt.receipt_id}\0{request.execution_id}"
            ).encode("utf-8")
        ).hexdigest()[:40]
        execution_run_id = f"dag-{stable}"
        workflow_id = deterministic_dag_workflow_id(
            request.tenant_id, execution_run_id
        )
        workflow_input = DagWorkflowInputV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            tenant_id=request.tenant_id,
            execution_run_id=execution_run_id,
            input_sha256=input_sha256,
            plan_sha256=plan.plan_sha256,
            max_activity_attempts=request.max_activity_attempts,
            max_transitions=request.max_transitions,
        )
        workflow_request_sha256 = dag_workflow_request_sha256(workflow_input)
        material = DagExecutionStartMaterialV1(
            execution_run_id=execution_run_id,
            execution_id=request.execution_id,
            tenant_id=request.tenant_id,
            principal_id=request.principal_id,
            campaign_id=request.campaign_id,
            engagement_id=request.engagement_id,
            admission_receipt_id=receipt.receipt_id,
            reservation_id=receipt.reservation_id,
            workflow_id=workflow_id,
            idempotency_key=request.idempotency_key,
            workflow_request_sha256=workflow_request_sha256,
            input_sha256=input_sha256,
            input_payload=input_payload,
            signed_authority_sha256=receipt.signed_authority_sha256,
            authority_sha256=receipt.authority_sha256,
            domain_sha256=receipt.domain_sha256,
            plan_sha256=receipt.plan_sha256,
            certificate_sha256=receipt.certificate_sha256,
            admission_receipt_sha256=receipt.receipt_sha256,
            reserved_budget_sha256=receipt.reserved_budget.budget_sha256,
            lifecycle_epoch=receipt.lifecycle_epoch,
            policy_revocation_epoch=receipt.policy_revocation_epoch,
            roe_revocation_epoch=receipt.roe_revocation_epoch,
            kill_switch_epoch=receipt.kill_switch_epoch,
            run_state=DagRunState.START_PENDING,
            max_transitions=request.max_transitions,
            workflow_input=workflow_input,
            nodes=tuple(nodes),
            outbox_event_type="campaign.dag.start.requested.v1",
            outbox_payload=asdict(workflow_input),
        )
        return await self._store.start(material, now=now)


async def prepare_dag_execution_start(
    request: DagExecutionStartRequestV1,
    *,
    now: datetime,
) -> DagExecutionStartMaterialV1:
    """Run accepted DAG validation/materialization without persistence or Workflow start."""

    class _Capture:
        material: DagExecutionStartMaterialV1 | None = None

        async def start(
            self,
            material: DagExecutionStartMaterialV1,
            *,
            now: datetime,
        ) -> DagExecutionStartMaterialV1:
            del now
            self.material = material
            return material

    capture = _Capture()
    prepared = await DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, capture).start(
        request,
        now=now,
    )
    if not isinstance(prepared, DagExecutionStartMaterialV1) or capture.material is not prepared:
        raise RuntimeError("dag_start_preparation_failed")
    return prepared


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _digest(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _bounded(name: str, value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_invalid")
