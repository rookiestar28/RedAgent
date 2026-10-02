"""Closed R172 contracts for safe plan preview and exact human approval."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Protocol

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignApplicationStateV1, AutonomousCampaignMode
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityLifecycleV2,
    SignedCampaignAuthorityEnvelopeV2,
)
from redagent_platform.campaign_service.planning.contracts import (
    CleanupMode,
    PlanValidationCertificateV1,
    PlanningDomainV1,
    ValidationResult,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search_contracts import AttackPathDagRevisionV1


PLAN_STAGE_SCHEMA_VERSION = "redagent.autonomous-campaign-plan-stage/v1"
PLAN_PREVIEW_SCHEMA_VERSION = "redagent.autonomous-campaign-plan-preview/v1"
PLAN_APPROVE_SCHEMA_VERSION = "redagent.autonomous-campaign-plan-approve/v1"
PLAN_DENY_SCHEMA_VERSION = "redagent.autonomous-campaign-plan-deny/v1"
APPROVAL_RECEIPT_SCHEMA_VERSION = "redagent.autonomous-campaign-plan-approval-receipt/v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_POLICY_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_REASON = re.compile(r"^[a-z][a-z0-9_:]{0,149}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AutonomousCampaignApprovalDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignApprovalContextV1:
    """Server-owned current signed authority and lifecycle for one application."""

    tenant_id: str
    campaign_id: str
    signed_authority: SignedCampaignAuthorityEnvelopeV2
    authority_lifecycle: CampaignAuthorityLifecycleV2
    execution_bindings: tuple[CapabilityBindingKeyV1, ...] = ()

    def __post_init__(self) -> None:
        _identifier("approval_context_tenant_id", self.tenant_id, 64)
        _identifier("approval_context_campaign_id", self.campaign_id, 64)
        if not isinstance(self.signed_authority, SignedCampaignAuthorityEnvelopeV2) or not isinstance(
            self.authority_lifecycle, CampaignAuthorityLifecycleV2
        ):
            raise ValueError("approval_context_material_invalid")
        authority = self.signed_authority.authority
        if (
            authority.tenant_id != self.tenant_id
            or self.authority_lifecycle.tenant_id != self.tenant_id
            or self.authority_lifecycle.engagement_id != authority.engagement_id
            or self.authority_lifecycle.authority_sha256 != authority.authority_sha256
        ):
            raise ValueError("approval_context_binding_mismatch")


class AutonomousCampaignApprovalContextProvider(Protocol):
    async def read_current_approval_context(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
    ) -> AutonomousCampaignApprovalContextV1 | None: ...


@dataclass(frozen=True, slots=True)
class AutonomousCampaignPlanApproverV1:
    principal_id: str
    role_id: str

    def __post_init__(self) -> None:
        _identifier("approval_required_principal", self.principal_id, 64)
        _identifier("approval_required_role", self.role_id, 100)


@dataclass(frozen=True, slots=True)
class AutonomousCampaignPlanActionV1:
    node_id: str
    order: int
    operator_id: str
    target_id: str
    capability_id: str
    capability_revision: int
    effect_class: str
    executable: bool
    max_duration_seconds: int
    max_requests: int
    max_rate_per_minute: int
    concurrency_weight: int
    max_retries: int
    max_risk_micropoints: int
    max_cost_microunits: int
    max_evidence_bytes: int
    max_data_bytes: int
    cleanup_mode: CleanupMode

    def __post_init__(self) -> None:
        for name in ("node_id", "operator_id", "target_id", "capability_id", "effect_class"):
            _identifier(f"preview_action_{name}", getattr(self, name), 150)
        for name in (
            "order",
            "capability_revision",
            "max_duration_seconds",
            "max_requests",
            "max_rate_per_minute",
            "concurrency_weight",
            "max_retries",
            "max_risk_micropoints",
            "max_cost_microunits",
            "max_evidence_bytes",
            "max_data_bytes",
        ):
            _integer(f"preview_action_{name}", getattr(self, name), 0)
        if self.capability_revision < 1 or self.concurrency_weight < 1:
            raise ValueError("preview_action_bound_invalid")
        if type(self.executable) is not bool or not isinstance(self.cleanup_mode, CleanupMode):
            raise ValueError("preview_action_contract_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class StageAutonomousCampaignPlanV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    actor_user_id: str
    expected_revision: int
    signed_authority: SignedCampaignAuthorityEnvelopeV2
    authority_lifecycle: CampaignAuthorityLifecycleV2
    domain: PlanningDomainV1
    revision: AttackPathDagRevisionV1
    certificate: PlanValidationCertificateV1
    idempotency_key: str
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_STAGE_SCHEMA_VERSION:
            raise ValueError("plan_stage_schema_unsupported")
        for name, maximum in (
            ("tenant_id", 64),
            ("campaign_id", 64),
            ("actor_user_id", 64),
            ("idempotency_key", 200),
            ("correlation_id", 100),
        ):
            _identifier(f"plan_stage_{name}", getattr(self, name), maximum)
        _integer("plan_stage_expected_revision", self.expected_revision, 1)
        if not isinstance(self.signed_authority, SignedCampaignAuthorityEnvelopeV2):
            raise ValueError("plan_stage_authority_invalid")
        if not isinstance(self.authority_lifecycle, CampaignAuthorityLifecycleV2):
            raise ValueError("plan_stage_lifecycle_invalid")
        if not isinstance(self.domain, PlanningDomainV1) or not isinstance(self.revision, AttackPathDagRevisionV1):
            raise ValueError("plan_stage_planning_material_invalid")
        if not isinstance(self.certificate, PlanValidationCertificateV1):
            raise ValueError("plan_stage_certificate_invalid")
        _aware("plan_stage_occurred_at", self.occurred_at)


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignPlanPreviewV1:
    schema_version: str
    preview_id: str
    tenant_id: str
    campaign_id: str
    engagement_id: str
    application_revision: int
    application_intent_sha256: str
    source_binding_sha256: str
    signed_authority_sha256: str
    authority_sha256: str
    domain_sha256: str
    plan_revision_id: str
    plan_revision_sha256: str
    plan_sha256: str
    objective_id: str
    objective_sha256: str
    target_id: str
    capability_ids: tuple[str, ...]
    capability_set_sha256: str
    effect_classes: tuple[str, ...]
    actions: tuple[AutonomousCampaignPlanActionV1, ...]
    authorized_budget: CampaignBudgetVectorV1
    plan_budget: CampaignBudgetVectorV1
    certificate_sha256: str
    validator_version: str
    validator_sha256: str
    validation_result: ValidationResult
    policy_revision: str
    policy_bundle_sha256: str
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    required_approvers: tuple[AutonomousCampaignPlanApproverV1, ...]
    issued_at: datetime
    expires_at: datetime
    execution_mode: AutonomousCampaignMode = AutonomousCampaignMode.PLAN_ONLY
    execution_bindings: tuple[CapabilityBindingKeyV1, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_PREVIEW_SCHEMA_VERSION:
            raise ValueError("plan_preview_schema_unsupported")
        if not isinstance(self.execution_mode, AutonomousCampaignMode) or self.execution_mode is AutonomousCampaignMode.DISABLED:
            raise ValueError("plan_preview_execution_mode_invalid")
        if not isinstance(self.execution_bindings, tuple) or any(not isinstance(item, CapabilityBindingKeyV1) for item in self.execution_bindings):
            raise ValueError("plan_preview_execution_bindings_invalid")
        for name, maximum in (
            ("preview_id", 64),
            ("tenant_id", 64),
            ("campaign_id", 64),
            ("engagement_id", 64),
            ("plan_revision_id", 150),
            ("objective_id", 150),
            ("target_id", 64),
            ("validator_version", 150),
            ("policy_revision", 150),
        ):
            _identifier(f"plan_preview_{name}", getattr(self, name), maximum)
        _integer("plan_preview_application_revision", self.application_revision, 1)
        for name in (
            "application_intent_sha256",
            "source_binding_sha256",
            "signed_authority_sha256",
            "authority_sha256",
            "domain_sha256",
            "plan_revision_sha256",
            "plan_sha256",
            "objective_sha256",
            "capability_set_sha256",
            "certificate_sha256",
            "validator_sha256",
            "policy_bundle_sha256",
        ):
            _sha256(f"plan_preview_{name}", getattr(self, name))
        _closed_identifiers("plan_preview_capabilities", self.capability_ids)
        _closed_identifiers("plan_preview_effect_classes", self.effect_classes)
        if (
            not isinstance(self.actions, tuple)
            or not self.actions
            or any(not isinstance(item, AutonomousCampaignPlanActionV1) for item in self.actions)
            or tuple(sorted(self.actions, key=lambda item: (item.order, item.node_id))) != self.actions
        ):
            raise ValueError("plan_preview_actions_invalid")
        # CRITICAL: redundant preview summaries must remain derived from the exact ordered actions.
        if (
            tuple(item.order for item in self.actions) != tuple(range(len(self.actions)))
            or len({item.node_id for item in self.actions}) != len(self.actions)
            or any(item.target_id != self.target_id for item in self.actions)
        ):
            raise ValueError("plan_preview_action_binding_invalid")
        expected_capabilities = tuple(sorted({item.capability_id for item in self.actions}))
        expected_effect_classes = tuple(sorted({item.effect_class for item in self.actions}))
        if (
            self.capability_ids != expected_capabilities
            or self.effect_classes != expected_effect_classes
            or self.capability_set_sha256 != canonical_planning_sha256(expected_capabilities)
        ):
            raise ValueError("plan_preview_capability_binding_invalid")
        if not isinstance(self.authorized_budget, CampaignBudgetVectorV1) or not isinstance(
            self.plan_budget, CampaignBudgetVectorV1
        ):
            raise ValueError("plan_preview_budget_invalid")
        if not self.plan_budget.fits_within(self.authorized_budget):
            raise ValueError("plan_preview_budget_exceeded")
        if self.validation_result is not ValidationResult.VALID:
            raise ValueError("plan_preview_validation_not_valid")
        for name in (
            "lifecycle_epoch",
            "policy_revocation_epoch",
            "roe_revocation_epoch",
            "kill_switch_epoch",
        ):
            _integer(f"plan_preview_{name}", getattr(self, name), 0)
        if (
            not isinstance(self.required_approvers, tuple)
            or not self.required_approvers
            or any(not isinstance(item, AutonomousCampaignPlanApproverV1) for item in self.required_approvers)
            or len({(item.principal_id, item.role_id) for item in self.required_approvers})
            != len(self.required_approvers)
            or tuple(sorted(self.required_approvers, key=lambda item: (item.principal_id, item.role_id)))
            != self.required_approvers
        ):
            raise ValueError("plan_preview_approvers_invalid")
        _aware("plan_preview_issued_at", self.issued_at)
        _aware("plan_preview_expires_at", self.expires_at)
        if not self.issued_at < self.expires_at:
            raise ValueError("plan_preview_expired")

    @property
    def preview_sha256(self) -> str:
        payload = asdict(self)
        # CRITICAL: old plan-only approval digests remain valid; auto authority is explicit.
        if self.execution_mode is AutonomousCampaignMode.PLAN_ONLY:
            payload.pop("execution_mode")
            if self.execution_bindings:
                raise ValueError("plan_only_execution_bindings_forbidden")
            payload.pop("execution_bindings")
        return canonical_planning_sha256(payload)

    @property
    def etag(self) -> str:
        return f'"r172-{self.application_revision}-{self.preview_sha256}"'


@dataclass(frozen=True, slots=True, kw_only=True)
class ApproveAutonomousCampaignPlanV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    preview_id: str
    preview_sha256: str
    actor_user_id: str
    actor_permissions: tuple[str, ...]
    policy_reference: str
    expected_revision: int
    idempotency_key: str
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        _decision_command(
            self,
            expected_schema=PLAN_APPROVE_SCHEMA_VERSION,
            schema_error="plan_approve_schema_unsupported",
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class DenyAutonomousCampaignPlanV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    preview_id: str
    preview_sha256: str
    actor_user_id: str
    actor_permissions: tuple[str, ...]
    policy_reference: str
    reason_code: str
    expected_revision: int
    idempotency_key: str
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        _decision_command(
            self,
            expected_schema=PLAN_DENY_SCHEMA_VERSION,
            schema_error="plan_deny_schema_unsupported",
        )
        if not _REASON.fullmatch(self.reason_code):
            raise ValueError("plan_denial_reason_invalid")


def canonical_approval_decision_request_sha256(
    command: ApproveAutonomousCampaignPlanV1 | DenyAutonomousCampaignPlanV1,
) -> str:
    """Return the one semantic request digest shared by receipts, audit, and replay."""
    if not isinstance(command, (ApproveAutonomousCampaignPlanV1, DenyAutonomousCampaignPlanV1)):
        raise ValueError("approval_decision_command_invalid")
    decision = (
        AutonomousCampaignApprovalDecision.APPROVED
        if isinstance(command, ApproveAutonomousCampaignPlanV1)
        else AutonomousCampaignApprovalDecision.DENIED
    )
    reason_code = command.reason_code if isinstance(command, DenyAutonomousCampaignPlanV1) else "approved"
    return canonical_planning_sha256(
        {
            "schema_version": command.schema_version,
            "tenant_id": command.tenant_id,
            "campaign_id": command.campaign_id,
            "preview_id": command.preview_id,
            "preview_sha256": command.preview_sha256,
            "actor_user_id": command.actor_user_id,
            "actor_permissions": command.actor_permissions,
            "policy_reference": command.policy_reference,
            "expected_revision": command.expected_revision,
            "decision": decision.value,
            "reason_code": reason_code,
        }
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignApprovalReceiptV1:
    schema_version: str
    receipt_id: str
    decision: AutonomousCampaignApprovalDecision
    reason_code: str
    tenant_id: str
    campaign_id: str
    engagement_id: str
    application_revision: int
    preview_id: str
    preview_sha256: str
    signed_authority_sha256: str
    authority_sha256: str
    domain_sha256: str
    plan_revision_id: str
    plan_revision_sha256: str
    plan_sha256: str
    certificate_sha256: str
    validator_version: str
    validator_sha256: str
    target_id: str
    capability_set_sha256: str
    authorized_budget_sha256: str
    plan_budget_sha256: str
    policy_revision: str
    policy_bundle_sha256: str
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    approver_user_id: str
    approver_role: str
    permission_set_sha256: str
    policy_reference: str
    idempotency_key: str
    request_sha256: str
    decided_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != APPROVAL_RECEIPT_SCHEMA_VERSION:
            raise ValueError("approval_receipt_schema_unsupported")
        if not isinstance(self.decision, AutonomousCampaignApprovalDecision):
            raise ValueError("approval_receipt_decision_invalid")
        if not _REASON.fullmatch(self.reason_code):
            raise ValueError("approval_receipt_reason_invalid")
        if (self.decision is AutonomousCampaignApprovalDecision.APPROVED) != (self.reason_code == "approved"):
            raise ValueError("approval_receipt_reason_mismatch")
        for name, maximum in (
            ("receipt_id", 64),
            ("tenant_id", 64),
            ("campaign_id", 64),
            ("engagement_id", 64),
            ("preview_id", 64),
            ("plan_revision_id", 150),
            ("validator_version", 150),
            ("target_id", 64),
            ("policy_revision", 150),
            ("approver_user_id", 64),
            ("approver_role", 100),
            ("idempotency_key", 200),
        ):
            _identifier(f"approval_receipt_{name}", getattr(self, name), maximum)
        _policy_reference("approval_receipt_policy_reference", self.policy_reference)
        _integer("approval_receipt_application_revision", self.application_revision, 1)
        for name in (
            "preview_sha256",
            "signed_authority_sha256",
            "authority_sha256",
            "domain_sha256",
            "plan_revision_sha256",
            "plan_sha256",
            "certificate_sha256",
            "validator_sha256",
            "capability_set_sha256",
            "authorized_budget_sha256",
            "plan_budget_sha256",
            "policy_bundle_sha256",
            "permission_set_sha256",
            "request_sha256",
        ):
            _sha256(f"approval_receipt_{name}", getattr(self, name))
        for name in (
            "lifecycle_epoch",
            "policy_revocation_epoch",
            "roe_revocation_epoch",
            "kill_switch_epoch",
        ):
            _integer(f"approval_receipt_{name}", getattr(self, name), 0)
        _aware("approval_receipt_decided_at", self.decided_at)
        _aware("approval_receipt_expires_at", self.expires_at)
        if not self.decided_at < self.expires_at:
            raise ValueError("approval_receipt_expired")

    @property
    def receipt_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True)
class AutonomousCampaignPlanPreviewResultV1:
    application: AutonomousCampaignApplicationStateV1
    preview: AutonomousCampaignPlanPreviewV1
    audit_ids: tuple[str, str]
    event_ids: tuple[str, str]
    replayed: bool

    def __post_init__(self) -> None:
        if self.application.aggregate_revision != self.preview.application_revision:
            raise ValueError("plan_preview_result_revision_mismatch")
        for values, name in ((self.audit_ids, "audit"), (self.event_ids, "event")):
            if not isinstance(values, tuple) or len(values) != 2:
                raise ValueError(f"plan_preview_result_{name}_invalid")
            for value in values:
                _identifier(f"plan_preview_result_{name}", value, 64)
        if type(self.replayed) is not bool:
            raise ValueError("plan_preview_result_replayed_invalid")


@dataclass(frozen=True, slots=True)
class AutonomousCampaignApprovalDecisionResultV1:
    application: AutonomousCampaignApplicationStateV1
    receipt: AutonomousCampaignApprovalReceiptV1
    audit_id: str
    event_id: str
    replayed: bool

    def __post_init__(self) -> None:
        if self.application.aggregate_revision != self.receipt.application_revision:
            raise ValueError("approval_result_revision_mismatch")
        _identifier("approval_result_audit", self.audit_id, 64)
        _identifier("approval_result_event", self.event_id, 64)
        if type(self.replayed) is not bool:
            raise ValueError("approval_result_replayed_invalid")


class AutonomousCampaignApprovalRepository(Protocol):
    async def stage_plan(
        self,
        command: StageAutonomousCampaignPlanV1,
        preview: AutonomousCampaignPlanPreviewV1,
    ) -> AutonomousCampaignPlanPreviewResultV1: ...

    async def read_plan_preview(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
    ) -> AutonomousCampaignPlanPreviewV1 | None: ...

    async def decide_plan(
        self,
        command: ApproveAutonomousCampaignPlanV1 | DenyAutonomousCampaignPlanV1,
        receipt: AutonomousCampaignApprovalReceiptV1,
    ) -> AutonomousCampaignApprovalDecisionResultV1: ...


def _decision_command(value: object, *, expected_schema: str, schema_error: str) -> None:
    if getattr(value, "schema_version", None) != expected_schema:
        raise ValueError(schema_error)
    for name, maximum in (
        ("tenant_id", 64),
        ("campaign_id", 64),
        ("preview_id", 64),
        ("actor_user_id", 64),
        ("idempotency_key", 200),
        ("correlation_id", 100),
    ):
        _identifier(f"approval_{name}", getattr(value, name), maximum)
    _sha256("approval_preview_sha256", getattr(value, "preview_sha256"))
    _policy_reference("approval_policy_reference", getattr(value, "policy_reference"))
    permissions = getattr(value, "actor_permissions")
    _closed_identifiers("approval_permissions", permissions)
    if tuple(sorted(permissions)) != permissions:
        raise ValueError("approval_permissions_not_canonical")
    _integer("approval_expected_revision", getattr(value, "expected_revision"), 1)
    _aware("approval_occurred_at", getattr(value, "occurred_at"))


def _closed_identifiers(name: str, values: tuple[str, ...]) -> None:
    if (
        not isinstance(values, tuple)
        or not values
        or len(values) > 1_024
        or len(set(values)) != len(values)
    ):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value, 200)


def _identifier(name: str, value: object, maximum: int) -> None:
    if not isinstance(value, str) or len(value) > maximum or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _policy_reference(name: str, value: object) -> None:
    if not isinstance(value, str) or not _POLICY_REFERENCE.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _integer(name: str, value: object, minimum: int) -> None:
    if type(value) is not int or not minimum <= value <= 2_147_483_647:
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")
