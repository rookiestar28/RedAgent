"""Closed, zero-effect contracts for the R173 durable admission-start bridge."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Protocol

from redagent_platform.campaign_service.application_contracts import (
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle,
)
from redagent_platform.campaign_service.admission_contracts import (
    AdmissionOutcome,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.approval_contracts import (
    AutonomousCampaignApprovalReceiptV1,
    AutonomousCampaignPlanPreviewV1,
)
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityLifecycleV2,
    SignedCampaignAuthorityEnvelopeV2,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from redagent_platform.campaign_service.planning.contracts import (
    PlanValidationCertificateV1,
    PlanningDomainV1,
)
from redagent_platform.campaign_service.planning.search_contracts import AttackPathDagRevisionV1
from redagent_platform.orchestration.admission_start_contracts import (
    ADMISSION_START_BRIDGE_SCHEMA_VERSION,
    ADMISSION_START_BRIDGE_WORKFLOW_NAME,
    AutonomousCampaignStartBridgeSnapshotV1,
    AutonomousCampaignStartBridgeState,
    AutonomousCampaignStartBridgeWorkflowInputV1,
    admission_start_bridge_request_sha256,
    deterministic_admission_start_bridge_workflow_id,
)


__all__ = (
    "ADMISSION_START_BRIDGE_SCHEMA_VERSION",
    "ADMISSION_START_BRIDGE_WORKFLOW_NAME",
    "ADMISSION_START_BRIDGE_EVENT_TYPE",
    "ADMISSION_START_SCHEMA_VERSION",
    "AutonomousCampaignStartBridgeSnapshotV1",
    "AutonomousCampaignStartBridgeState",
    "AutonomousCampaignStartBridgeWorkflowInputV1",
    "admission_start_bridge_request_sha256",
    "deterministic_admission_start_bridge_workflow_id",
    "AutonomousCampaignAdmissionStartState",
    "ClaimedAutonomousCampaignStartBridgeV1",
    "AutonomousCampaignApprovalBundleV1",
    "AutonomousCampaignAdmissionContextV1",
    "AutonomousCampaignAdmissionContextProvider",
    "AutonomousCampaignAdmissionStartCommandV1",
    "canonical_admission_start_request_sha256",
    "AutonomousCampaignAdmissionStartResultV1",
)


ADMISSION_START_BRIDGE_EVENT_TYPE = "autonomous_campaign.start_bridge.requested.v1"
ADMISSION_START_SCHEMA_VERSION = "redagent.autonomous-campaign-admission-start/v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POLICY_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")


class AutonomousCampaignAdmissionStartState(str, Enum):
    START_PENDING = "start_pending"
    EXECUTION_QUEUED = "execution_queued"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    FAILED_BEFORE_IO = "failed_before_io"


@dataclass(frozen=True, slots=True, kw_only=True)
class ClaimedAutonomousCampaignStartBridgeV1:
    """Tenant-bound relay claim with an explicit query-only recovery mode."""

    event_id: str
    start_id: str
    aggregate_sequence: int
    attempt_count: int
    claim_owner: str
    claim_expires_at: datetime
    payload: dict[str, object]
    reconciliation_only: bool

    def __post_init__(self) -> None:
        _identifier("start_bridge_claim_event_id", self.event_id, 64)
        _identifier("start_bridge_claim_start_id", self.start_id, 64)
        _identifier("start_bridge_claim_owner", self.claim_owner, 100)
        if type(self.aggregate_sequence) is not int or self.aggregate_sequence < 1:
            raise ValueError("start_bridge_claim_sequence_invalid")
        if type(self.attempt_count) is not int or not 1 <= self.attempt_count <= 10:
            raise ValueError("start_bridge_claim_attempt_invalid")
        if (
            not isinstance(self.claim_expires_at, datetime)
            or self.claim_expires_at.tzinfo is None
            or self.claim_expires_at.utcoffset() is None
        ):
            raise ValueError("start_bridge_claim_expiry_timezone_required")
        if not isinstance(self.payload, dict):
            raise ValueError("start_bridge_claim_payload_invalid")
        if type(self.reconciliation_only) is not bool:
            raise ValueError("start_bridge_claim_reconciliation_mode_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignApprovalBundleV1:
    """Authoritative current R172 rows loaded from the application repository."""

    application: AutonomousCampaignApplicationStateV1
    preview: AutonomousCampaignPlanPreviewV1
    approval_receipt: AutonomousCampaignApprovalReceiptV1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.application, AutonomousCampaignApplicationStateV1)
            or not isinstance(self.preview, AutonomousCampaignPlanPreviewV1)
            or not isinstance(self.approval_receipt, AutonomousCampaignApprovalReceiptV1)
        ):
            raise ValueError("admission_approval_bundle_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignAdmissionContextV1:
    """Complete server-owned material needed to recompute R158 admission."""

    tenant_id: str
    campaign_id: str
    signed_authority: SignedCampaignAuthorityEnvelopeV2
    authority_lifecycle: CampaignAuthorityLifecycleV2
    domain: PlanningDomainV1
    revision: AttackPathDagRevisionV1
    certificate: PlanValidationCertificateV1

    def __post_init__(self) -> None:
        _identifier("admission_context_tenant_id", self.tenant_id, 64)
        _identifier("admission_context_campaign_id", self.campaign_id, 64)
        if (
            not isinstance(self.signed_authority, SignedCampaignAuthorityEnvelopeV2)
            or not isinstance(self.authority_lifecycle, CampaignAuthorityLifecycleV2)
            or not isinstance(self.domain, PlanningDomainV1)
            or not isinstance(self.revision, AttackPathDagRevisionV1)
            or not isinstance(self.certificate, PlanValidationCertificateV1)
        ):
            raise ValueError("admission_context_material_invalid")
        authority = self.signed_authority.authority
        if (
            authority.tenant_id != self.tenant_id
            or self.authority_lifecycle.tenant_id != self.tenant_id
            or self.authority_lifecycle.engagement_id != authority.engagement_id
            or self.authority_lifecycle.authority_sha256 != authority.authority_sha256
            or self.revision.tenant_id != self.tenant_id
            or self.revision.engagement_id != authority.engagement_id
            or self.revision.authority_sha256 != authority.authority_sha256
            or self.revision.domain_sha256 != self.domain.domain_sha256
            or self.certificate.tenant_id != self.tenant_id
            or self.certificate.engagement_id != authority.engagement_id
        ):
            raise ValueError("admission_context_binding_mismatch")


class AutonomousCampaignAdmissionContextProvider(Protocol):
    async def read_current_admission_context(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
    ) -> AutonomousCampaignAdmissionContextV1 | None: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignAdmissionStartCommandV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    approval_receipt_id: str
    approval_receipt_sha256: str
    actor_user_id: str
    actor_roles: tuple[str, ...]
    actor_permissions: tuple[str, ...]
    policy_reference: str
    expected_revision: int
    idempotency_key: str
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != ADMISSION_START_SCHEMA_VERSION:
            raise ValueError("admission_start_schema_unsupported")
        for name, maximum in (
            ("tenant_id", 64),
            ("campaign_id", 64),
            ("approval_receipt_id", 64),
            ("actor_user_id", 64),
            ("idempotency_key", 200),
            ("correlation_id", 100),
        ):
            _identifier(f"admission_start_{name}", getattr(self, name), maximum)
        _digest("admission_start_approval_receipt_sha256", self.approval_receipt_sha256)
        _closed_identifiers("admission_start_actor_roles", self.actor_roles, 100)
        _closed_identifiers("admission_start_actor_permissions", self.actor_permissions, 100)
        if not _POLICY_REFERENCE.fullmatch(self.policy_reference):
            raise ValueError("admission_start_policy_reference_invalid")
        if type(self.expected_revision) is not int or not 1 <= self.expected_revision <= 2_147_483_647:
            raise ValueError("admission_start_expected_revision_invalid")
        if (
            not isinstance(self.occurred_at, datetime)
            or self.occurred_at.tzinfo is None
            or self.occurred_at.utcoffset() is None
        ):
            raise ValueError("admission_start_occurred_at_invalid")


def canonical_admission_start_request_sha256(
    command: AutonomousCampaignAdmissionStartCommandV1,
) -> str:
    if not isinstance(command, AutonomousCampaignAdmissionStartCommandV1):
        raise ValueError("admission_start_command_invalid")
    return canonical_planning_sha256(
        {
            "schema_version": command.schema_version,
            "tenant_id": command.tenant_id,
            "campaign_id": command.campaign_id,
            "approval_receipt_id": command.approval_receipt_id,
            "approval_receipt_sha256": command.approval_receipt_sha256,
            "actor_user_id": command.actor_user_id,
            "actor_roles": command.actor_roles,
            "actor_permissions": command.actor_permissions,
            "policy_reference": command.policy_reference,
            "expected_revision": command.expected_revision,
        }
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignAdmissionStartResultV1:
    application: AutonomousCampaignApplicationStateV1
    approval_receipt_id: str
    approval_receipt_sha256: str
    admission_receipt: PlanAdmissionReceiptV1
    execution_run_id: str | None
    workflow_id: str | None
    workflow_run_id: str | None
    workflow_request_sha256: str | None
    input_sha256: str | None
    start_state: AutonomousCampaignAdmissionStartState | None
    start_reason_code: str | None
    audit_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    outbox_event_id: str | None
    replayed: bool

    def __post_init__(self) -> None:
        _identifier("admission_start_result_approval_receipt_id", self.approval_receipt_id, 64)
        _digest(
            "admission_start_result_approval_receipt_sha256",
            self.approval_receipt_sha256,
        )
        if not isinstance(self.application, AutonomousCampaignApplicationStateV1) or not isinstance(
            self.admission_receipt, PlanAdmissionReceiptV1
        ):
            raise ValueError("admission_start_result_material_invalid")
        _closed_identifiers("admission_start_result_audit_ids", self.audit_ids, 64)
        _closed_identifiers("admission_start_result_event_ids", self.event_ids, 64)
        if type(self.replayed) is not bool:
            raise ValueError("admission_start_result_replayed_invalid")
        if self.admission_receipt.outcome is AdmissionOutcome.ADMITTED:
            for name, value, maximum in (
                ("execution_run_id", self.execution_run_id, 64),
                ("workflow_id", self.workflow_id, 100),
                ("outbox_event_id", self.outbox_event_id, 64),
            ):
                _identifier(f"admission_start_result_{name}", value, maximum)
            for name, value in (
                ("workflow_request_sha256", self.workflow_request_sha256),
                ("input_sha256", self.input_sha256),
            ):
                _digest(f"admission_start_result_{name}", value)
            if not isinstance(self.start_state, AutonomousCampaignAdmissionStartState):
                raise ValueError("admission_start_result_state_invalid")
            if self.start_reason_code is not None:
                _identifier(
                    "admission_start_result_start_reason_code",
                    self.start_reason_code,
                    100,
                )
            needs_reason = self.start_state in {
                AutonomousCampaignAdmissionStartState.RECONCILIATION_REQUIRED,
                AutonomousCampaignAdmissionStartState.MANUAL_REVIEW_REQUIRED,
                AutonomousCampaignAdmissionStartState.FAILED_BEFORE_IO,
            }
            if needs_reason != (self.start_reason_code is not None):
                raise ValueError("admission_start_result_reason_state_mismatch")
            if self.workflow_run_id is not None:
                _identifier("admission_start_result_workflow_run_id", self.workflow_run_id, 100)
            if self.application.lifecycle_state not in {
                AutonomousCampaignLifecycle.ADMITTED,
                AutonomousCampaignLifecycle.EXECUTION_QUEUED,
                AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
                AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
                AutonomousCampaignLifecycle.FAILED_CONTAINED,
                AutonomousCampaignLifecycle.DENIED,
                AutonomousCampaignLifecycle.EXPIRED,
                AutonomousCampaignLifecycle.REVOKED,
            }:
                raise ValueError("admission_start_result_application_state_invalid")
        else:
            if any(
                value is not None
                for value in (
                    self.execution_run_id,
                    self.workflow_id,
                    self.workflow_run_id,
                    self.workflow_request_sha256,
                    self.input_sha256,
                    self.start_state,
                    self.start_reason_code,
                    self.outbox_event_id,
                )
            ):
                raise ValueError("admission_start_denial_has_start_material")
            if self.application.lifecycle_state not in {
                AutonomousCampaignLifecycle.DENIED,
                AutonomousCampaignLifecycle.EXPIRED,
                AutonomousCampaignLifecycle.REVOKED,
            }:
                raise ValueError("admission_start_denial_application_state_invalid")

    @property
    def etag(self) -> str:
        return (
            f'"r173-{self.application.aggregate_revision}-'
            f'{self.admission_receipt.receipt_sha256}"'
        )


def _identifier(name: str, value: object, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or not _IDENTIFIER.fullmatch(value)
    ):
        raise ValueError(f"{name}_invalid")


def _digest(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _closed_identifiers(name: str, values: object, maximum: int) -> None:
    if (
        not isinstance(values, tuple)
        or not values
        or tuple(sorted(set(values))) != values
    ):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value, maximum)
