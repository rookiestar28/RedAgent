"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    Literal,
    OPAQUE_ID,
    datetime,
)

from redagent_platform.api.schemas.common import (
    StrictModel,
)

class WorkbenchDraftCreateRequest(StrictModel):
    draft_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    campaign_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    target_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    tool_fqn: str = Field(min_length=1, max_length=200, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r114-structured-draft"]

class WorkbenchSuccessorRequest(StrictModel):
    successor_draft_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r114-successor-invalidates-approval"]

class WorkbenchReviewRequest(StrictModel):
    decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    expected_proposal_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    decision: Literal["approve_exact", "deny"]
    confirmation: Literal["--confirm-r114-exact-review"]

class McpFreezeRequest(StrictModel):
    expected_inventory_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    confirmation: Literal["--confirm-r114-freeze-and-invalidate"]

class McpRegistrationData(StrictModel):
    registration_id: str; server_id: str; protocol_version: str; transport_kind: str
    inventory_sha256: str; risk_class: str; data_class: str; registration_state: str
    issued_at: datetime; expires_at: datetime; version: int = Field(ge=1)

class McpAttestationData(StrictModel):
    attestation_id: str; registration_id: str; transport_kind: str; identity_sha256: str
    authorization_profile_sha256: str; boundary_controls_sha256: str; transport_enabled: bool
    attestation_state: str; attested_at: datetime; version: int = Field(ge=1)

class McpInventoryData(StrictModel):
    inventory_id: str; registration_id: str; inventory_revision: int = Field(ge=1)
    inventory_sha256: str; protocol_version: str; inventory_state: str; observed_at: datetime
    version: int = Field(ge=1)

class McpInventoryItemData(StrictModel):
    item_id: str; inventory_id: str; item_name: str; item_kind: str; description_sha256: str
    request_schema_sha256: str; result_schema_sha256: str; risk_class: str; data_class: str
    tool_mode: str; item_state: str; version: int = Field(ge=1)

class McpFreezeData(StrictModel):
    freeze_id: str; registration_id: str; reason_code: str; expected_inventory_sha256: str | None
    observed_inventory_sha256: str | None; invalidated_approval_count: int = Field(ge=0)
    freeze_state: str; frozen_at: datetime; version: int = Field(ge=1)

class WorkbenchDraftData(StrictModel):
    draft_id: str; campaign_id: str; draft_revision: int = Field(ge=1); predecessor_draft_id: str | None
    proposal_sha256: str; authority_sha256: str; draft_state: str; created_by: str
    expires_at: datetime; version: int = Field(ge=1)

class WorkbenchTrustItemData(StrictModel):
    draft_id: str; item_id: str; trust_lane: str; summary_sha256: str; provenance_sha256: str
    item_state: str; version: int = Field(ge=1)

class WorkbenchDisclosureData(StrictModel):
    disclosure_id: str; draft_id: str; sanitized_fields_sha256: str; target_scope_sha256: str
    access_class: str; egress_class: str; side_effects_sha256: str; budget_sha256: str
    disclosure_state: str; version: int = Field(ge=1)

class WorkbenchDecisionData(StrictModel):
    decision_id: str; draft_id: str; decision_kind: str; proposal_sha256: str; actor_id: str
    rationale_sha256: str; decision_state: str; decided_at: datetime; version: int = Field(ge=1)

class WorkbenchLifecycleData(StrictModel):
    event_id: str; draft_id: str; event_kind: str; from_state: str; to_state: str
    event_sha256: str; occurred_at: datetime; version: int = Field(ge=1)

class WorkbenchDraftBindingData(StrictModel):
    binding_id: str; campaign_id: str; campaign_label: str; plan_id: str; plan_label: str
    successor_plan_id: str; successor_plan_label: str; target_id: str; target_label: str
    tool_fqn: str; binding_state: str; fixture_only: bool; egress_class: str

class WorkbenchDashboardData(StrictModel):
    binding_options: list[WorkbenchDraftBindingData]
    registrations: list[McpRegistrationData]; attestations: list[McpAttestationData]
    inventories: list[McpInventoryData]; items: list[McpInventoryItemData]; freezes: list[McpFreezeData]
    drafts: list[WorkbenchDraftData]; trust_items: list[WorkbenchTrustItemData]
    disclosures: list[WorkbenchDisclosureData]; decisions: list[WorkbenchDecisionData]
    lifecycle: list[WorkbenchLifecycleData]

class WorkbenchDraftMutationData(StrictModel):
    draft_id: str; draft_state: str; proposal_sha256: str; version: int = Field(ge=1)
    predecessor_draft_id: str | None = None; approval_invalidated: bool = False

class WorkbenchReviewData(StrictModel):
    draft_id: str; decision_id: str; decision: str; proposal_sha256: str; draft_state: str
    version: int = Field(ge=1)

class McpFreezeMutationData(StrictModel):
    registration_id: str; expected_inventory_sha256: str | None; freeze_state: str
    invalidated_approval_count: int = Field(ge=0); version: int = Field(ge=1)

class WorkbenchDashboardResponse(StrictModel): data: WorkbenchDashboardData

class WorkbenchDraftMutationResponse(StrictModel): data: WorkbenchDraftMutationData

class WorkbenchReviewResponse(StrictModel): data: WorkbenchReviewData

class McpFreezeResponse(StrictModel): data: McpFreezeMutationData

__all__ = (
    "WorkbenchDraftCreateRequest",
    "WorkbenchSuccessorRequest",
    "WorkbenchReviewRequest",
    "McpFreezeRequest",
    "McpRegistrationData",
    "McpAttestationData",
    "McpInventoryData",
    "McpInventoryItemData",
    "McpFreezeData",
    "WorkbenchDraftData",
    "WorkbenchTrustItemData",
    "WorkbenchDisclosureData",
    "WorkbenchDecisionData",
    "WorkbenchLifecycleData",
    "WorkbenchDraftBindingData",
    "WorkbenchDashboardData",
    "WorkbenchDraftMutationData",
    "WorkbenchReviewData",
    "McpFreezeMutationData",
    "WorkbenchDashboardResponse",
    "WorkbenchDraftMutationResponse",
    "WorkbenchReviewResponse",
    "McpFreezeResponse",
)
