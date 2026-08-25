"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    Literal,
    OPAQUE_ID,
    datetime,
)

from redagent_platform.api.schemas.common import (
    PageData,
    StrictModel,
)

class PolicyReferenceData(StrictModel):
    policy_reference_id: str
    policy_name: str
    policy_version: str

class PolicyPromotionRequest(StrictModel):
    revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class PolicySimulationRequest(StrictModel):
    fixture: Literal["api-job-create", "workflow-job-command", "evidence-write", "secret-lease"]

class PolicyStatusData(StrictModel):
    required_revision: str
    previous_revision: str | None
    promotion_state: str
    required_agents: list[str]
    acknowledged_agents: list[str]
    converged: bool

class PolicyStatusResponse(StrictModel):
    data: PolicyStatusData

class PolicyDecisionData(StrictModel):
    decision_id: str
    bundle_revision: str
    input_hash: str
    boundary: str
    action: str
    subject_id: str
    resource_type: str
    resource_id: str
    allowed: bool
    reason_code: str
    obligations: list[str]
    issued_at: datetime
    valid_until: datetime
    correlation_id: str

class PolicyDecisionListResponse(StrictModel):
    data: list[PolicyDecisionData]
    page: PageData

class PolicyBundleData(StrictModel):
    revision: str
    artifact_sha256: str
    artifact_size: int
    rego_version: int
    signing_key_id: str
    author_user_id: str
    reviewer_user_id: str
    coverage_basis_points: int
    status: str
    version: int
    created_at: datetime

class PolicyBundleListResponse(StrictModel):
    data: list[PolicyBundleData]
    page: PageData

class PolicyPromotionData(StrictModel):
    revision: str
    previous_revision: str | None
    state: str
    required_agents: list[str]
    acknowledged_agents: list[str]
    promoted_at: datetime
    version: int

class PolicyPromotionMeta(StrictModel):
    replayed: bool

class PolicyPromotionResponse(StrictModel):
    data: PolicyPromotionData
    meta: PolicyPromotionMeta

class PolicySimulationData(StrictModel):
    fixture: str
    decision_id: str
    receipt_id: str
    bundle_revision: str
    input_hash: str
    obligations: list[str]

class PolicySimulationResponse(StrictModel):
    data: PolicySimulationData

__all__ = (
    "PolicyReferenceData",
    "PolicyPromotionRequest",
    "PolicySimulationRequest",
    "PolicyStatusData",
    "PolicyStatusResponse",
    "PolicyDecisionData",
    "PolicyDecisionListResponse",
    "PolicyBundleData",
    "PolicyBundleListResponse",
    "PolicyPromotionData",
    "PolicyPromotionMeta",
    "PolicyPromotionResponse",
    "PolicySimulationData",
    "PolicySimulationResponse",
)
