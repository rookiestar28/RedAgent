"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    Literal,
    OPAQUE_ID,
    datetime,
    model_validator,
)

from redagent_platform.api.schemas.common import (
    PageData,
    StrictModel,
)

class ContainmentStopRequest(StrictModel):
    stop_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    scope_kind: Literal["job", "campaign", "capability", "tenant", "global"]
    scope_id: str | None = Field(default=None, min_length=1, max_length=200, pattern=OPAQUE_ID)
    expected_version: int = Field(default=1, ge=1)
    reason: str = Field(min_length=10, max_length=500)

    @model_validator(mode="after")
    def validate_scope(self) -> "ContainmentStopRequest":
        if self.scope_kind == "global" and self.scope_id is not None:
            raise ValueError("global_scope_id_forbidden")
        if self.scope_kind != "global" and self.scope_id is None:
            raise ValueError("containment_scope_id_required")
        return self

class ContainmentApprovalRequest(StrictModel):
    approval_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    request_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    expected_version: int = Field(ge=1)

class ContainmentRecoveryRequest(StrictModel):
    review_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    expected_version: int = Field(ge=1)

class ContainmentPhaseData(StrictModel):
    phase: str
    state: str
    reason_code: str
    duration_ms: int
    occurred_at: datetime

class JobContainmentData(StrictModel):
    job_id: str
    stop_id: str
    control_id: str
    control_state: str
    requested_at: datetime
    ack_deadline: datetime
    action_state: str
    outcome: str | None
    containment_complete: bool
    phases: list[ContainmentPhaseData]
    residual_risk_codes: list[str]
    open_incident_ids: list[str]

class JobContainmentResponse(StrictModel):
    data: JobContainmentData

class ContainmentControlData(StrictModel):
    control_id: str
    stop_id: str
    scope_kind: Literal["job", "campaign", "capability", "tenant", "global"]
    scope_id: str | None
    control_mode: str
    request_hash: str
    initiated_by_user_id: str
    approved_by_user_id: str | None
    control_state: str
    requested_at: datetime
    activated_at: datetime | None
    ack_deadline: datetime
    recovered_at: datetime | None
    version: int

class ContainmentControlResponse(StrictModel):
    data: ContainmentControlData

class ContainmentControlListResponse(StrictModel):
    data: list[ContainmentControlData]
    page: PageData

class QuotaStatusData(StrictModel):
    policy_record_id: str
    policy_id: str
    revision: int
    dimension: str
    extension_name: str | None
    scope_kind: str
    scope_id: str | None
    hard_limit: int
    reserved: int
    consumed: int
    remaining: int
    window_start: datetime | None
    window_end: datetime | None

class QuotaStatusResponse(StrictModel):
    data: list[QuotaStatusData]

__all__ = (
    "ContainmentStopRequest",
    "ContainmentApprovalRequest",
    "ContainmentRecoveryRequest",
    "ContainmentPhaseData",
    "JobContainmentData",
    "JobContainmentResponse",
    "ContainmentControlData",
    "ContainmentControlResponse",
    "ContainmentControlListResponse",
    "QuotaStatusData",
    "QuotaStatusResponse",
)
