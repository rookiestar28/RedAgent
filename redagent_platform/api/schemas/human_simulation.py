"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Any,
    Field,
    Literal,
    OPAQUE_ID,
    datetime,
)

from redagent_platform.api.schemas.common import (
    StrictModel,
)

HumanCampaignIdValue = Literal["r112-sink-email-canary-v1"]

class HumanSimulationCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    campaign_id: HumanCampaignIdValue
    approval_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    reservation_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    delivery_lease_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    stop_switch_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    quota_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r112-synthetic-sink-only"]

class HumanSimulationRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r112-synthetic-sink-only"]

class HumanSimulationStopRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class HumanSimulationCampaignData(StrictModel):
    campaign_id: HumanCampaignIdValue; purpose: str; recipient_class: Literal["synthetic-invalid-owned"]
    sink_id: str; template_sha256: str; canary_id: str; max_deliveries: Literal[1]; rate_per_minute: Literal[1]
    retention_seconds: Literal[300]; consent_required: Literal[True]; suppression_required: Literal[True]
    privacy_review_required: Literal[True]; deletion_required: Literal[True]; human_delivery: Literal[False]
    external_delivery: Literal[False]; raw_submission_retention: Literal[False]; production_qualified: Literal[False]

class HumanSimulationPlanData(StrictModel):
    plan_id: str; campaign_id: HumanCampaignIdValue; approval_id: str; policy_decision_id: str
    roe_revision: str; reservation_id: str; delivery_lease_id: str; stop_switch_id: str
    plan_sha256: str; plan_state: str; expires_at: datetime; version: int = Field(ge=1)

class HumanSimulationRunData(StrictModel):
    run_id: str; plan_id: str; job_id: str; runner_id: str; run_state: str; new_delivery_blocked: bool
    human_delivery_count: Literal[0]; external_delivery_count: Literal[0]; deletion_verified: bool
    failure_code: str | None; version: int = Field(ge=1)

class HumanSimulationApprovalOptionData(StrictModel):
    approval_id: str
    campaign_id: HumanCampaignIdValue
    approval_state: str
    expires_at: datetime

class HumanSimulationRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    registration_state: str
    expires_at: datetime

class HumanSimulationJobOptionData(StrictModel):
    job_id: str
    engagement_id: str
    roe_version_id: str
    status: str
    current_gate: str
    dispatch_blocked: bool
    stop_requested: bool

class HumanSimulationReservationOptionData(StrictModel):
    reservation_id: str
    reserved_amount: int = Field(ge=1)
    consumed_amount: int = Field(ge=0)
    released_amount: int = Field(ge=0)
    remaining_amount: int = Field(ge=0)
    reservation_state: str
    expires_at: datetime

class HumanSimulationDashboardData(StrictModel):
    campaigns: list[HumanSimulationCampaignData]; rosters: list[dict[str, Any]]; suppressions: list[dict[str, Any]]
    privacy_reviews: list[dict[str, Any]]; templates: list[dict[str, Any]]; approvals: list[dict[str, Any]]
    plans: list[HumanSimulationPlanData]; runs: list[HumanSimulationRunData]; deliveries: list[dict[str, Any]]
    events: list[dict[str, Any]]; canaries: list[dict[str, Any]]; stops: list[dict[str, Any]]
    deletions: list[dict[str, Any]]; rehearsals: list[dict[str, Any]]
    approval_options: list[HumanSimulationApprovalOptionData]
    runner_options: list[HumanSimulationRunnerOptionData]
    job_options: list[HumanSimulationJobOptionData]
    reservation_options: list[HumanSimulationReservationOptionData]

class HumanSimulationCampaignListResponse(StrictModel): data: list[HumanSimulationCampaignData]

class HumanSimulationPlanResponse(StrictModel): data: HumanSimulationPlanData

class HumanSimulationRunResponse(StrictModel): data: HumanSimulationRunData

class HumanSimulationDashboardResponse(StrictModel): data: HumanSimulationDashboardData

__all__ = (
    "HumanCampaignIdValue",
    "HumanSimulationCompileRequest",
    "HumanSimulationRunCreateRequest",
    "HumanSimulationStopRequest",
    "HumanSimulationCampaignData",
    "HumanSimulationPlanData",
    "HumanSimulationRunData",
    "HumanSimulationApprovalOptionData",
    "HumanSimulationRunnerOptionData",
    "HumanSimulationJobOptionData",
    "HumanSimulationReservationOptionData",
    "HumanSimulationDashboardData",
    "HumanSimulationCampaignListResponse",
    "HumanSimulationPlanResponse",
    "HumanSimulationRunResponse",
    "HumanSimulationDashboardResponse",
)
