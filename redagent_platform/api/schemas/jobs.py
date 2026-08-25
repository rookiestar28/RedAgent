"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    Literal,
    OPAQUE_ID,
)

from redagent_platform.api.schemas.common import (
    MutationMeta,
    PageData,
    StrictModel,
)

class JobCreateRequest(StrictModel):
    job_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    engagement_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    request: "JobWorkflowSpec"

class JobWorkflowSpec(StrictModel):
    capability: Literal["synthetic-noop", "synthetic-conformance", "zap-controlled-runtime"]
    approval_timeout_seconds: int = Field(default=3600, ge=1, le=604800)
    max_activity_attempts: int = Field(default=3, ge=1, le=5)
    budget_reference: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)

class CampaignJobCreateRequest(StrictModel):
    job_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    request: JobWorkflowSpec

class JobLifecycleCommandRequest(StrictModel):
    command_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    action: Literal["approve", "pause", "resume", "retry", "cancel"]
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class JobEmergencyStopRequest(StrictModel):
    signal_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    reason: str = Field(min_length=10, max_length=500)

class JobTransitionRequest(StrictModel):
    expected_version: int = Field(ge=1)
    next_status: Literal["running", "succeeded", "failed", "cancelled"]

class JobData(StrictModel):
    job_id: str
    tenant_id: str
    engagement_id: str
    roe_version_id: str
    created_by_user_id: str
    campaign_id: str | None
    status: str
    request: JobWorkflowSpec
    policy_reference: str
    workflow_id: str
    workflow_run_id: str | None
    orchestration_state: str
    orchestration_revision: int
    current_gate: str
    failure_code: str | None
    retry_count: int
    dispatch_blocked: bool
    stop_requested: bool
    version: int

class JobResponse(StrictModel):
    data: JobData

class JobMutationResponse(StrictModel):
    data: JobData
    meta: MutationMeta

class JobListResponse(StrictModel):
    data: list[JobData]
    page: PageData

class JobCommandMeta(StrictModel):
    replayed: bool
    command_id: str

class JobCommandResponse(StrictModel):
    data: JobData
    meta: JobCommandMeta

class JobStopData(StrictModel):
    job_id: str
    workflow_id: str
    stop_id: str
    control_id: str
    state: Literal["stop_requested"]
    containment_complete: Literal[False]
    completion_owner: Literal["R101"]

class JobStopResponse(StrictModel):
    data: JobStopData

__all__ = (
    "JobCreateRequest",
    "JobWorkflowSpec",
    "CampaignJobCreateRequest",
    "JobLifecycleCommandRequest",
    "JobEmergencyStopRequest",
    "JobTransitionRequest",
    "JobData",
    "JobResponse",
    "JobMutationResponse",
    "JobListResponse",
    "JobCommandMeta",
    "JobCommandResponse",
    "JobStopData",
    "JobStopResponse",
)
