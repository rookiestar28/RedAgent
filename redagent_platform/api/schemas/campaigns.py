"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    OPAQUE_ID,
    model_validator,
)

from redagent_platform.api.schemas.common import (
    MutationMeta,
    PageData,
    StrictModel,
)

from redagent_platform.api.schemas.jobs import (
    CampaignJobCreateRequest,
)

class CampaignCreateRequest(StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    engagement_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    name: str = Field(min_length=1, max_length=200)
    jobs: list[CampaignJobCreateRequest] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique_job_ids(self) -> "CampaignCreateRequest":
        identifiers = [job.job_id for job in self.jobs]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("campaign_job_ids_must_be_unique")
        return self

class CampaignData(StrictModel):
    campaign_id: str
    tenant_id: str
    engagement_id: str
    roe_version_id: str
    name: str
    status: str
    workflow_id: str
    workflow_run_id: str | None
    orchestration_revision: int
    version: int

class CampaignResponse(StrictModel):
    data: CampaignData

class CampaignMutationResponse(StrictModel):
    data: CampaignData
    meta: MutationMeta

class CampaignListResponse(StrictModel):
    data: list[CampaignData]
    page: PageData

__all__ = (
    "CampaignCreateRequest",
    "CampaignData",
    "CampaignResponse",
    "CampaignMutationResponse",
    "CampaignListResponse",
)
