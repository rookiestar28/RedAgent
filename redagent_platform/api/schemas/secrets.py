"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    OPAQUE_ID,
    datetime,
)

from redagent_platform.api.schemas.common import (
    PageData,
    StrictModel,
)

class SecretSyntheticIssueRequest(StrictModel):
    reference_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    lease_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    engagement_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    workload_client_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    ttl_seconds: int = Field(ge=1, le=900)

class SecretRevokeRequest(StrictModel):
    expected_version: int = Field(ge=1)

class SecretReferenceData(StrictModel):
    reference_id: str
    tenant_id: str
    engagement_id: str
    reference_kind: str
    provider_alias: str
    allowed_capabilities: list[str]
    allowed_permissions: list[str]
    expires_at: datetime
    rotation_due_at: datetime
    reference_status: str
    redaction_label: str
    version: int

class SecretLeaseData(StrictModel):
    lease_id: str
    tenant_id: str
    reference_id: str
    engagement_id: str
    job_id: str
    workload_client_id: str
    capability: str
    permission_count: int
    issued_at: datetime
    expires_at: datetime
    renewed_at: datetime | None
    revoked_at: datetime | None
    renewable: bool
    renewal_count: int
    lease_state: str
    policy_reference: str
    roe_version_id: str
    failure_code: str | None
    version: int

class SecretReferenceListResponse(StrictModel):
    data: list[SecretReferenceData]
    page: "PageData"

class SecretLeaseListResponse(StrictModel):
    data: list[SecretLeaseData]
    page: "PageData"

class SecretLeaseResponse(StrictModel):
    data: SecretLeaseData
    meta: dict[str, bool]

__all__ = (
    "SecretSyntheticIssueRequest",
    "SecretRevokeRequest",
    "SecretReferenceData",
    "SecretLeaseData",
    "SecretReferenceListResponse",
    "SecretLeaseListResponse",
    "SecretLeaseResponse",
)
