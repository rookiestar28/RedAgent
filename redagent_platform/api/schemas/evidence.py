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

class EvidenceSyntheticRegisterRequest(StrictModel):
    artifact_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    engagement_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    fixture_kind: Literal["sanitized-log", "sanitized-json"]
    retention_days: int = Field(default=30, ge=1, le=365)

class EvidenceDeriveRequest(StrictModel):
    artifact_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    artifact_class: Literal["report_safe", "export_safe"]
    transform_name: Literal["central-redaction"] = "central-redaction"
    transform_version: Literal["1"] = "1"
    quality_approved: Literal[True]

class EvidenceLegalHoldRequest(StrictModel):
    expected_version: int = Field(ge=1)

class EvidenceArtifactData(StrictModel):
    artifact_id: str
    tenant_id: str
    engagement_id: str
    job_id: str
    producer_id: str
    object_key: str
    object_version_id: str
    content_sha256: str
    provider_checksum: str
    size_bytes: int
    content_type: str
    artifact_class: Literal["raw", "redacted", "report_safe", "export_safe"]
    classification: Literal["public", "internal", "confidential", "restricted"]
    redaction_state: Literal["raw", "redacted", "report_safe", "export_safe"]
    retention_mode: Literal["GOVERNANCE", "COMPLIANCE"]
    retain_until: datetime
    legal_hold: bool
    kms_reference: str
    attestation_hash: str
    policy_reference: str
    quarantine_reason: str | None
    version: int

class EvidenceArtifactDetailData(EvidenceArtifactData):
    source_artifact_id: str | None
    transform_name: str | None
    transform_version: str | None
    transform_config_hash: str | None
    custody_event_count: int
    verification_count: int
    last_verified: bool | None
    last_verified_at: datetime | None

class EvidenceArtifactResponse(StrictModel):
    data: EvidenceArtifactData

class EvidenceArtifactDetailResponse(StrictModel):
    data: EvidenceArtifactDetailData

class EvidenceArtifactMutationMeta(StrictModel):
    replayed: bool

class EvidenceArtifactMutationResponse(StrictModel):
    data: EvidenceArtifactData
    meta: EvidenceArtifactMutationMeta

class EvidenceArtifactListResponse(StrictModel):
    data: list[EvidenceArtifactData]
    page: PageData

class EvidenceVerificationData(StrictModel):
    artifact_id: str
    object_version_id: str
    verified: bool
    reason: str

class EvidenceVerificationResponse(StrictModel):
    data: EvidenceVerificationData

__all__ = (
    "EvidenceSyntheticRegisterRequest",
    "EvidenceDeriveRequest",
    "EvidenceLegalHoldRequest",
    "EvidenceArtifactData",
    "EvidenceArtifactDetailData",
    "EvidenceArtifactResponse",
    "EvidenceArtifactDetailResponse",
    "EvidenceArtifactMutationMeta",
    "EvidenceArtifactMutationResponse",
    "EvidenceArtifactListResponse",
    "EvidenceVerificationData",
    "EvidenceVerificationResponse",
)
