"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    datetime,
)

from redagent_platform.api.schemas.common import (
    PageData,
    StrictModel,
)

class RunnerStatusData(StrictModel):
    registration_count: int
    active_registration_count: int
    certified_capability_count: int
    open_manifest_count: int
    active_lease_count: int
    succeeded_execution_count: int
    failed_execution_count: int
    last_heartbeat_at: datetime | None
    policy_revisions: list[str]
    capability_revisions: list[str]
    image_digests: list[str]

class RunnerStatusResponse(StrictModel):
    data: RunnerStatusData

class RunnerRegistrationData(StrictModel):
    runner_id: str
    runner_class_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    generation: int
    registration_state: str
    registered_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    last_seen_at: datetime
    version: int

class RunnerRegistrationListResponse(StrictModel):
    data: list[RunnerRegistrationData]
    page: PageData

class RunnerManifestData(StrictModel):
    manifest_id: str
    job_id: str
    manifest_sha256: str
    capability_id: str
    capability_revision: int
    image_digest: str
    policy_revision: str
    manifest_state: str
    issued_at: datetime
    expires_at: datetime
    version: int

class RunnerManifestListResponse(StrictModel):
    data: list[RunnerManifestData]
    page: PageData

class RunnerExecutionData(StrictModel):
    execution_id: str
    job_id: str
    manifest_sha256: str
    evidence_artifact_id: str | None
    outcome: str
    final_phase: str
    cleanup_completed: bool
    residual_risk: str | None
    completed_at: datetime
    version: int

class RunnerExecutionListResponse(StrictModel):
    data: list[RunnerExecutionData]
    page: PageData

__all__ = (
    "RunnerStatusData",
    "RunnerStatusResponse",
    "RunnerRegistrationData",
    "RunnerRegistrationListResponse",
    "RunnerManifestData",
    "RunnerManifestListResponse",
    "RunnerExecutionData",
    "RunnerExecutionListResponse",
)
