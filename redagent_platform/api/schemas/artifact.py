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

ArtifactProfileIdValue = Literal[
    "r110-repository-snapshot-v1",
    "r110-packaged-artifact-v1",
    "r110-mobile-static-v1",
]

class ArtifactCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    profile_id: ArtifactProfileIdValue
    artifact_binding_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    reservation_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    artifact_lease_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r110-canonical-fixture"]

class ArtifactRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r110-canonical-fixture"]

class ArtifactCancelRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class ArtifactProfileData(StrictModel):
    profile_id: ArtifactProfileIdValue
    artifact_kind: Literal["repository_snapshot", "packaged_artifact", "mobile_static"]
    stages: list[str]
    max_files: int = Field(ge=1)
    max_bytes: int = Field(ge=1)
    max_depth: int = Field(ge=1)
    max_expansion_ratio: int = Field(ge=1)
    profile_state: Literal["certified-local-lab"]
    zero_execution: Literal[True]
    production_qualified: Literal[False]

class ArtifactPlanData(StrictModel):
    plan_id: str; profile_id: ArtifactProfileIdValue; artifact_binding_id: str
    policy_decision_id: str; reservation_id: str; artifact_lease_id: str
    plan_sha256: str; plan_state: str; expires_at: datetime; version: int = Field(ge=1)

class ArtifactRunData(StrictModel):
    run_id: str; plan_id: str; job_id: str; runner_id: str; run_state: str; complete: bool
    partial_reasons: list[str]; result_sha256: str | None; untrusted_execution_count: int = Field(ge=0); version: int = Field(ge=1)

class ArtifactBindingOptionData(StrictModel):
    binding_id: str
    artifact_kind: Literal["repository_snapshot", "packaged_artifact", "mobile_static"]
    declared_files: int = Field(ge=1)
    declared_bytes: int = Field(ge=1)
    binding_state: str
    expires_at: datetime

class ArtifactRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    registration_state: str
    expires_at: datetime

class ArtifactJobOptionData(StrictModel):
    job_id: str
    engagement_id: str
    roe_version_id: str
    status: str
    current_gate: str
    dispatch_blocked: bool
    stop_requested: bool

class ArtifactReservationOptionData(StrictModel):
    reservation_id: str
    reserved_amount: int = Field(ge=1)
    consumed_amount: int = Field(ge=0)
    released_amount: int = Field(ge=0)
    remaining_amount: int = Field(ge=0)
    reservation_state: str
    expires_at: datetime

class ArtifactDashboardData(StrictModel):
    profiles: list[ArtifactProfileData]; plans: list[ArtifactPlanData]; runs: list[ArtifactRunData]
    components: list[dict[str, Any]]; vulnerabilities: list[dict[str, Any]]
    credential_findings: list[dict[str, Any]]; static_findings: list[dict[str, Any]]
    mobile: list[dict[str, Any]]; cleanups: list[dict[str, Any]]
    binding_options: list[ArtifactBindingOptionData]
    runner_options: list[ArtifactRunnerOptionData]
    job_options: list[ArtifactJobOptionData]
    reservation_options: list[ArtifactReservationOptionData]

class ArtifactProfileListResponse(StrictModel): data: list[ArtifactProfileData]

class ArtifactPlanResponse(StrictModel): data: ArtifactPlanData

class ArtifactRunResponse(StrictModel): data: ArtifactRunData

class ArtifactDashboardResponse(StrictModel): data: ArtifactDashboardData

__all__ = (
    "ArtifactProfileIdValue",
    "ArtifactCompileRequest",
    "ArtifactRunCreateRequest",
    "ArtifactCancelRequest",
    "ArtifactProfileData",
    "ArtifactPlanData",
    "ArtifactRunData",
    "ArtifactBindingOptionData",
    "ArtifactRunnerOptionData",
    "ArtifactJobOptionData",
    "ArtifactReservationOptionData",
    "ArtifactDashboardData",
    "ArtifactProfileListResponse",
    "ArtifactPlanResponse",
    "ArtifactRunResponse",
    "ArtifactDashboardResponse",
)
