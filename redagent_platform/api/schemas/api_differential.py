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

ApiDifferentialProfileIdValue = Literal["openapi-authorization-differential-v1"]

class ApiDifferentialCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    profile_id: ApiDifferentialProfileIdValue
    target_id: Literal["r106-owned-api-fixture"]
    target_attestation_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    seed: int = Field(ge=0, le=2**63 - 1)

class ApiDifferentialRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)

class ApiDifferentialCancelRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class ApiDifferentialProfileData(StrictModel):
    profile_id: ApiDifferentialProfileIdValue
    profile_revision: int = Field(ge=1)
    engine_version: Literal["4.22.4"]
    artifact_digest: str
    bundle_id: Literal["r106-owned-api-differential"]
    spec_sha256: str
    operation_ids: list[str]
    identity_states: list[str]
    max_requests: int = Field(ge=1)
    request_rate_per_second: int = Field(ge=1)
    concurrency_limit: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    total_data_bytes: int = Field(ge=1)
    profile_state: Literal["certified-local-lab"]
    production_qualified: Literal[False]

class ApiDifferentialPlanData(StrictModel):
    plan_id: str
    profile_id: ApiDifferentialProfileIdValue
    target_id: str
    policy_decision_id: str
    policy_revision: str
    roe_version_id: str
    spec_sha256: str
    plan_sha256: str
    seed: int = Field(ge=0)
    case_count: int = Field(ge=1)
    expires_at: datetime
    version: int = Field(ge=1)

class ApiDifferentialRunData(StrictModel):
    run_id: str
    plan_id: str
    job_id: str
    runner_id: str
    run_state: str
    progress_percent: int = Field(ge=0, le=100)
    request_count: int = Field(ge=0)
    response_bytes: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    reason_code: str
    version: int = Field(ge=1)

class ApiDifferentialObservationData(StrictModel):
    observation_id: str
    case_id: str
    finding_type: str | None
    violated: bool
    evidence_instance_id: str | None
    reason_code: str

class ApiDifferentialReplayData(StrictModel):
    replay_id: str
    case_id: str
    minimized_replay_sha256: str
    semantic_predicate: str
    replay_state: str

class ApiDifferentialCleanupData(StrictModel):
    receipt_id: str
    compensation_complete: bool
    lease_revoked: bool
    residual_resource_count: int = Field(ge=0)
    completed_at: datetime

class ApiDifferentialTargetOptionData(StrictModel):
    target_id: str
    attestation_sha256: str
    attestation_state: str
    non_production: bool
    expires_at: datetime

class ApiDifferentialRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    registration_state: str
    expires_at: datetime

class ApiDifferentialJobOptionData(StrictModel):
    job_id: str
    engagement_id: str
    roe_version_id: str
    status: str
    current_gate: str
    dispatch_blocked: bool
    stop_requested: bool

class ApiDifferentialDashboardData(StrictModel):
    profiles: list[ApiDifferentialProfileData]
    plans: list[ApiDifferentialPlanData]
    runs: list[ApiDifferentialRunData]
    observations: list[ApiDifferentialObservationData]
    replays: list[ApiDifferentialReplayData]
    cleanups: list[ApiDifferentialCleanupData]
    target_options: list[ApiDifferentialTargetOptionData]
    runner_options: list[ApiDifferentialRunnerOptionData]
    job_options: list[ApiDifferentialJobOptionData]

class ApiDifferentialProfileListResponse(StrictModel):
    data: list[ApiDifferentialProfileData]

class ApiDifferentialPlanResponse(StrictModel):
    data: ApiDifferentialPlanData

class ApiDifferentialRunResponse(StrictModel):
    data: ApiDifferentialRunData

class ApiDifferentialDashboardResponse(StrictModel):
    data: ApiDifferentialDashboardData

__all__ = (
    "ApiDifferentialProfileIdValue",
    "ApiDifferentialCompileRequest",
    "ApiDifferentialRunCreateRequest",
    "ApiDifferentialCancelRequest",
    "ApiDifferentialProfileData",
    "ApiDifferentialPlanData",
    "ApiDifferentialRunData",
    "ApiDifferentialObservationData",
    "ApiDifferentialReplayData",
    "ApiDifferentialCleanupData",
    "ApiDifferentialTargetOptionData",
    "ApiDifferentialRunnerOptionData",
    "ApiDifferentialJobOptionData",
    "ApiDifferentialDashboardData",
    "ApiDifferentialProfileListResponse",
    "ApiDifferentialPlanResponse",
    "ApiDifferentialRunResponse",
    "ApiDifferentialDashboardResponse",
)
