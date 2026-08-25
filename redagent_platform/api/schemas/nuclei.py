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

NucleiProfileIdValue = Literal["nuclei-http-header-v1"]

class NucleiCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    profile_id: NucleiProfileIdValue
    bundle_id: Literal["r105-http-header-bundle"]
    bundle_revision: Literal[2]
    target_id: Literal["r105-owned-http-fixture"]
    target_attestation_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)

class NucleiRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)

class NucleiCancelRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class NucleiProfileData(StrictModel):
    profile_id: NucleiProfileIdValue
    profile_revision: int = Field(ge=1)
    engine_version: str
    image_digest: str
    bundle_id: str
    bundle_revision: int = Field(ge=1)
    profile_sha256: str
    risk_class: str
    allowed_protocols: list[str]
    allowed_methods: list[str]
    allowed_paths: list[str]
    request_limit: int = Field(ge=1)
    request_rate_per_second: int = Field(ge=1)
    concurrency_limit: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    response_bytes_limit: int = Field(ge=1)
    result_limit: int = Field(ge=1)
    profile_state: Literal["certified-local-lab"]

class NucleiPlanData(StrictModel):
    plan_id: str
    profile_id: NucleiProfileIdValue
    bundle_id: str
    target_id: str
    policy_decision_id: str
    policy_revision: str
    roe_version_id: str
    plan_sha256: str
    scope_sha256: str
    expires_at: datetime
    version: int = Field(ge=1)

class NucleiRunData(StrictModel):
    run_id: str
    plan_id: str
    job_id: str
    runner_id: str
    run_state: str
    progress_percent: int = Field(ge=0, le=100)
    request_count: int = Field(ge=0)
    response_bytes: int = Field(ge=0)
    result_count: int = Field(ge=0)
    reason_code: str
    version: int = Field(ge=1)

class NucleiResultData(StrictModel):
    result_id: str
    template_id: str
    matcher_name: str
    severity: str
    affected_resource: str
    fingerprint: str
    evidence_instance_id: str

class NucleiCleanupData(StrictModel):
    receipt_id: str
    residual_resource_count: int = Field(ge=0)
    cleanup_complete: bool
    completed_at: datetime

class NucleiTargetOptionData(StrictModel):
    target_id: str
    attestation_sha256: str
    attestation_state: str
    non_production: bool
    expires_at: datetime

class NucleiRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    registration_state: str
    expires_at: datetime

class NucleiJobOptionData(StrictModel):
    job_id: str
    engagement_id: str
    roe_version_id: str
    status: str
    current_gate: str
    dispatch_blocked: bool
    stop_requested: bool

class NucleiDashboardData(StrictModel):
    profiles: list[NucleiProfileData]
    plans: list[NucleiPlanData]
    runs: list[NucleiRunData]
    results: list[NucleiResultData]
    cleanups: list[NucleiCleanupData]
    target_options: list[NucleiTargetOptionData]
    runner_options: list[NucleiRunnerOptionData]
    job_options: list[NucleiJobOptionData]

class NucleiProfileListResponse(StrictModel):
    data: list[NucleiProfileData]

class NucleiPlanResponse(StrictModel):
    data: NucleiPlanData

class NucleiRunResponse(StrictModel):
    data: NucleiRunData

class NucleiDashboardResponse(StrictModel):
    data: NucleiDashboardData

__all__ = (
    "NucleiProfileIdValue",
    "NucleiCompileRequest",
    "NucleiRunCreateRequest",
    "NucleiCancelRequest",
    "NucleiProfileData",
    "NucleiPlanData",
    "NucleiRunData",
    "NucleiResultData",
    "NucleiCleanupData",
    "NucleiTargetOptionData",
    "NucleiRunnerOptionData",
    "NucleiJobOptionData",
    "NucleiDashboardData",
    "NucleiProfileListResponse",
    "NucleiPlanResponse",
    "NucleiRunResponse",
    "NucleiDashboardResponse",
)
