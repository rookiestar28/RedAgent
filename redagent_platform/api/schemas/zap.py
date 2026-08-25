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

ZapProfileId = Literal[
    "zap-passive-v1", "zap-auth-crawl-v1", "zap-client-spider-v1", "zap-active-xss-lab-v1"
]

class ZapCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    profile_id: ZapProfileId
    target_id: Literal["r104-owned-web-fixture"]
    target_attestation_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    credential_reference_ids: list[str] = Field(default_factory=list, max_length=1)

class ZapRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)

class ZapCancelRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class ZapProfileData(StrictModel):
    profile_id: ZapProfileId
    profile_revision: int = Field(ge=1)
    image_version: str
    image_digest: str
    addon_inventory_sha256: str
    profile_sha256: str
    risk_class: str
    passive_rule_ids: list[str]
    active_rule_ids: list[str]
    request_limit: int = Field(ge=1)
    request_rate_per_second: int = Field(ge=1)
    concurrency_limit: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    response_bytes_limit: int = Field(ge=1)
    profile_state: Literal["certified"]

class ZapPlanData(StrictModel):
    plan_id: str
    profile_id: ZapProfileId
    target_id: str
    policy_decision_id: str
    roe_version_id: str
    plan_sha256: str
    scope_sha256: str
    expires_at: datetime
    version: int = Field(ge=1)

class ZapRunData(StrictModel):
    run_id: str
    plan_id: str
    job_id: str
    runner_id: str
    run_state: str
    current_step: int = Field(ge=0)
    progress_percent: int = Field(ge=0, le=100)
    passive_queue_size: int = Field(ge=0)
    reason_code: str
    version: int = Field(ge=1)

class ZapCleanupData(StrictModel):
    receipt_id: str
    residual_resource_count: int = Field(ge=0)
    cleanup_complete: bool
    completed_at: datetime

class ZapTargetOptionData(StrictModel):
    target_id: str
    attestation_sha256: str
    attestation_state: str
    non_production: bool
    expires_at: datetime

class ZapRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    registration_state: str
    expires_at: datetime

class ZapDashboardData(StrictModel):
    profiles: list[ZapProfileData]
    plans: list[ZapPlanData]
    runs: list[ZapRunData]
    cleanups: list[ZapCleanupData]
    target_options: list[ZapTargetOptionData]
    runner_options: list[ZapRunnerOptionData]

class ZapProfileListResponse(StrictModel):
    data: list[ZapProfileData]

class ZapPlanResponse(StrictModel):
    data: ZapPlanData

class ZapRunResponse(StrictModel):
    data: ZapRunData

class ZapDashboardResponse(StrictModel):
    data: ZapDashboardData

__all__ = (
    "ZapProfileId",
    "ZapCompileRequest",
    "ZapRunCreateRequest",
    "ZapCancelRequest",
    "ZapProfileData",
    "ZapPlanData",
    "ZapRunData",
    "ZapCleanupData",
    "ZapTargetOptionData",
    "ZapRunnerOptionData",
    "ZapDashboardData",
    "ZapProfileListResponse",
    "ZapPlanResponse",
    "ZapRunResponse",
    "ZapDashboardResponse",
)
