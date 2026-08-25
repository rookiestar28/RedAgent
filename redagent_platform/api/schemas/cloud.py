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

CloudProfileIdValue = Literal[
    "r108-aws-emulator-v1",
    "r108-azure-emulator-v1",
    "r108-gcp-emulator-v1",
    "r108-kubernetes-emulator-v1",
]

class CloudCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    profile_id: CloudProfileIdValue
    identity_binding_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    reservation_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    credential_lease_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r108-local-lab"]

class CloudRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r108-local-lab"]

class CloudCancelRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class CloudOperationData(StrictModel):
    operation_id: str
    action: str
    resource_scope: str
    data_class: str
    mutation: Literal[False]

class CloudProfileData(StrictModel):
    profile_id: CloudProfileIdValue
    provider: Literal["aws", "azure", "gcp", "kubernetes"]
    expected_identity: str
    operations: list[CloudOperationData]
    max_api_calls: int = Field(ge=1)
    max_pages: int = Field(ge=1)
    max_resources: int = Field(ge=1)
    max_response_bytes: int = Field(ge=1)
    profile_state: Literal["certified-local-lab"]
    emulator_only: Literal[True]
    production_qualified: Literal[False]

class CloudPlanData(StrictModel):
    plan_id: str
    profile_id: CloudProfileIdValue
    identity_binding_id: str
    policy_decision_id: str
    policy_revision: str
    reservation_id: str
    credential_lease_id: str
    plan_sha256: str
    plan_state: str
    expires_at: datetime
    version: int = Field(ge=1)

class CloudRunData(StrictModel):
    run_id: str
    plan_id: str
    job_id: str
    runner_id: str
    run_state: str
    complete: bool
    partial_reasons: list[str]
    snapshot_sha256: str | None
    version: int = Field(ge=1)

class CloudResultData(StrictModel):
    result_id: str
    control_pack_id: str
    check_id: str
    resource_id: str
    passed: bool
    severity: str
    evidence_instance_id: str | None

class CloudCleanupData(StrictModel):
    receipt_id: str
    lease_revoked: bool
    new_requests_blocked: bool
    residual_resource_count: int = Field(ge=0)
    completed_at: datetime

class CloudIdentityOptionData(StrictModel):
    binding_id: str
    profile_id: CloudProfileIdValue
    provider: str
    expected_identity: str
    permission_digest: str
    binding_state: str

class CloudRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    registration_state: str
    expires_at: datetime

class CloudJobOptionData(StrictModel):
    job_id: str
    engagement_id: str
    roe_version_id: str
    status: str
    current_gate: str
    dispatch_blocked: bool
    stop_requested: bool

class CloudReservationOptionData(StrictModel):
    reservation_id: str
    reserved_amount: int = Field(ge=1)
    consumed_amount: int = Field(ge=0)
    released_amount: int = Field(ge=0)
    remaining_amount: int = Field(ge=0)
    reservation_state: str
    expires_at: datetime

class CloudLeaseOptionData(StrictModel):
    lease_id: str
    job_id: str
    roe_version_id: str
    permission_digest: str
    lease_state: str
    expires_at: datetime

class CloudDashboardData(StrictModel):
    profiles: list[CloudProfileData]
    plans: list[CloudPlanData]
    runs: list[CloudRunData]
    results: list[CloudResultData]
    cleanups: list[CloudCleanupData]
    identity_options: list[CloudIdentityOptionData]
    runner_options: list[CloudRunnerOptionData]
    job_options: list[CloudJobOptionData]
    reservation_options: list[CloudReservationOptionData]
    lease_options: list[CloudLeaseOptionData]

class CloudProfileListResponse(StrictModel):
    data: list[CloudProfileData]

class CloudPlanResponse(StrictModel):
    data: CloudPlanData

class CloudRunResponse(StrictModel):
    data: CloudRunData

class CloudDashboardResponse(StrictModel):
    data: CloudDashboardData

__all__ = (
    "CloudProfileIdValue",
    "CloudCompileRequest",
    "CloudRunCreateRequest",
    "CloudCancelRequest",
    "CloudOperationData",
    "CloudProfileData",
    "CloudPlanData",
    "CloudRunData",
    "CloudResultData",
    "CloudCleanupData",
    "CloudIdentityOptionData",
    "CloudRunnerOptionData",
    "CloudJobOptionData",
    "CloudReservationOptionData",
    "CloudLeaseOptionData",
    "CloudDashboardData",
    "CloudProfileListResponse",
    "CloudPlanResponse",
    "CloudRunResponse",
    "CloudDashboardResponse",
)
