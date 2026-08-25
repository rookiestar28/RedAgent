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

NetworkProfileIdValue = Literal["tcp-connect-discovery-v1"]

class NetworkCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    profile_id: NetworkProfileIdValue
    target_set_id: Literal["r107-local-fixture"]
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    reservation_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r107-local-lab"]

class NetworkRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r107-local-lab"]

class NetworkCancelRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class NetworkProfileData(StrictModel):
    profile_id: NetworkProfileIdValue
    profile_revision: int = Field(ge=1)
    engine_id: Literal["redagent-stdlib-tcp-connect"]
    category: Literal["low-risk-connect-discovery"]
    max_targets: int = Field(ge=1)
    max_ports_per_target: int = Field(ge=1)
    max_attempts: int = Field(ge=1)
    rate_per_second: int = Field(ge=1)
    concurrency_limit: int = Field(ge=1)
    max_retries: int = Field(ge=0)
    connect_timeout_seconds: int = Field(ge=1)
    run_timeout_seconds: int = Field(ge=1)
    banner_bytes: int = Field(ge=0)
    output_bytes: int = Field(ge=1)
    profile_state: Literal["certified-local-lab"]
    production_qualified: Literal[False]

class NetworkPlanData(StrictModel):
    plan_id: str
    profile_id: NetworkProfileIdValue
    target_set_id: str
    policy_decision_id: str
    policy_revision: str
    roe_version_id: str
    reservation_id: str
    plan_sha256: str
    tuple_count: int = Field(ge=1)
    budgets: dict[str, int]
    plan_state: str
    expires_at: datetime
    version: int = Field(ge=1)

class NetworkRunData(StrictModel):
    run_id: str
    plan_id: str
    job_id: str
    runner_id: str
    run_state: str
    completed_tuples: int = Field(ge=0)
    total_tuples: int = Field(ge=1)
    partial: bool
    reason_code: str
    version: int = Field(ge=1)

class NetworkObservationData(StrictModel):
    observation_id: str
    tuple_id: str
    connection_state: str
    latency_bucket: str
    service_class: str
    sample_sha256: str
    uncertainty: str
    redaction_state: str
    evidence_instance_id: str | None

class NetworkCleanupData(StrictModel):
    receipt_id: str
    residual_resource_count: int = Field(ge=0)
    completed_at: datetime

class NetworkTargetOptionData(StrictModel):
    target_set_id: str
    target_set_state: str
    non_production: bool
    no_public_route: bool
    no_direct_target_route: bool
    expires_at: datetime

class NetworkRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    registration_state: str
    expires_at: datetime

class NetworkJobOptionData(StrictModel):
    job_id: str
    engagement_id: str
    roe_version_id: str
    status: str
    current_gate: str
    dispatch_blocked: bool
    stop_requested: bool

class NetworkReservationOptionData(StrictModel):
    reservation_id: str
    reserved_amount: int = Field(ge=1)
    consumed_amount: int = Field(ge=0)
    released_amount: int = Field(ge=0)
    remaining_amount: int = Field(ge=0)
    reservation_state: str
    expires_at: datetime

class NetworkDashboardData(StrictModel):
    profiles: list[NetworkProfileData]
    plans: list[NetworkPlanData]
    runs: list[NetworkRunData]
    observations: list[NetworkObservationData]
    cleanups: list[NetworkCleanupData]
    target_options: list[NetworkTargetOptionData]
    runner_options: list[NetworkRunnerOptionData]
    job_options: list[NetworkJobOptionData]
    reservation_options: list[NetworkReservationOptionData]

class NetworkProfileListResponse(StrictModel):
    data: list[NetworkProfileData]

class NetworkPlanResponse(StrictModel):
    data: NetworkPlanData

class NetworkRunResponse(StrictModel):
    data: NetworkRunData

class NetworkDashboardResponse(StrictModel):
    data: NetworkDashboardData

__all__ = (
    "NetworkProfileIdValue",
    "NetworkCompileRequest",
    "NetworkRunCreateRequest",
    "NetworkCancelRequest",
    "NetworkProfileData",
    "NetworkPlanData",
    "NetworkRunData",
    "NetworkObservationData",
    "NetworkCleanupData",
    "NetworkTargetOptionData",
    "NetworkRunnerOptionData",
    "NetworkJobOptionData",
    "NetworkReservationOptionData",
    "NetworkDashboardData",
    "NetworkProfileListResponse",
    "NetworkPlanResponse",
    "NetworkRunResponse",
    "NetworkDashboardResponse",
)
