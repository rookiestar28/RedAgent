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

IdentityProfileIdValue = Literal[
    "r109-microsoft_365-emulator-v1",
    "r109-google_workspace-emulator-v1",
    "r109-okta-emulator-v1",
]

class IdentitySaasCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    profile_id: IdentityProfileIdValue
    tenant_binding_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    reservation_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    credential_lease_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r109-local-lab"]

class IdentitySaasRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r109-local-lab"]

class IdentitySaasCancelRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class IdentitySaasOperationData(StrictModel):
    operation_id: str; method: Literal["GET"]; api_version: str; permission_scope: str
    effective_role_permission: str; selected_fields: list[str]; data_class: str; graph_eligible: bool

class IdentitySaasProfileData(StrictModel):
    profile_id: IdentityProfileIdValue; provider: Literal["microsoft_365", "google_workspace", "okta"]
    provider_tenant_id: str; audience: str; consent_mode: str; operations: list[IdentitySaasOperationData]
    retention_days: int = Field(ge=1, le=30); profile_state: Literal["certified-local-lab"]
    emulator_only: Literal[True]; production_qualified: Literal[False]

class IdentitySaasPlanData(StrictModel):
    plan_id: str; profile_id: IdentityProfileIdValue; tenant_binding_id: str; policy_decision_id: str
    reservation_id: str; credential_lease_id: str; plan_sha256: str; plan_state: str; expires_at: datetime; version: int = Field(ge=1)

class IdentitySaasRunData(StrictModel):
    run_id: str; plan_id: str; job_id: str; runner_id: str; run_state: str; complete: bool
    partial_reasons: list[str]; snapshot_sha256: str | None; version: int = Field(ge=1)

class IdentitySaasBindingOptionData(StrictModel):
    binding_id: str
    profile_id: IdentityProfileIdValue
    provider_tenant_id: str
    audience: str
    consent_mode: str
    permission_digest: str
    binding_state: str

class IdentitySaasRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    registration_state: str
    expires_at: datetime

class IdentitySaasJobOptionData(StrictModel):
    job_id: str
    engagement_id: str
    roe_version_id: str
    status: str
    current_gate: str
    dispatch_blocked: bool
    stop_requested: bool

class IdentitySaasReservationOptionData(StrictModel):
    reservation_id: str
    reserved_amount: int = Field(ge=1)
    consumed_amount: int = Field(ge=0)
    released_amount: int = Field(ge=0)
    remaining_amount: int = Field(ge=0)
    reservation_state: str
    expires_at: datetime

class IdentitySaasLeaseOptionData(StrictModel):
    lease_id: str
    job_id: str
    roe_version_id: str
    permission_digest: str
    lease_state: str
    expires_at: datetime

class IdentitySaasDashboardData(StrictModel):
    profiles: list[IdentitySaasProfileData]; plans: list[IdentitySaasPlanData]; runs: list[IdentitySaasRunData]
    evaluations: list[dict[str, Any]]; exceptions: list[dict[str, Any]]; graphs: list[dict[str, Any]]; cleanups: list[dict[str, Any]]
    binding_options: list[IdentitySaasBindingOptionData]
    runner_options: list[IdentitySaasRunnerOptionData]
    job_options: list[IdentitySaasJobOptionData]
    reservation_options: list[IdentitySaasReservationOptionData]
    lease_options: list[IdentitySaasLeaseOptionData]

class IdentitySaasProfileListResponse(StrictModel): data: list[IdentitySaasProfileData]

class IdentitySaasPlanResponse(StrictModel): data: IdentitySaasPlanData

class IdentitySaasRunResponse(StrictModel): data: IdentitySaasRunData

class IdentitySaasDashboardResponse(StrictModel): data: IdentitySaasDashboardData

__all__ = (
    "IdentityProfileIdValue",
    "IdentitySaasCompileRequest",
    "IdentitySaasRunCreateRequest",
    "IdentitySaasCancelRequest",
    "IdentitySaasOperationData",
    "IdentitySaasProfileData",
    "IdentitySaasPlanData",
    "IdentitySaasRunData",
    "IdentitySaasBindingOptionData",
    "IdentitySaasRunnerOptionData",
    "IdentitySaasJobOptionData",
    "IdentitySaasReservationOptionData",
    "IdentitySaasLeaseOptionData",
    "IdentitySaasDashboardData",
    "IdentitySaasProfileListResponse",
    "IdentitySaasPlanResponse",
    "IdentitySaasRunResponse",
    "IdentitySaasDashboardResponse",
)
