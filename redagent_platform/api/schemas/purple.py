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

PurpleAbilityIdValue = Literal["r111-file-stage-marker-v1"]

class PurpleCompileRequest(StrictModel):
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    ability_id: PurpleAbilityIdValue
    lab_binding_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    approval_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_decision_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    policy_revision: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    reservation_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    lease_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    kill_switch_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    quota_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r111-owned-disposable-lab"]

class PurpleRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    job_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    runner_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r111-owned-disposable-lab"]

class PurpleKillRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class PurpleAbilityData(StrictModel):
    ability_id: PurpleAbilityIdValue; attack_version: str; attack_technique_id: Literal["T1074.001"]
    phases: list[str]; detection_strategy_id: str; analytic_id: str; event_schema: str
    timeout_seconds: int = Field(ge=1, le=10); lab_only: Literal[True]; network_allowed: Literal[False]
    subprocess_allowed: Literal[False]; external_content_allowed: Literal[False]; production_qualified: Literal[False]

class PurplePlanData(StrictModel):
    plan_id: str; ability_id: PurpleAbilityIdValue; lab_binding_id: str; approval_id: str
    policy_decision_id: str; roe_revision: str; reservation_id: str; lease_id: str; kill_switch_id: str
    plan_sha256: str; plan_state: str; expires_at: datetime; version: int = Field(ge=1)

class PurpleRunData(StrictModel):
    run_id: str; plan_id: str; job_id: str; runner_id: str; run_state: str; dispatch_blocked: bool
    detection_observed: bool; cleanup_complete: bool; teardown_verified: bool; failure_code: str | None
    version: int = Field(ge=1)

class PurpleLabOptionData(StrictModel):
    binding_id: str
    runner_id: str
    disposable: bool
    production: bool
    egress_allowed: bool
    binding_state: str
    expires_at: datetime

class PurpleApprovalOptionData(StrictModel):
    approval_id: str
    ability_id: PurpleAbilityIdValue
    lab_binding_id: str
    approval_state: str
    expires_at: datetime

class PurpleRunnerOptionData(StrictModel):
    runner_id: str
    environment: str
    network_plane: str
    required_policy_revision: str
    registration_state: str
    expires_at: datetime

class PurpleJobOptionData(StrictModel):
    job_id: str
    engagement_id: str
    roe_version_id: str
    status: str
    current_gate: str
    dispatch_blocked: bool
    stop_requested: bool

class PurpleReservationOptionData(StrictModel):
    reservation_id: str
    reserved_amount: int = Field(ge=1)
    consumed_amount: int = Field(ge=0)
    released_amount: int = Field(ge=0)
    remaining_amount: int = Field(ge=0)
    reservation_state: str
    expires_at: datetime

class PurpleDashboardData(StrictModel):
    abilities: list[PurpleAbilityData]; labs: list[dict[str, Any]]; approvals: list[dict[str, Any]]
    plans: list[PurplePlanData]; runs: list[PurpleRunData]; detections: list[dict[str, Any]]
    telemetry: list[dict[str, Any]]; cleanups: list[dict[str, Any]]; teardowns: list[dict[str, Any]]
    rehearsals: list[dict[str, Any]]
    lab_options: list[PurpleLabOptionData]
    approval_options: list[PurpleApprovalOptionData]
    runner_options: list[PurpleRunnerOptionData]
    job_options: list[PurpleJobOptionData]
    reservation_options: list[PurpleReservationOptionData]

class PurpleAbilityListResponse(StrictModel): data: list[PurpleAbilityData]

class PurplePlanResponse(StrictModel): data: PurplePlanData

class PurpleRunResponse(StrictModel): data: PurpleRunData

class PurpleDashboardResponse(StrictModel): data: PurpleDashboardData

__all__ = (
    "PurpleAbilityIdValue",
    "PurpleCompileRequest",
    "PurpleRunCreateRequest",
    "PurpleKillRequest",
    "PurpleAbilityData",
    "PurplePlanData",
    "PurpleRunData",
    "PurpleLabOptionData",
    "PurpleApprovalOptionData",
    "PurpleRunnerOptionData",
    "PurpleJobOptionData",
    "PurpleReservationOptionData",
    "PurpleDashboardData",
    "PurpleAbilityListResponse",
    "PurplePlanResponse",
    "PurpleRunResponse",
    "PurpleDashboardResponse",
)
