"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    Literal,
    datetime,
)

from redagent_platform.api.schemas.common import (
    StrictModel,
)

class LabBundleData(StrictModel):
    bundle_id: str
    bundle_revision: int = Field(ge=1)
    fixture_digest: str
    network_id: str
    bundle_state: str
    expires_at: datetime

class LabScenarioData(StrictModel):
    run_id: str
    scenario_id: str
    scenario_state: Literal["pending", "running", "succeeded", "failed", "compensating", "cleaned"]
    reason_code: str
    current_step: int = Field(ge=0)
    version: int = Field(ge=1)

class LabMeasurementData(StrictModel):
    measurement_id: str
    metric_id: str
    comparison: Literal["lte", "gte"]
    observed_millionths: int = Field(ge=0)
    threshold_millionths: int = Field(ge=0)
    unit: str
    sample_count: int = Field(ge=1)
    result_state: Literal["passed", "failed"]

class LabTeardownData(StrictModel):
    receipt_id: str
    residual_resource_count: int = Field(ge=0)
    teardown_complete: bool
    inventory_sha256: str
    completed_at: datetime

class LabDashboardData(StrictModel):
    bundle: LabBundleData | None
    scenarios: list[LabScenarioData]
    measurements: list[LabMeasurementData]
    latest_teardown: LabTeardownData | None
    emergency_stop_path: Literal["/jobs/{job_id}/emergency-stop"]
    arbitrary_target_input_allowed: Literal[False]

class LabDashboardResponse(StrictModel):
    data: LabDashboardData

__all__ = (
    "LabBundleData",
    "LabScenarioData",
    "LabMeasurementData",
    "LabTeardownData",
    "LabDashboardData",
    "LabDashboardResponse",
)
