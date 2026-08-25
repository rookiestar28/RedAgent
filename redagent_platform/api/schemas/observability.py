"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    Literal,
    OPAQUE_ID,
    datetime,
    model_validator,
)

from redagent_platform.api.schemas.common import (
    PageData,
    StrictModel,
)

class ObservabilityDashboardData(StrictModel):
    export_state_counts: dict[str, int]
    incident_state_counts: dict[str, int]
    slo_state_counts: dict[str, int]
    open_alerts: int = Field(ge=0)
    unreplayed_dead_letters: int = Field(ge=0)

class ObservabilityDashboardResponse(StrictModel):
    data: ObservabilityDashboardData

class CorrelationEventData(StrictModel):
    operation_id: str
    event_id: str
    correlation_id: str
    signal_kind: str
    priority: str
    export_state: str
    reason_code: str | None
    occurred_at: datetime

class CorrelationEventListResponse(StrictModel):
    data: list[CorrelationEventData]
    page: "PageData"

class IncidentData(StrictModel):
    incident_id: str
    source_kind: str
    source_id: str
    severity: Literal["low", "medium", "high", "critical"]
    state: Literal["open", "acknowledged", "contained", "recovered", "reviewed", "closed"]
    reason_code: str
    opened_by_user_id: str
    assigned_to_user_id: str | None
    acknowledged_by_user_id: str | None
    contained_by_user_id: str | None
    recovered_by_user_id: str | None
    reviewed_by_user_id: str | None
    evidence_preserved: bool
    containment_verified: bool
    opened_at: datetime
    closed_at: datetime | None
    version: int = Field(ge=1)

class IncidentResponse(StrictModel):
    data: IncidentData

class IncidentListResponse(StrictModel):
    data: list[IncidentData]
    page: "PageData"

class IncidentActionRequest(StrictModel):
    action_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    action: Literal[
        "assign", "acknowledge", "preserve_evidence", "verify_containment",
        "mark_contained", "mark_recovered", "complete_review", "close",
    ]
    expected_version: int = Field(ge=1)
    assignee_id: str | None = Field(default=None, min_length=1, max_length=64, pattern=OPAQUE_ID)

    @model_validator(mode="after")
    def validate_assignee(self) -> "IncidentActionRequest":
        if (self.action == "assign") != (self.assignee_id is not None):
            raise ValueError("incident_assignee_action_mismatch")
        return self

class IncidentTimelineData(StrictModel):
    event_id: str
    event_type: str
    actor_user_id: str
    reason_code: str
    occurred_at: datetime

class IncidentTimelineResponse(StrictModel):
    data: list[IncidentTimelineData]

class IncidentRunbookData(StrictModel):
    runbook_id: str
    owner: str
    triage: list[str]
    containment: list[str]
    evidence: list[str]
    recovery: list[str]
    review: list[str]

class IncidentRunbookListResponse(StrictModel):
    data: list[IncidentRunbookData]

__all__ = (
    "ObservabilityDashboardData",
    "ObservabilityDashboardResponse",
    "CorrelationEventData",
    "CorrelationEventListResponse",
    "IncidentData",
    "IncidentResponse",
    "IncidentListResponse",
    "IncidentActionRequest",
    "IncidentTimelineData",
    "IncidentTimelineResponse",
    "IncidentRunbookData",
    "IncidentRunbookListResponse",
)
