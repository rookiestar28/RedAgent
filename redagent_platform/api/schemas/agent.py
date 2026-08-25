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

class AgentRunCreateRequest(StrictModel):
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    campaign_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    tool_fqn: str = Field(min_length=1, max_length=200, pattern=OPAQUE_ID)
    plan_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r113-proposal-only"]

class AgentProposalApproveRequest(StrictModel):
    approval_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    expected_proposal_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    confirmation: Literal["--confirm-r113-exact-proposal"]

class AgentCancelRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class AgentToolData(StrictModel):
    tool_fqn: str; capability_id: str; capability_revision: int = Field(ge=1); capability_sha256: str
    input_schema_sha256: str; output_schema_sha256: str; approval_tier: str; network_class: str
    access_class: str; max_turns: int = Field(ge=1); max_tool_calls: int = Field(ge=0)
    max_elapsed_seconds: int = Field(ge=1); max_input_tokens: int = Field(ge=1)
    max_output_tokens: int = Field(ge=1); max_cost_microunits: int = Field(ge=0)
    max_result_bytes: int = Field(ge=1); unsupported_features: list[str]

class AgentRunData(StrictModel):
    run_id: str; campaign_id: str; provider_id: str; registry_sha256: str; run_state: str
    cancel_requested: bool; failure_code: str | None; started_at: datetime; expires_at: datetime
    completed_at: datetime | None; version: int = Field(ge=1)

class AgentProposalData(StrictModel):
    proposal_id: str; run_id: str; tool_fqn: str; proposal_sha256: str; argument_sha256: str
    target_sha256: str; side_effect_classes: list[str]; roe_version_id: str; policy_revision: str
    policy_decision_id: str; proposal_state: str; expires_at: datetime; version: int = Field(ge=1)

class AgentApprovalData(StrictModel):
    approval_id: str; proposal_id: str; proposal_sha256: str; approved_by: str; approval_state: str
    issued_at: datetime; expires_at: datetime; consumed_at: datetime | None; revoked_at: datetime | None
    version: int = Field(ge=1)

class AgentBudgetData(StrictModel):
    ledger_id: str; run_id: str; turn_count: int = Field(ge=0); tool_call_count: int = Field(ge=0)
    input_token_count: int = Field(ge=0); result_token_count: int = Field(ge=0)
    cost_microunits: int = Field(ge=0); result_bytes: int = Field(ge=0); elapsed_millis: int = Field(ge=0)
    ledger_state: str; version: int = Field(ge=1)

class AgentTraceData(StrictModel):
    trace_id: str; span_id: str; run_id: str; event_type: str; trace_state: str
    input_sha256: str; output_sha256: str; policy_decision_id: str | None; approval_id: str | None
    evidence_id: str | None; error_code: str | None; occurred_at: datetime

class AgentRunStartData(StrictModel):
    run: AgentRunData
    proposal: AgentProposalData

class AgentDashboardData(StrictModel):
    tools: list[AgentToolData]; runs: list[AgentRunData]; proposals: list[AgentProposalData]
    approvals: list[AgentApprovalData]; budgets: list[AgentBudgetData]; traces: list[AgentTraceData]

class AgentToolListResponse(StrictModel): data: list[AgentToolData]

class AgentRunStartResponse(StrictModel): data: AgentRunStartData

class AgentProposalResponse(StrictModel): data: AgentProposalData

class AgentRunResponse(StrictModel): data: AgentRunData

class AgentDashboardResponse(StrictModel): data: AgentDashboardData

__all__ = (
    "AgentRunCreateRequest",
    "AgentProposalApproveRequest",
    "AgentCancelRequest",
    "AgentToolData",
    "AgentRunData",
    "AgentProposalData",
    "AgentApprovalData",
    "AgentBudgetData",
    "AgentTraceData",
    "AgentRunStartData",
    "AgentDashboardData",
    "AgentToolListResponse",
    "AgentRunStartResponse",
    "AgentProposalResponse",
    "AgentRunResponse",
    "AgentDashboardResponse",
)
