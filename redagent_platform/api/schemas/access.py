"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Any,
    Field,
    Literal,
    OPAQUE_ID,
    datetime,
    model_validator,
    timedelta,
    timezone,
)

from redagent_platform.api.schemas.common import (
    MutationMeta,
    PageData,
    StrictModel,
)

from redagent_platform.api.schemas.policy import (
    PolicyReferenceData,
)

class EngagementCreateRequest(StrictModel):
    engagement_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    name: str = Field(min_length=1, max_length=200)
    owner_user_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)

class EngagementUpdateRequest(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    expected_version: int = Field(ge=1)

class TargetCreateRequest(StrictModel):
    target_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    target_type: Literal["hostname", "ip", "cidr", "url", "application"]
    normalized_value: str = Field(min_length=1, max_length=500)

class RoeVersionCreateRequest(StrictModel):
    roe_version_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    revision: int = Field(ge=1, le=1_000_000)
    document: dict[str, Any]
    policy_reference_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    policy_name: str = Field(min_length=1, max_length=200)
    policy_version: str = Field(min_length=1, max_length=100)

class RoeApprovalRequest(StrictModel):
    approval_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    expected_version: int = Field(ge=1)

class JitGrantCreateRequest(StrictModel):
    grant_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    role: Literal["operator", "approver", "reviewer", "tenant_admin"]
    permission: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    scope_type: Literal["engagement"]
    scope_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    reason: str = Field(min_length=10, max_length=500)
    expires_at: datetime
    break_glass: bool = False

    @model_validator(mode="after")
    def validate_expiry(self) -> "JitGrantCreateRequest":
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("jit_expiry_timezone_required")
        now = datetime.now(timezone.utc)
        if not now < self.expires_at <= now + timedelta(hours=24):
            raise ValueError("jit_expiry_invalid")
        return self

class JitGrantApprovalRequest(StrictModel):
    expected_version: int = Field(ge=1)

class JitGrantRevokeRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)

class JitGrantReviewRequest(StrictModel):
    review_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    expected_version: int = Field(ge=1)
    outcome: Literal["approved", "exception", "rejected"]

class OperatorShellContextData(StrictModel):
    schema_version: Literal["1"] = "1"
    environment: Literal["local", "production", "unknown"] = "unknown"
    safety_profile: Literal[
        "synthetic-local", "local-conformance", "production", "unknown"
    ] = "unknown"
    status: Literal["ready", "unknown", "unavailable"] = "unavailable"

    @model_validator(mode="after")
    def validate_ready_profile_pair(self) -> "OperatorShellContextData":
        compatible = (
            self.environment == "local"
            and self.safety_profile in {"synthetic-local", "local-conformance"}
        ) or (
            self.environment == "production"
            and self.safety_profile == "production"
        )
        # CRITICAL: even server injection cannot label a cross-environment profile ready.
        if self.status == "ready" and not compatible:
            raise ValueError("operator_shell_ready_profile_mismatch")
        return self

class ContextData(StrictModel):
    subject: str
    tenant_id: str
    permissions: list[str]
    roles: list[str]
    operator_shell: OperatorShellContextData

class ContextResponse(StrictModel):
    data: ContextData

class MembershipData(StrictModel):
    user_id: str
    status: str
    generation: int
    roles: list[str]
    version: int

class JitGrantData(StrictModel):
    grant_id: str
    requester_user_id: str
    approver_user_id: str | None
    role: str
    permission: str
    scope_type: str
    scope_id: str
    reason: str
    approved_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    break_glass: bool
    version: int

class ActivityData(StrictModel):
    event_id: str
    actor_user_id: str
    action: str
    subject_type: str
    subject_id: str
    correlation_id: str
    occurred_at: datetime

class MembershipListResponse(StrictModel):
    data: list[MembershipData]
    page: PageData

class JitGrantListResponse(StrictModel):
    data: list[JitGrantData]
    page: PageData

class JitGrantResponse(StrictModel):
    data: JitGrantData

class ActivityListResponse(StrictModel):
    data: list[ActivityData]
    page: PageData

class JitGrantMutationResponse(StrictModel):
    data: JitGrantData
    meta: MutationMeta

class EngagementData(StrictModel):
    engagement_id: str
    tenant_id: str
    name: str
    owner_user_id: str
    version: int

class EngagementResponse(StrictModel):
    data: EngagementData

class EngagementMutationResponse(StrictModel):
    data: EngagementData
    meta: MutationMeta

class EngagementListResponse(StrictModel):
    data: list[EngagementData]
    page: PageData

class TargetData(StrictModel):
    target_id: str
    tenant_id: str
    engagement_id: str
    target_type: str
    normalized_value: str
    version: int

class TargetMutationResponse(StrictModel):
    data: TargetData
    meta: MutationMeta

class TargetListResponse(StrictModel):
    data: list[TargetData]
    page: PageData

class RoeVersionData(StrictModel):
    roe_version_id: str
    tenant_id: str
    engagement_id: str
    revision: int
    status: str
    document: dict[str, Any]
    version: int
    policy_reference: PolicyReferenceData | None = None
    approval_id: str | None = None

class RoeVersionMutationResponse(StrictModel):
    data: RoeVersionData
    meta: MutationMeta

class RoeVersionListResponse(StrictModel):
    data: list[RoeVersionData]
    page: PageData

__all__ = (
    "EngagementCreateRequest",
    "EngagementUpdateRequest",
    "TargetCreateRequest",
    "RoeVersionCreateRequest",
    "RoeApprovalRequest",
    "JitGrantCreateRequest",
    "JitGrantApprovalRequest",
    "JitGrantRevokeRequest",
    "JitGrantReviewRequest",
    "OperatorShellContextData",
    "ContextData",
    "ContextResponse",
    "MembershipData",
    "JitGrantData",
    "ActivityData",
    "MembershipListResponse",
    "JitGrantListResponse",
    "JitGrantResponse",
    "ActivityListResponse",
    "JitGrantMutationResponse",
    "EngagementData",
    "EngagementResponse",
    "EngagementMutationResponse",
    "EngagementListResponse",
    "TargetData",
    "TargetMutationResponse",
    "TargetListResponse",
    "RoeVersionData",
    "RoeVersionMutationResponse",
    "RoeVersionListResponse",
)
