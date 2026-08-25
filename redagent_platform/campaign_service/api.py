"""Thin internal API router for the bounded compat_123 qualification seam."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from redagent_platform.campaign_service.qualification import (
    OwnedLoopbackQualificationIntentV1,
    QualificationStartReceiptV1,
    R123QualificationService,
    R123StatusService,
)
from redagent_platform.campaign_service.status import (
    R123CampaignStatusNotFound,
    R123CampaignStatusOwner,
    R123CampaignStatusV1,
    R124PrincipalInactive,
)
from redagent_platform.campaign_service.service import R124CreateDisabled, R124EtagConflict
from redagent_platform.persistence.repository import IdempotencyConflict


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class R123QualificationRequest(_StrictModel):
    fixture_id: Literal["owned-loopback-http-first-slice"]
    objective_kind: Literal["http_posture", "security_header_assertion"]
    header_code: Literal["x-content-type-options"] | None = None
    require_corroboration: bool
    risk_profile: Literal["tier1_passive"]


class R123QualificationData(_StrictModel):
    schema_version: Literal["redagent.r123-qualification-start-receipt/v1"]
    campaign_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    aggregate_sequence: Literal[1]
    status: Literal["dispatch_pending"]


class R123QualificationResponse(_StrictModel):
    data: R123QualificationData


class R123StatusData(_StrictModel):
    ready: bool
    execution_enabled: bool
    reason: str = Field(min_length=1, max_length=100)
    capability_ids: tuple[str, ...] = Field(max_length=2)


class R123StatusResponse(_StrictModel):
    data: R123StatusData


class R123CampaignEffectStatusData(_StrictModel):
    capability_id: str = Field(min_length=1, max_length=101)
    state: str = Field(min_length=1, max_length=32)
    reconciliation_state: str = Field(min_length=1, max_length=32)
    evidence_count: int = Field(ge=0, le=100)
    cleanup_complete: bool


class R123CampaignStatusData(_StrictModel):
    schema_version: Literal["redagent.r123-campaign-status/v1"]
    campaign_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    status: str = Field(min_length=1, max_length=32)
    aggregate_sequence: int = Field(ge=1)
    replan_count: int = Field(ge=0, le=1)
    attention_reason: str | None = Field(default=None, max_length=100)
    workflow_delivery_state: str = Field(min_length=1, max_length=32)
    workflow_reconciliation_state: str = Field(min_length=1, max_length=100)
    effects: tuple[R123CampaignEffectStatusData, ...] = Field(max_length=2)
    terminal_receipt_present: bool


class R123CampaignStatusResponse(_StrictModel):
    data: R123CampaignStatusData


class R124CampaignStartRequest(_StrictModel):
    engagement_binding: str = Field(min_length=1, max_length=100)
    target_binding: str = Field(min_length=1, max_length=100)
    objective: str = Field(min_length=1, max_length=300)
    risk_profile: str = Field(min_length=1, max_length=100)


class R124RecoveryRequest(_StrictModel):
    reason: str = Field(min_length=10, max_length=500)


class R124OptionData(_StrictModel):
    binding: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=200)
    revision: str = Field(min_length=1, max_length=100)
    freshness: str = Field(min_length=1, max_length=32)
    eligible: bool
    unavailable_reason: str | None = Field(default=None, max_length=200)


class R124PageData(_StrictModel):
    limit: int = Field(ge=1, le=50)
    next_cursor: str | None = Field(default=None, max_length=200)


class R124EngagementOptionPageResponse(_StrictModel):
    data: tuple[R124OptionData, ...] = Field(max_length=50)
    page: R124PageData


class R124TargetOptionPageResponse(R124EngagementOptionPageResponse):
    pass


class R124RiskProfileOptionPageResponse(R124EngagementOptionPageResponse):
    pass


class R124CampaignMutationData(_StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    status: str = Field(min_length=1, max_length=32)
    aggregate_sequence: int = Field(ge=1)
    etag: str = Field(min_length=3, max_length=100)
    replayed: bool


class R124CampaignMutationResponse(_StrictModel):
    data: R124CampaignMutationData


class R124CampaignSummaryData(_StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=200)
    status: str = Field(min_length=1, max_length=32)
    authority_state: str = Field(min_length=1, max_length=64)
    attention_reason: str | None = Field(default=None, max_length=100)
    aggregate_sequence: int = Field(ge=1)


class R124CampaignSummaryPageResponse(_StrictModel):
    data: tuple[R124CampaignSummaryData, ...] = Field(max_length=50)
    page: R124PageData


class R124AuthorityData(_StrictModel):
    state: str = Field(min_length=1, max_length=64)
    attention_reason: str | None = Field(default=None, max_length=100)


class R124ContextData(_StrictModel):
    schema_version: str = Field(alias="schema", min_length=1, max_length=100)
    coverage: str = Field(min_length=1, max_length=100)
    freshness: str = Field(min_length=1, max_length=100)


class R124CandidateData(_StrictModel):
    label: str = Field(min_length=1, max_length=200)
    eligible: bool
    reason: str = Field(min_length=1, max_length=200)


class R124DecisionData(_StrictModel):
    outcome: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=200)
    candidates: tuple[R124CandidateData, ...] = Field(max_length=2)


class R124PlanData(_StrictModel):
    primary: str = Field(min_length=1, max_length=200)
    successor: str | None = Field(default=None, max_length=200)
    successor_condition: str | None = Field(default=None, max_length=100)
    depth: int = Field(ge=1, le=2)
    risk: str = Field(min_length=1, max_length=100)
    cost: str = Field(min_length=1, max_length=200)
    evidence: str = Field(min_length=1, max_length=200)
    cleanup: str = Field(min_length=1, max_length=200)
    approval: str = Field(min_length=1, max_length=100)


class R124EffectData(_StrictModel):
    capability: str = Field(min_length=1, max_length=200)
    state: str = Field(min_length=1, max_length=64)
    reconciliation: str = Field(min_length=1, max_length=64)
    evidence_count: int = Field(ge=0, le=100)
    cleanup_complete: bool
    failure: str | None = Field(default=None, max_length=100)


class R124RetestData(_StrictModel):
    coverage: str | None = Field(default=None, max_length=100)
    result: str | None = Field(default=None, max_length=100)


class R124FindingData(_StrictModel):
    title: str = Field(min_length=1, max_length=500)
    severity: str = Field(min_length=1, max_length=32)
    disposition: str = Field(min_length=1, max_length=64)
    owner: str | None = Field(default=None, max_length=200)
    state: str = Field(min_length=1, max_length=64)
    residual_risk: str = Field(min_length=1, max_length=100)
    retest: R124RetestData


class R124RecoveryData(_StrictModel):
    stop_visible: bool
    revoke_visible: bool
    cleanup_required: bool
    guidance: str = Field(min_length=1, max_length=300)


class R124CampaignAggregateData(_StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=200)
    status: str = Field(min_length=1, max_length=64)
    aggregate_sequence: int = Field(ge=1)
    etag: str = Field(min_length=3, max_length=100)
    authority: R124AuthorityData
    context: R124ContextData
    decision: R124DecisionData
    plan: R124PlanData
    effects: tuple[R124EffectData, ...] = Field(max_length=2)
    findings: tuple[R124FindingData, ...] = Field(max_length=100)
    recovery: R124RecoveryData


class R124CampaignAggregateResponse(_StrictModel):
    data: R124CampaignAggregateData


class R124CampaignInspectorData(_StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    engagement_id: str = Field(min_length=1, max_length=64)
    roe_version_id: str = Field(min_length=1, max_length=64)
    workflow_id: str = Field(min_length=1, max_length=200)
    strategy_revision_id: str = Field(min_length=1, max_length=100)
    context_sha256: str = Field(min_length=64, max_length=64)
    decision_sha256: str = Field(min_length=64, max_length=64)
    plan_sha256: str = Field(min_length=64, max_length=64)
    approval_receipt_id: str = Field(min_length=1, max_length=100)
    approval_receipt_sha256: str = Field(min_length=64, max_length=64)
    envelope_sha256: str = Field(min_length=64, max_length=64)
    terminal_receipt_sha256: str | None = Field(default=None, min_length=64, max_length=64)


class R124CampaignInspectorResponse(_StrictModel):
    data: R124CampaignInspectorData


class R124AttentionData(_StrictModel):
    binding: str = Field(min_length=1, max_length=100)
    campaign_label: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=200)
    next_safe_action: str = Field(min_length=1, max_length=300)
    occurred_at: datetime


class R124AttentionPageResponse(_StrictModel):
    data: tuple[R124AttentionData, ...] = Field(max_length=50)
    page: R124PageData


def build_r123_router(
    *,
    require_guard: Callable[..., object],
    api_error: Callable[[int, str, str], Exception],
    now: Callable[[], datetime] | None = None,
    router: APIRouter | None = None,
) -> APIRouter:
    """Mount the compat_123 seam without adding domain route bodies to the API monolith."""

    clock = now or (lambda: datetime.now(timezone.utc))
    selected_router = router if router is not None else APIRouter()

    @selected_router.get(
        "/api/v1/internal/r123/status",
        operation_id="get_r123_internal_status",
        response_model=R123StatusResponse,
    )
    async def get_status(
        request: Request,
        guard=Depends(require_guard("campaign:read", safety_preserving=True)),
    ) -> R123StatusResponse:
        del guard
        service: R123StatusService = request.app.state.r123_status_service
        projected = await service.read(now=clock())
        return R123StatusResponse(
            data=R123StatusData(
                ready=projected.ready,
                execution_enabled=projected.execution_enabled,
                reason=projected.reason,
                capability_ids=projected.capability_ids,
            )
        )

    @selected_router.get(
        "/api/v1/internal/r123/campaigns/{campaign_id}/status",
        operation_id="get_r123_campaign_status",
        response_model=R123CampaignStatusResponse,
    )
    async def get_campaign_status(
        request: Request,
        campaign_id: str = Path(
            min_length=1,
            max_length=64,
            pattern=r"^[A-Za-z0-9._:-]+$",
        ),
        guard=Depends(require_guard("campaign:read", safety_preserving=True)),
    ) -> R123CampaignStatusResponse:
        owner: R123CampaignStatusOwner | None = (
            request.app.state.r123_campaign_status_owner
        )
        if owner is None:
            raise api_error(
                503,
                "r123_campaign_status_unavailable",
                "The R123 campaign status projection is unavailable.",
            )
        try:
            projected = await owner.read(
                tenant_id=guard.security.tenant_id,
                campaign_id=campaign_id,
            )
        except R123CampaignStatusNotFound as exc:
            raise api_error(
                404,
                "r123_campaign_not_found",
                "The R123 campaign was not found.",
            ) from exc
        if not isinstance(projected, R123CampaignStatusV1):
            raise ValueError("r123_campaign_status_projection_invalid")
        return R123CampaignStatusResponse(
            data=R123CampaignStatusData(
                schema_version=projected.schema_version,
                campaign_id=projected.campaign_id,
                status=projected.status,
                aggregate_sequence=projected.aggregate_sequence,
                replan_count=projected.replan_count,
                attention_reason=projected.attention_reason,
                workflow_delivery_state=projected.workflow_delivery_state,
                workflow_reconciliation_state=projected.workflow_reconciliation_state,
                effects=tuple(
                    R123CampaignEffectStatusData(
                        capability_id=item.capability_id,
                        state=item.state,
                        reconciliation_state=item.reconciliation_state,
                        evidence_count=item.evidence_count,
                        cleanup_complete=item.cleanup_complete,
                    )
                    for item in projected.effects
                ),
                terminal_receipt_present=projected.terminal_receipt_present,
            )
        )

    @selected_router.post(
        "/api/v1/internal/r123/qualification",
        operation_id="start_r123_owned_loopback_qualification",
        response_model=R123QualificationResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def start_qualification(
        payload: R123QualificationRequest,
        request: Request,
        guard=Depends(require_guard("campaign:create", mutation=True)),
    ) -> R123QualificationResponse:
        service: R123QualificationService | None = (
            request.app.state.r123_qualification_service
        )
        if service is None:
            raise api_error(
                503,
                "r123_qualification_unavailable",
                "The R123 owned-loopback qualification path is unavailable.",
            )
        receipt = await service.start(
            OwnedLoopbackQualificationIntentV1(**payload.model_dump()),
            tenant_id=guard.security.tenant_id,
            principal_id=guard.security.subject,
            now=clock(),
        )
        if not isinstance(receipt, QualificationStartReceiptV1):
            raise ValueError("r123_qualification_start_receipt_invalid")
        return R123QualificationResponse(
            data=R123QualificationData(**{
                "schema_version": receipt.schema_version,
                "campaign_id": receipt.campaign_id,
                "aggregate_sequence": receipt.aggregate_sequence,
                "status": receipt.status,
            })
        )

    def core_service(request: Request):
        service = getattr(request.app.state, "r124_campaign_core_service", None)
        if service is None:
            raise api_error(
                503,
                "r124_campaign_core_unavailable",
                "The campaign core is unavailable.",
            )
        return service

    @selected_router.get(
        "/api/v1/campaign-core/options/engagements",
        operation_id="list_r124_engagement_options",
        response_model=R124EngagementOptionPageResponse,
    )
    async def list_r124_engagement_options(
        request: Request,
        limit: int = Query(default=50, ge=1, le=50),
        cursor: str | None = Query(default=None, max_length=200),
        guard=Depends(require_guard("campaign:read")),
    ) -> object:
        return await core_service(request).list_engagement_options(
            tenant_id=guard.security.tenant_id,
            principal_id=guard.security.subject,
            limit=limit,
            cursor=cursor,
            now=clock(),
        )

    @selected_router.get(
        "/api/v1/campaign-core/options/targets",
        operation_id="list_r124_target_options",
        response_model=R124TargetOptionPageResponse,
    )
    async def list_r124_target_options(
        request: Request,
        engagement_binding: str = Query(min_length=1, max_length=100),
        limit: int = Query(default=50, ge=1, le=50),
        cursor: str | None = Query(default=None, max_length=200),
        guard=Depends(require_guard("campaign:read")),
    ) -> object:
        return await core_service(request).list_target_options(
            tenant_id=guard.security.tenant_id,
            principal_id=guard.security.subject,
            engagement_binding=engagement_binding,
            limit=limit,
            cursor=cursor,
            now=clock(),
        )

    @selected_router.get(
        "/api/v1/campaign-core/options/risk-profiles",
        operation_id="list_r124_risk_profile_options",
        response_model=R124RiskProfileOptionPageResponse,
    )
    async def list_r124_risk_profile_options(
        request: Request,
        engagement_binding: str = Query(min_length=1, max_length=100),
        target_binding: str = Query(min_length=1, max_length=100),
        limit: int = Query(default=50, ge=1, le=50),
        cursor: str | None = Query(default=None, max_length=200),
        guard=Depends(require_guard("campaign:read")),
    ) -> object:
        return await core_service(request).list_risk_profile_options(
            tenant_id=guard.security.tenant_id,
            principal_id=guard.security.subject,
            engagement_binding=engagement_binding,
            target_binding=target_binding,
            limit=limit,
            cursor=cursor,
            now=clock(),
        )

    @selected_router.post(
        "/api/v1/campaign-core/campaigns",
        operation_id="start_r124_campaign",
        response_model=R124CampaignMutationResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def start_r124_campaign(
        payload: R124CampaignStartRequest,
        request: Request,
        guard=Depends(require_guard("campaign:create", mutation=True)),
    ) -> object:
        try:
            return await core_service(request).start_campaign(
                payload,
                tenant_id=guard.security.tenant_id,
                principal_id=guard.security.subject,
                idempotency_key=guard.idempotency_key,
                now=clock(),
            )
        except IdempotencyConflict as exc:
            raise api_error(
                409,
                "idempotency_conflict",
                "The idempotency key was already used for a different campaign request.",
            ) from exc
        except R124CreateDisabled as exc:
            raise api_error(
                503,
                "campaign_create_disabled",
                "Normal campaign creation is disabled; recovery and read paths remain available.",
            ) from exc

    @selected_router.get(
        "/api/v1/campaign-core/campaigns",
        operation_id="list_r124_campaigns",
        response_model=R124CampaignSummaryPageResponse,
    )
    async def list_r124_campaigns(
        request: Request,
        limit: int = Query(default=50, ge=1, le=50),
        cursor: str | None = Query(default=None, max_length=200),
        guard=Depends(require_guard("campaign:read")),
    ) -> object:
        try:
            return await core_service(request).list_campaigns(
                tenant_id=guard.security.tenant_id,
                principal_id=guard.security.subject,
                limit=limit,
                cursor=cursor,
                now=clock(),
            )
        except R124PrincipalInactive as exc:
            raise api_error(403, "principal_inactive", "Current principal is inactive.") from exc

    @selected_router.get(
        "/api/v1/campaign-core/campaigns/{campaign_id}",
        operation_id="get_r124_campaign",
        response_model=R124CampaignAggregateResponse,
    )
    async def get_r124_campaign(
        request: Request,
        campaign_id: str = Path(min_length=1, max_length=64),
        guard=Depends(require_guard("campaign:read")),
    ) -> object:
        try:
            return await core_service(request).read_campaign(
                tenant_id=guard.security.tenant_id,
                principal_id=guard.security.subject,
                campaign_id=campaign_id,
                now=clock(),
            )
        except R123CampaignStatusNotFound as exc:
            raise api_error(404, "campaign_not_found", "Campaign was not found.") from exc
        except R124PrincipalInactive as exc:
            raise api_error(403, "principal_inactive", "Current principal is inactive.") from exc

    @selected_router.get(
        "/api/v1/campaign-core/campaigns/{campaign_id}/inspector",
        operation_id="inspect_r124_campaign",
        response_model=R124CampaignInspectorResponse,
    )
    async def inspect_r124_campaign(
        request: Request,
        campaign_id: str = Path(min_length=1, max_length=64),
        guard=Depends(require_guard("campaign:inspect")),
    ) -> object:
        try:
            return await core_service(request).inspect_campaign(
                tenant_id=guard.security.tenant_id,
                principal_id=guard.security.subject,
                campaign_id=campaign_id,
                now=clock(),
            )
        except R123CampaignStatusNotFound as exc:
            raise api_error(404, "campaign_not_found", "Campaign was not found.") from exc
        except R124PrincipalInactive as exc:
            raise api_error(403, "principal_inactive", "Current principal is inactive.") from exc

    @selected_router.get(
        "/api/v1/campaign-core/attention",
        operation_id="list_r124_attention",
        response_model=R124AttentionPageResponse,
    )
    async def list_r124_attention(
        request: Request,
        limit: int = Query(default=50, ge=1, le=50),
        cursor: str | None = Query(default=None, max_length=200),
        guard=Depends(require_guard("campaign:read")),
    ) -> object:
        try:
            return await core_service(request).list_attention(
                tenant_id=guard.security.tenant_id,
                principal_id=guard.security.subject,
                limit=limit,
                cursor=cursor,
                now=clock(),
            )
        except R124PrincipalInactive as exc:
            raise api_error(403, "principal_inactive", "Current principal is inactive.") from exc

    async def recover_campaign(
        *,
        action: Literal["stop", "revoke"],
        payload: R124RecoveryRequest,
        request: Request,
        campaign_id: str,
        if_match: str,
        guard: object,
    ) -> object:
        try:
            return await core_service(request).recover_campaign(
                action=action,
                reason=payload.reason,
                tenant_id=guard.security.tenant_id,
                principal_id=guard.security.subject,
                campaign_id=campaign_id,
                expected_etag=if_match,
                idempotency_key=guard.idempotency_key,
                now=clock(),
            )
        except R124EtagConflict as exc:
            raise api_error(
                409,
                "etag_conflict",
                "Campaign state changed; refresh current authority before retrying.",
            ) from exc
        except IdempotencyConflict as exc:
            raise api_error(
                409,
                "idempotency_conflict",
                "The idempotency key was already used for a different recovery request.",
            ) from exc

    @selected_router.post(
        "/api/v1/campaign-core/campaigns/{campaign_id}/stop",
        operation_id="stop_r124_campaign",
        response_model=R124CampaignMutationResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def stop_r124_campaign(
        payload: R124RecoveryRequest,
        request: Request,
        campaign_id: str = Path(min_length=1, max_length=64),
        if_match: str = Header(min_length=3, max_length=100, alias="If-Match"),
        guard=Depends(require_guard("campaign:stop", mutation=True, safety_preserving=True)),
    ) -> object:
        return await recover_campaign(
            action="stop", payload=payload, request=request, campaign_id=campaign_id,
            if_match=if_match, guard=guard,
        )

    @selected_router.post(
        "/api/v1/campaign-core/campaigns/{campaign_id}/revoke",
        operation_id="revoke_r124_campaign",
        response_model=R124CampaignMutationResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def revoke_r124_campaign(
        payload: R124RecoveryRequest,
        request: Request,
        campaign_id: str = Path(min_length=1, max_length=64),
        if_match: str = Header(min_length=3, max_length=100, alias="If-Match"),
        guard=Depends(require_guard("campaign:stop", mutation=True, safety_preserving=True)),
    ) -> object:
        return await recover_campaign(
            action="revoke", payload=payload, request=request, campaign_id=campaign_id,
            if_match=if_match, guard=guard,
        )

    return selected_router
