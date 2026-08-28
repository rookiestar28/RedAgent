"""Thin internal API router for the bounded compat_123 qualification seam."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from redagent_platform.campaign_service.qualification import (
    OwnedLoopbackQualificationIntentV1,
    QualificationStartReceiptV1,
    CampaignQualificationService,
    CampaignStatusService,
)
from redagent_platform.campaign_service.status import (
    CampaignStatusNotFound,
    CampaignStatusOwner,
    CampaignStatusV1,
    CampaignCorePrincipalInactive,
)
from redagent_platform.campaign_service.service import CampaignCoreCreateDisabled, CampaignCoreEtagConflict
from redagent_platform.persistence.repository import IdempotencyConflict


CAMPAIGN_CORE_ENGAGEMENT_OPTIONS_OPERATION_ID = "list_r124_engagement_options"
CAMPAIGN_CORE_TARGET_OPTIONS_OPERATION_ID = "list_r124_target_options"
CAMPAIGN_CORE_RISK_PROFILE_OPTIONS_OPERATION_ID = "list_r124_risk_profile_options"
CAMPAIGN_CORE_START_OPERATION_ID = "start_r124_campaign"
CAMPAIGN_CORE_LIST_OPERATION_ID = "list_r124_campaigns"
CAMPAIGN_CORE_GET_OPERATION_ID = "get_r124_campaign"
CAMPAIGN_CORE_INSPECT_OPERATION_ID = "inspect_r124_campaign"
CAMPAIGN_CORE_ATTENTION_OPERATION_ID = "list_r124_attention"
CAMPAIGN_CORE_STOP_OPERATION_ID = "stop_r124_campaign"
CAMPAIGN_CORE_REVOKE_OPERATION_ID = "revoke_r124_campaign"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CampaignQualificationRequest(_StrictModel):
    fixture_id: Literal["owned-loopback-http-first-slice"]
    objective_kind: Literal["http_posture", "security_header_assertion"]
    header_code: Literal["x-content-type-options"] | None = None
    require_corroboration: bool
    risk_profile: Literal["tier1_passive"]


class CampaignQualificationData(_StrictModel):
    schema_version: Literal["redagent.r123-qualification-start-receipt/v1"]
    campaign_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    aggregate_sequence: Literal[1]
    status: Literal["dispatch_pending"]


class CampaignQualificationResponse(_StrictModel):
    data: CampaignQualificationData


class CampaignReadinessStatusData(_StrictModel):
    ready: bool
    execution_enabled: bool
    reason: str = Field(min_length=1, max_length=100)
    capability_ids: tuple[str, ...] = Field(max_length=3)


class CampaignReadinessStatusResponse(_StrictModel):
    data: CampaignReadinessStatusData


class CampaignEffectStatusData(_StrictModel):
    capability_id: str = Field(min_length=1, max_length=101)
    state: str = Field(min_length=1, max_length=32)
    reconciliation_state: str = Field(min_length=1, max_length=32)
    evidence_count: int = Field(ge=0, le=100)
    cleanup_complete: bool


class CampaignStatusData(_StrictModel):
    schema_version: Literal["redagent.r123-campaign-status/v1"]
    campaign_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    status: str = Field(min_length=1, max_length=32)
    aggregate_sequence: int = Field(ge=1)
    replan_count: int = Field(ge=0, le=1)
    attention_reason: str | None = Field(default=None, max_length=100)
    workflow_delivery_state: str = Field(min_length=1, max_length=32)
    workflow_reconciliation_state: str = Field(min_length=1, max_length=100)
    effects: tuple[CampaignEffectStatusData, ...] = Field(max_length=2)
    terminal_receipt_present: bool


class CampaignStatusResponse(_StrictModel):
    data: CampaignStatusData


class CampaignCoreStartRequest(_StrictModel):
    engagement_binding: str = Field(min_length=1, max_length=100)
    target_binding: str = Field(min_length=1, max_length=100)
    objective: str = Field(min_length=1, max_length=300)
    risk_profile: str = Field(min_length=1, max_length=100)


class CampaignCoreRecoveryRequest(_StrictModel):
    reason: str = Field(min_length=10, max_length=500)


class CampaignCoreOptionData(_StrictModel):
    binding: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=200)
    revision: str = Field(min_length=1, max_length=100)
    freshness: str = Field(min_length=1, max_length=32)
    eligible: bool
    unavailable_reason: str | None = Field(default=None, max_length=200)


class CampaignCorePageData(_StrictModel):
    limit: int = Field(ge=1, le=50)
    next_cursor: str | None = Field(default=None, max_length=200)


class CampaignCoreEngagementOptionPageResponse(_StrictModel):
    data: tuple[CampaignCoreOptionData, ...] = Field(max_length=50)
    page: CampaignCorePageData


class CampaignCoreTargetOptionPageResponse(CampaignCoreEngagementOptionPageResponse):
    pass


class CampaignCoreRiskProfileOptionPageResponse(CampaignCoreEngagementOptionPageResponse):
    pass


class CampaignCoreMutationData(_StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    status: str = Field(min_length=1, max_length=32)
    aggregate_sequence: int = Field(ge=1)
    etag: str = Field(min_length=3, max_length=100)
    replayed: bool


class CampaignCoreMutationResponse(_StrictModel):
    data: CampaignCoreMutationData


class CampaignCoreSummaryData(_StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=200)
    status: str = Field(min_length=1, max_length=32)
    authority_state: str = Field(min_length=1, max_length=64)
    attention_reason: str | None = Field(default=None, max_length=100)
    aggregate_sequence: int = Field(ge=1)


class CampaignCoreSummaryPageResponse(_StrictModel):
    data: tuple[CampaignCoreSummaryData, ...] = Field(max_length=50)
    page: CampaignCorePageData


class CampaignCoreAuthorityData(_StrictModel):
    state: str = Field(min_length=1, max_length=64)
    attention_reason: str | None = Field(default=None, max_length=100)


class CampaignCoreContextData(_StrictModel):
    schema_version: str = Field(alias="schema", min_length=1, max_length=100)
    coverage: str = Field(min_length=1, max_length=100)
    freshness: str = Field(min_length=1, max_length=100)


class CampaignCoreCandidateData(_StrictModel):
    label: str = Field(min_length=1, max_length=200)
    eligible: bool
    reason: str = Field(min_length=1, max_length=200)


class CampaignCoreDecisionData(_StrictModel):
    outcome: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=200)
    candidates: tuple[CampaignCoreCandidateData, ...] = Field(max_length=3)


class CampaignCorePlanData(_StrictModel):
    primary: str = Field(min_length=1, max_length=200)
    successor: str | None = Field(default=None, max_length=200)
    successor_condition: str | None = Field(default=None, max_length=100)
    depth: int = Field(ge=1, le=2)
    risk: str = Field(min_length=1, max_length=100)
    cost: str = Field(min_length=1, max_length=200)
    evidence: str = Field(min_length=1, max_length=200)
    cleanup: str = Field(min_length=1, max_length=200)
    approval: str = Field(min_length=1, max_length=100)


class CampaignCoreEffectData(_StrictModel):
    capability: str = Field(min_length=1, max_length=200)
    state: str = Field(min_length=1, max_length=64)
    reconciliation: str = Field(min_length=1, max_length=64)
    evidence_count: int = Field(ge=0, le=100)
    cleanup_complete: bool
    failure: str | None = Field(default=None, max_length=100)


class CampaignCoreRetestData(_StrictModel):
    coverage: str | None = Field(default=None, max_length=100)
    result: str | None = Field(default=None, max_length=100)


class CampaignCoreFindingData(_StrictModel):
    title: str = Field(min_length=1, max_length=500)
    severity: str = Field(min_length=1, max_length=32)
    disposition: str = Field(min_length=1, max_length=64)
    owner: str | None = Field(default=None, max_length=200)
    state: str = Field(min_length=1, max_length=64)
    residual_risk: str = Field(min_length=1, max_length=100)
    retest: CampaignCoreRetestData


class CampaignCoreRecoveryData(_StrictModel):
    stop_visible: bool
    revoke_visible: bool
    cleanup_required: bool
    guidance: str = Field(min_length=1, max_length=300)


class CampaignCoreAggregateData(_StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=200)
    status: str = Field(min_length=1, max_length=64)
    aggregate_sequence: int = Field(ge=1)
    etag: str = Field(min_length=3, max_length=100)
    authority: CampaignCoreAuthorityData
    context: CampaignCoreContextData
    decision: CampaignCoreDecisionData
    plan: CampaignCorePlanData
    effects: tuple[CampaignCoreEffectData, ...] = Field(max_length=2)
    findings: tuple[CampaignCoreFindingData, ...] = Field(max_length=100)
    recovery: CampaignCoreRecoveryData


class CampaignCoreAggregateResponse(_StrictModel):
    data: CampaignCoreAggregateData


class CampaignCoreInspectorData(_StrictModel):
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


class CampaignCoreInspectorResponse(_StrictModel):
    data: CampaignCoreInspectorData


class CampaignCoreAttentionData(_StrictModel):
    binding: str = Field(min_length=1, max_length=100)
    campaign_label: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=200)
    next_safe_action: str = Field(min_length=1, max_length=300)
    occurred_at: datetime


class CampaignCoreAttentionPageResponse(_StrictModel):
    data: tuple[CampaignCoreAttentionData, ...] = Field(max_length=50)
    page: CampaignCorePageData


def build_campaign_router(
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
        response_model=CampaignReadinessStatusResponse,
    )
    async def get_status(
        request: Request,
        guard=Depends(require_guard("campaign:read", safety_preserving=True)),
    ) -> CampaignReadinessStatusResponse:
        del guard
        service: CampaignStatusService = request.app.state.r123_status_service
        projected = await service.read(now=clock())
        return CampaignReadinessStatusResponse(
            data=CampaignReadinessStatusData(
                ready=projected.ready,
                execution_enabled=projected.execution_enabled,
                reason=projected.reason,
                capability_ids=projected.capability_ids,
            )
        )

    @selected_router.get(
        "/api/v1/internal/r123/campaigns/{campaign_id}/status",
        operation_id="get_r123_campaign_status",
        response_model=CampaignStatusResponse,
    )
    async def get_campaign_status(
        request: Request,
        campaign_id: str = Path(
            min_length=1,
            max_length=64,
            pattern=r"^[A-Za-z0-9._:-]+$",
        ),
        guard=Depends(require_guard("campaign:read", safety_preserving=True)),
    ) -> CampaignStatusResponse:
        owner: CampaignStatusOwner | None = (
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
        except CampaignStatusNotFound as exc:
            raise api_error(
                404,
                "r123_campaign_not_found",
                "The R123 campaign was not found.",
            ) from exc
        if not isinstance(projected, CampaignStatusV1):
            raise ValueError("r123_campaign_status_projection_invalid")
        return CampaignStatusResponse(
            data=CampaignStatusData(
                schema_version=projected.schema_version,
                campaign_id=projected.campaign_id,
                status=projected.status,
                aggregate_sequence=projected.aggregate_sequence,
                replan_count=projected.replan_count,
                attention_reason=projected.attention_reason,
                workflow_delivery_state=projected.workflow_delivery_state,
                workflow_reconciliation_state=projected.workflow_reconciliation_state,
                effects=tuple(
                    CampaignEffectStatusData(
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
        response_model=CampaignQualificationResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def start_qualification(
        payload: CampaignQualificationRequest,
        request: Request,
        guard=Depends(require_guard("campaign:create", mutation=True)),
    ) -> CampaignQualificationResponse:
        service: CampaignQualificationService | None = (
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
        return CampaignQualificationResponse(
            data=CampaignQualificationData(**{
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
        operation_id=CAMPAIGN_CORE_ENGAGEMENT_OPTIONS_OPERATION_ID,
        name=CAMPAIGN_CORE_ENGAGEMENT_OPTIONS_OPERATION_ID,
        response_model=CampaignCoreEngagementOptionPageResponse,
    )
    async def list_campaign_core_engagement_options(
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
        operation_id=CAMPAIGN_CORE_TARGET_OPTIONS_OPERATION_ID,
        name=CAMPAIGN_CORE_TARGET_OPTIONS_OPERATION_ID,
        response_model=CampaignCoreTargetOptionPageResponse,
    )
    async def list_campaign_core_target_options(
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
        operation_id=CAMPAIGN_CORE_RISK_PROFILE_OPTIONS_OPERATION_ID,
        name=CAMPAIGN_CORE_RISK_PROFILE_OPTIONS_OPERATION_ID,
        response_model=CampaignCoreRiskProfileOptionPageResponse,
    )
    async def list_campaign_core_risk_profile_options(
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
        operation_id=CAMPAIGN_CORE_START_OPERATION_ID,
        name=CAMPAIGN_CORE_START_OPERATION_ID,
        response_model=CampaignCoreMutationResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def start_campaign_core_campaign(
        payload: CampaignCoreStartRequest,
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
        except CampaignCoreCreateDisabled as exc:
            raise api_error(
                503,
                "campaign_create_disabled",
                "Normal campaign creation is disabled; recovery and read paths remain available.",
            ) from exc

    @selected_router.get(
        "/api/v1/campaign-core/campaigns",
        operation_id=CAMPAIGN_CORE_LIST_OPERATION_ID,
        name=CAMPAIGN_CORE_LIST_OPERATION_ID,
        response_model=CampaignCoreSummaryPageResponse,
    )
    async def list_campaign_core_campaigns(
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
        except CampaignCorePrincipalInactive as exc:
            raise api_error(403, "principal_inactive", "Current principal is inactive.") from exc

    @selected_router.get(
        "/api/v1/campaign-core/campaigns/{campaign_id}",
        operation_id=CAMPAIGN_CORE_GET_OPERATION_ID,
        name=CAMPAIGN_CORE_GET_OPERATION_ID,
        response_model=CampaignCoreAggregateResponse,
    )
    async def get_campaign_core_campaign(
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
        except CampaignStatusNotFound as exc:
            raise api_error(404, "campaign_not_found", "Campaign was not found.") from exc
        except CampaignCorePrincipalInactive as exc:
            raise api_error(403, "principal_inactive", "Current principal is inactive.") from exc

    @selected_router.get(
        "/api/v1/campaign-core/campaigns/{campaign_id}/inspector",
        operation_id=CAMPAIGN_CORE_INSPECT_OPERATION_ID,
        name=CAMPAIGN_CORE_INSPECT_OPERATION_ID,
        response_model=CampaignCoreInspectorResponse,
    )
    async def inspect_campaign_core_campaign(
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
        except CampaignStatusNotFound as exc:
            raise api_error(404, "campaign_not_found", "Campaign was not found.") from exc
        except CampaignCorePrincipalInactive as exc:
            raise api_error(403, "principal_inactive", "Current principal is inactive.") from exc

    @selected_router.get(
        "/api/v1/campaign-core/attention",
        operation_id=CAMPAIGN_CORE_ATTENTION_OPERATION_ID,
        name=CAMPAIGN_CORE_ATTENTION_OPERATION_ID,
        response_model=CampaignCoreAttentionPageResponse,
    )
    async def list_campaign_core_attention(
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
        except CampaignCorePrincipalInactive as exc:
            raise api_error(403, "principal_inactive", "Current principal is inactive.") from exc

    async def recover_campaign(
        *,
        action: Literal["stop", "revoke"],
        payload: CampaignCoreRecoveryRequest,
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
        except CampaignCoreEtagConflict as exc:
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
        operation_id=CAMPAIGN_CORE_STOP_OPERATION_ID,
        name=CAMPAIGN_CORE_STOP_OPERATION_ID,
        response_model=CampaignCoreMutationResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def stop_campaign_core_campaign(
        payload: CampaignCoreRecoveryRequest,
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
        operation_id=CAMPAIGN_CORE_REVOKE_OPERATION_ID,
        name=CAMPAIGN_CORE_REVOKE_OPERATION_ID,
        response_model=CampaignCoreMutationResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def revoke_campaign_core_campaign(
        payload: CampaignCoreRecoveryRequest,
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
