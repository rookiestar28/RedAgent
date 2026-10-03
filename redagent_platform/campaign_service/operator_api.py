"""Guarded normal intent and root preparation routes for Campaign Core."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import APIRouter, Depends, Header, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from redagent_platform.api.contracts import RequestGuard
from redagent_platform.campaign_service.api import CampaignCoreStartRequest, CampaignOperationsData
from redagent_platform.campaign_service.application_contracts import ApplicationOutcomeError
from redagent_platform.campaign_service.approval_api import (
    AutonomousCampaignPlanPreviewResponse, AutonomousCampaignPlanPreviewData, _preview_payload, _raise_api_error,
)
from redagent_platform.campaign_service.operator_service import AutonomousCampaignOperatorService
from redagent_platform.campaign_service.service import CampaignCoreService


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AutonomousCampaignOperatorAvailabilityData(_StrictModel):
    canonical_configured: bool
    create_available: bool
    preparation_available: bool
    status_available: bool
    stop_available: bool
    revoke_available: bool
    mode: Literal["disabled", "plan_only", "owned_loopback_auto", "bounded_replan"]
    legacy_available: bool
    reason: str


class AutonomousCampaignOperatorAvailabilityResponse(_StrictModel):
    data: AutonomousCampaignOperatorAvailabilityData


class AutonomousCampaignIntentData(_StrictModel):
    campaign_id: str
    mode: Literal["plan_only", "owned_loopback_auto", "bounded_replan"]
    lifecycle_state: str
    aggregate_revision: int = Field(ge=1)
    etag: str
    replayed: bool


class AutonomousCampaignIntentResponse(_StrictModel):
    data: AutonomousCampaignIntentData


class AutonomousCampaignPrepareRequest(_StrictModel):
    expected_revision: int = Field(ge=1, strict=True)


class AutonomousCampaignOperatorApprovalData(_StrictModel):
    receipt_id: str
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["approved", "denied"]
    reason_code: str
    application_revision: int = Field(ge=1)
    expires_at: datetime
    expired: bool


class AutonomousCampaignOperatorStartData(_StrictModel):
    execution_run_id: str
    admission_receipt_id: str
    reservation_id: str
    state: Literal["start_pending", "execution_queued", "reconciliation_required", "manual_review_required", "failed_before_io"]
    reason_code: str | None


class AutonomousCampaignOperatorResultData(_StrictModel):
    effect_count: int = Field(ge=0, le=100)
    verified_effect_count: int = Field(ge=0, le=100)
    cleanup_state: Literal["not_started", "incomplete", "complete"]
    evidence_state: Literal["not_started", "pending", "retained_pending_verification", "verified", "verification_failed"]
    export_state: Literal["unavailable_without_verified_bundle", "unavailable_export_not_configured"]


class AutonomousCampaignOperatorChildData(_StrictModel):
    replan_sequence: Literal[1]
    parent_execution_run_id: str
    lineage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    preview_id: str


class AutonomousCampaignOperatorStatusData(_StrictModel):
    campaign_id: str
    target_label: str = Field(min_length=1, max_length=600)
    objective_label: str | None = Field(default=None, max_length=200)
    mode: Literal["plan_only", "owned_loopback_auto", "bounded_replan"]
    lifecycle_state: str
    aggregate_revision: int = Field(ge=1)
    etag: str
    roe_version_id: str
    preview: AutonomousCampaignPlanPreviewData | None
    preview_etag: str | None
    approval_etag: str | None
    preview_expired: bool
    approval: AutonomousCampaignOperatorApprovalData | None
    start: AutonomousCampaignOperatorStartData | None
    operations: CampaignOperationsData
    result: AutonomousCampaignOperatorResultData
    child: AutonomousCampaignOperatorChildData | None
    attention: tuple[str, ...] = Field(max_length=100)


class AutonomousCampaignOperatorStatusResponse(_StrictModel):
    data: AutonomousCampaignOperatorStatusData


class AutonomousCampaignOperatorRecoveryRequest(AutonomousCampaignPrepareRequest):
    reason: str = Field(min_length=10, max_length=500)


class AutonomousCampaignOperatorRecoveryData(_StrictModel):
    campaign_id: str
    mode: Literal["plan_only", "owned_loopback_auto", "bounded_replan"]
    lifecycle_state: str
    aggregate_revision: int = Field(ge=1)
    etag: str
    replayed: bool
    action: Literal["stop", "revoke"]
    stop_requested: bool
    signal_status: Literal["not_requested", "acknowledged", "unknown", "not_repeated"]
    execution_run_id: str | None


class AutonomousCampaignOperatorRecoveryResponse(_StrictModel):
    data: AutonomousCampaignOperatorRecoveryData


def application_etag(campaign_id: str, revision: int) -> str:
    return f'"autonomous-{campaign_id}:{revision}"'


def register_autonomous_campaign_operator_routes(
    router: APIRouter, *, require_guard: Callable[..., Callable[..., object]],
    api_error: Callable[[int, str, str], Exception],
) -> None:
    @router.get(
        "/api/v1/campaign-core/operator-availability", operation_id="get_autonomous_campaign_operator_availability",
        response_model=AutonomousCampaignOperatorAvailabilityResponse,
    )
    async def availability(
        request: Request, response: Response,
        guard: RequestGuard = Depends(require_guard("campaign:read", safety_preserving=True)),
    ) -> object:
        del guard
        raw_service = getattr(request.app.state, "autonomous_campaign_operator_service", None)
        service = raw_service if isinstance(raw_service, AutonomousCampaignOperatorService) else None
        configured = service is not None
        core = getattr(request.app.state, "r124_campaign_core_service", None)
        response.headers["Cache-Control"] = "no-store"
        return {"data": {
            "canonical_configured": configured,
            "create_available": service is not None and service.creation_available,
            "preparation_available": service is not None and service.preparation_available,
            "status_available": service is not None and service.status_available,
            "stop_available": service is not None and service.stop_available,
            "revoke_available": service is not None and service.revoke_available,
            "mode": service.mode.value if service is not None else "disabled",
            "legacy_available": isinstance(core, CampaignCoreService) and core.creation_enabled,
            "reason": ("ready" if service is not None and service.creation_available else
                       "operator_creation_unavailable" if configured else "operator_owner_not_configured"),
        }}

    @router.get(
        "/api/v1/autonomous-campaigns/{campaign_id}", operation_id="get_autonomous_campaign_operator_status",
        response_model=AutonomousCampaignOperatorStatusResponse,
    )
    async def current_status(
        request: Request, response: Response,
        campaign_id: str = Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$"),
        guard: RequestGuard = Depends(require_guard("campaign:read", safety_preserving=True)),
    ) -> object:
        try:
            result = await _service(request, api_error).read_status(
                tenant_id=guard.security.tenant_id, campaign_id=campaign_id,
                principal_id=guard.security.subject, now=_now(),
            )
        except (ApplicationOutcomeError, ValueError) as exc:
            _raise_operator_error(exc, api_error)
        response.headers["ETag"] = result["etag"]
        response.headers["Cache-Control"] = "no-store"
        return {"data": result}

    def recovery_route(action: str):
        async def recover(
            payload: AutonomousCampaignOperatorRecoveryRequest, request: Request, response: Response,
            campaign_id: str = Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$"),
            if_match: str = Header(min_length=3, max_length=150, alias="If-Match"),
            guard: RequestGuard = Depends(require_guard(f"campaign:{action}", mutation=True, safety_preserving=True)),
        ) -> object:
            if if_match != application_etag(campaign_id, payload.expected_revision):
                raise api_error(409, "operator_etag_mismatch", "Refresh current campaign state before confirming again.")
            try:
                result = await _service(request, api_error).recover(
                    action=action, reason=payload.reason, tenant_id=guard.security.tenant_id,
                    campaign_id=campaign_id, principal_id=guard.security.subject,
                    expected_revision=payload.expected_revision, idempotency_key=str(guard.idempotency_key),
                    correlation_id=guard.correlation_id, now=_now(),
                )
            except (ApplicationOutcomeError, ValueError) as exc:
                _raise_operator_error(exc, api_error)
            response.headers["ETag"] = str(result["etag"])
            response.headers["Cache-Control"] = "no-store"
            return {"data": result}
        return recover

    for action in ("stop", "revoke"):
        router.add_api_route(
            f"/api/v1/autonomous-campaigns/{{campaign_id}}/{action}", recovery_route(action), methods=["POST"],
            operation_id=f"{action}_autonomous_campaign_operator", response_model=AutonomousCampaignOperatorRecoveryResponse,
            status_code=202,
        )

    @router.post(
        "/api/v1/autonomous-campaigns", operation_id="create_autonomous_campaign_operator_intent",
        response_model=AutonomousCampaignIntentResponse, status_code=201,
    )
    async def create_intent(
        payload: CampaignCoreStartRequest, request: Request, response: Response,
        guard: RequestGuard = Depends(require_guard("campaign:create", mutation=True)),
    ) -> object:
        try:
            result = await _service(request, api_error).create_intent(
                payload, tenant_id=guard.security.tenant_id, principal_id=guard.security.subject,
                idempotency_key=str(guard.idempotency_key), correlation_id=guard.correlation_id, now=_now(),
            )
        except (ApplicationOutcomeError, ValueError) as exc:
            _raise_operator_error(exc, api_error)
        state = result.application
        etag = application_etag(state.campaign_id, state.aggregate_revision)
        response.headers["ETag"] = etag
        response.headers["Cache-Control"] = "no-store"
        return {"data": {
            "campaign_id": state.campaign_id, "mode": state.mode.value,
            "lifecycle_state": state.lifecycle_state.value, "aggregate_revision": state.aggregate_revision,
            "etag": etag, "replayed": result.replayed,
        }}

    @router.post(
        "/api/v1/autonomous-campaigns/{campaign_id}/prepare-plan",
        operation_id="prepare_autonomous_campaign_operator_plan",
        response_model=AutonomousCampaignPlanPreviewResponse, status_code=201,
    )
    async def prepare_plan(
        payload: AutonomousCampaignPrepareRequest, request: Request, response: Response,
        campaign_id: str = Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$"),
        if_match: str = Header(min_length=3, max_length=150, alias="If-Match"),
        guard: RequestGuard = Depends(require_guard("campaign:create", mutation=True)),
    ) -> object:
        if if_match != application_etag(campaign_id, payload.expected_revision):
            raise api_error(409, "operator_etag_mismatch", "Refresh current campaign state before confirming again.")
        try:
            result = await _service(request, api_error).prepare_plan(
                tenant_id=guard.security.tenant_id, campaign_id=campaign_id,
                principal_id=guard.security.subject, expected_revision=payload.expected_revision,
                idempotency_key=str(guard.idempotency_key), correlation_id=guard.correlation_id, now=_now(),
            )
        except (ApplicationOutcomeError, ValueError) as exc:
            _raise_operator_error(exc, api_error)
        response.headers["ETag"] = result.preview.etag
        response.headers["Cache-Control"] = "no-store"
        return {"data": _preview_payload(result.preview)}


def _service(request: Request, api_error: Callable[[int, str, str], Exception]) -> AutonomousCampaignOperatorService:
    service = getattr(request.app.state, "autonomous_campaign_operator_service", None)
    if not isinstance(service, AutonomousCampaignOperatorService):
        raise api_error(503, "operator_owner_not_configured", "The normal operator owner is unavailable.")
    return service


def _raise_operator_error(exc: Exception, api_error: Callable[[int, str, str], Exception]) -> None:
    if isinstance(exc, ApplicationOutcomeError):
        _raise_api_error(exc, api_error)
    if isinstance(exc, ValueError):
        raise api_error(409, "operator_selection_denied", "Current server-owned selections or source are unavailable.") from exc
    raise exc


def _now() -> datetime:
    return datetime.now(timezone.utc)
