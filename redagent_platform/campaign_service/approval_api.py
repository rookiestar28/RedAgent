"""Tenant-guarded R172 plan-preview and exact human-decision API boundary."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Callable, Literal

from fastapi import APIRouter, Depends, Header, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from redagent_platform.api.contracts import RequestGuard
from redagent_platform.campaign_service.application_contracts import (
    ApplicationApprovalExpired,
    ApplicationApprovalForbidden,
    ApplicationBindingConflict,
    ApplicationDependencyUnavailable,
    ApplicationIdempotencyConflict,
    ApplicationModeDisabled,
    ApplicationNotFound,
    ApplicationOutcomeError,
    ApplicationPlanInvalid,
    ApplicationPlanUnavailable,
    ApplicationRevisionConflict,
    ApplicationTransitionConflict,
)
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.approval_contracts import (
    PLAN_APPROVE_SCHEMA_VERSION,
    PLAN_DENY_SCHEMA_VERSION,
    ApproveAutonomousCampaignPlanV1,
    AutonomousCampaignApprovalDecisionResultV1,
    AutonomousCampaignPlanPreviewV1,
    DenyAutonomousCampaignPlanV1,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes


_ETAG = re.compile(r'^"r172-([1-9][0-9]*)-([0-9a-f]{64})"$')


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AutonomousCampaignBudgetData(_StrictModel):
    schema_version: Literal["redagent.campaign-budget-vector/v1"]
    duration_seconds: int = Field(ge=0)
    requests: int = Field(ge=0)
    rate_per_minute: int = Field(ge=0)
    concurrency: int = Field(ge=0)
    risk_micropoints: int = Field(ge=0)
    cost_microunits: int = Field(ge=0)
    evidence_bytes: int = Field(ge=0)
    data_bytes: int = Field(ge=0)


class AutonomousCampaignPlanActionData(_StrictModel):
    node_id: str
    order: int = Field(ge=0)
    operator_id: str
    target_id: str
    capability_id: str
    capability_revision: int = Field(ge=1)
    effect_class: str
    executable: bool
    max_duration_seconds: int = Field(ge=0)
    max_requests: int = Field(ge=0)
    max_rate_per_minute: int = Field(ge=0)
    concurrency_weight: int = Field(ge=1)
    max_retries: int = Field(ge=0)
    max_risk_micropoints: int = Field(ge=0)
    max_cost_microunits: int = Field(ge=0)
    max_evidence_bytes: int = Field(ge=0)
    max_data_bytes: int = Field(ge=0)
    cleanup_mode: str


class AutonomousCampaignPlanApproverData(_StrictModel):
    principal_id: str
    role_id: str


class AutonomousCampaignPlanPreviewData(_StrictModel):
    schema_version: Literal["redagent.autonomous-campaign-plan-preview/v1"]
    preview_id: str
    preview_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tenant_id: str
    campaign_id: str
    engagement_id: str
    application_revision: int = Field(ge=1)
    application_intent_sha256: str
    source_binding_sha256: str
    signed_authority_sha256: str
    authority_sha256: str
    domain_sha256: str
    plan_revision_id: str
    plan_revision_sha256: str
    plan_sha256: str
    objective_id: str
    objective_sha256: str
    target_id: str
    capability_ids: tuple[str, ...]
    capability_set_sha256: str
    effect_classes: tuple[str, ...]
    actions: tuple[AutonomousCampaignPlanActionData, ...]
    authorized_budget: AutonomousCampaignBudgetData
    plan_budget: AutonomousCampaignBudgetData
    certificate_sha256: str
    validator_version: str
    validator_sha256: str
    validation_result: Literal["valid"]
    policy_revision: str
    policy_bundle_sha256: str
    lifecycle_epoch: int = Field(ge=0)
    policy_revocation_epoch: int = Field(ge=0)
    roe_revocation_epoch: int = Field(ge=0)
    kill_switch_epoch: int = Field(ge=0)
    required_approvers: tuple[AutonomousCampaignPlanApproverData, ...]
    issued_at: datetime
    expires_at: datetime


class AutonomousCampaignPlanPreviewResponse(_StrictModel):
    data: AutonomousCampaignPlanPreviewData


class AutonomousCampaignApprovalRequest(_StrictModel):
    preview_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    preview_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AutonomousCampaignDenialRequest(AutonomousCampaignApprovalRequest):
    reason_code: str = Field(min_length=1, max_length=150, pattern=r"^[a-z][a-z0-9_:]{0,149}$")


class AutonomousCampaignReadinessData(_StrictModel):
    campaign_id: str
    lifecycle_state: str
    aggregate_revision: int = Field(ge=1)
    plan_ready: bool
    approval_ready: bool
    admission_ready: bool
    start_ready: bool
    unavailable_reason: str


class AutonomousCampaignApprovalDecisionData(_StrictModel):
    receipt_id: str
    receipt_sha256: str
    preview_id: str
    preview_sha256: str
    decision: Literal["approved", "denied"]
    reason_code: str
    application: AutonomousCampaignReadinessData
    replayed: bool


class AutonomousCampaignApprovalDecisionResponse(_StrictModel):
    data: AutonomousCampaignApprovalDecisionData


def _now() -> datetime:
    return datetime.now(timezone.utc)


def register_autonomous_campaign_approval_routes(
    router: APIRouter,
    *,
    require_guard: Callable[..., Callable[..., object]],
    api_error: Callable[[int, str, str], Exception],
) -> None:
    @router.get(
        "/api/v1/autonomous-campaigns/{campaign_id}/plan-preview",
        operation_id="get_autonomous_campaign_plan_preview",
        response_model=AutonomousCampaignPlanPreviewResponse,
    )
    async def get_plan_preview(
        request: Request,
        response: Response,
        campaign_id: str = Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$"),
        guard: RequestGuard = Depends(require_guard("campaign:read")),
    ) -> object:
        try:
            preview = await _service(request, api_error).read_plan_preview(
                tenant_id=guard.security.tenant_id,
                campaign_id=campaign_id,
            )
        except ApplicationOutcomeError as exc:
            _raise_api_error(exc, api_error)
        response.headers["ETag"] = preview.etag
        response.headers["Cache-Control"] = "no-store"
        return {"data": _preview_payload(preview)}

    @router.post(
        "/api/v1/autonomous-campaigns/{campaign_id}/plan-approval",
        operation_id="approve_autonomous_campaign_plan",
        response_model=AutonomousCampaignApprovalDecisionResponse,
    )
    async def approve_plan(
        payload: AutonomousCampaignApprovalRequest,
        request: Request,
        campaign_id: str = Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$"),
        if_match: str = Header(min_length=3, max_length=100, alias="If-Match"),
        guard: RequestGuard = Depends(require_guard("campaign:approve", mutation=True)),
    ) -> object:
        revision = _expected_revision(if_match, payload.preview_sha256, api_error)
        command = ApproveAutonomousCampaignPlanV1(
            schema_version=PLAN_APPROVE_SCHEMA_VERSION,
            tenant_id=guard.security.tenant_id,
            campaign_id=campaign_id,
            preview_id=payload.preview_id,
            preview_sha256=payload.preview_sha256,
            actor_user_id=guard.security.subject,
            actor_permissions=tuple(sorted(guard.security.permissions)),
            expected_revision=revision,
            idempotency_key=str(guard.idempotency_key),
            correlation_id=guard.correlation_id,
            occurred_at=_now(),
        )
        try:
            result = await _service(request, api_error).approve_plan(command)
        except ApplicationOutcomeError as exc:
            _raise_api_error(exc, api_error)
        return {"data": _decision_payload(_service(request, api_error), result)}

    @router.post(
        "/api/v1/autonomous-campaigns/{campaign_id}/plan-denial",
        operation_id="deny_autonomous_campaign_plan",
        response_model=AutonomousCampaignApprovalDecisionResponse,
    )
    async def deny_plan(
        payload: AutonomousCampaignDenialRequest,
        request: Request,
        campaign_id: str = Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$"),
        if_match: str = Header(min_length=3, max_length=100, alias="If-Match"),
        guard: RequestGuard = Depends(require_guard("campaign:approve", mutation=True)),
    ) -> object:
        revision = _expected_revision(if_match, payload.preview_sha256, api_error)
        command = DenyAutonomousCampaignPlanV1(
            schema_version=PLAN_DENY_SCHEMA_VERSION,
            tenant_id=guard.security.tenant_id,
            campaign_id=campaign_id,
            preview_id=payload.preview_id,
            preview_sha256=payload.preview_sha256,
            actor_user_id=guard.security.subject,
            actor_permissions=tuple(sorted(guard.security.permissions)),
            reason_code=payload.reason_code,
            expected_revision=revision,
            idempotency_key=str(guard.idempotency_key),
            correlation_id=guard.correlation_id,
            occurred_at=_now(),
        )
        try:
            result = await _service(request, api_error).deny_plan(command)
        except ApplicationOutcomeError as exc:
            _raise_api_error(exc, api_error)
        return {"data": _decision_payload(_service(request, api_error), result)}


def _service(
    request: Request,
    api_error: Callable[[int, str, str], Exception],
) -> AutonomousCampaignApplicationService:
    service = request.app.state.autonomous_campaign_application_service
    if not isinstance(service, AutonomousCampaignApplicationService):
        raise api_error(503, "autonomous_campaign_not_configured", "Autonomous campaign planning is unavailable.")
    return service


def _expected_revision(
    if_match: str,
    preview_sha256: str,
    api_error: Callable[[int, str, str], Exception],
) -> int:
    match = _ETAG.fullmatch(if_match)
    if match is None or match.group(2) != preview_sha256:
        raise api_error(409, "approval_etag_mismatch", "The plan preview changed; refresh before deciding.")
    return int(match.group(1))


def _preview_payload(preview: AutonomousCampaignPlanPreviewV1) -> dict[str, object]:
    payload = json.loads(canonical_planning_bytes(preview).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("plan_preview_projection_invalid")
    payload["preview_sha256"] = preview.preview_sha256
    return payload


def _decision_payload(
    service: AutonomousCampaignApplicationService,
    result: AutonomousCampaignApprovalDecisionResultV1,
) -> dict[str, object]:
    readiness = service.project(result.application)
    return {
        "receipt_id": result.receipt.receipt_id,
        "receipt_sha256": result.receipt.receipt_sha256,
        "preview_id": result.receipt.preview_id,
        "preview_sha256": result.receipt.preview_sha256,
        "decision": result.receipt.decision.value,
        "reason_code": result.receipt.reason_code,
        "application": {
            "campaign_id": result.application.campaign_id,
            "lifecycle_state": result.application.lifecycle_state.value,
            "aggregate_revision": result.application.aggregate_revision,
            "plan_ready": readiness.plan_ready,
            "approval_ready": readiness.approval_ready,
            "admission_ready": readiness.admission_ready,
            "start_ready": readiness.start_ready,
            "unavailable_reason": readiness.unavailable_reason,
        },
        "replayed": result.replayed,
    }


def _raise_api_error(exc: Exception, api_error: Callable[[int, str, str], Exception]) -> None:
    if isinstance(exc, ApplicationNotFound):
        raise api_error(404, str(exc), "Autonomous campaign was not found.") from exc
    if isinstance(exc, ApplicationPlanUnavailable):
        raise api_error(404, str(exc), "A current plan preview is unavailable.") from exc
    if isinstance(
        exc,
        (
            ApplicationBindingConflict,
            ApplicationIdempotencyConflict,
            ApplicationRevisionConflict,
            ApplicationTransitionConflict,
        ),
    ):
        raise api_error(409, str(exc), "The approval request conflicts with current state.") from exc
    if isinstance(exc, (ApplicationPlanInvalid, ApplicationApprovalExpired)):
        raise api_error(409, str(exc), "The exact plan preview is no longer approvable.") from exc
    if isinstance(exc, ApplicationApprovalForbidden):
        raise api_error(403, str(exc), "The current principal cannot decide this plan.") from exc
    if isinstance(exc, (ApplicationDependencyUnavailable, ApplicationModeDisabled)):
        raise api_error(503, str(exc), "Autonomous campaign planning is unavailable.") from exc
    raise exc
