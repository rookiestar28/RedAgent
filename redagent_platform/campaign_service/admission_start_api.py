"""Authenticated R173 admission and durable start-intent API boundary."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Callable, Literal

from fastapi import APIRouter, Depends, Header, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from redagent_platform.api.contracts import RequestGuard
from redagent_platform.campaign_service.admission_start_contracts import (
    ADMISSION_START_SCHEMA_VERSION,
    AutonomousCampaignAdmissionStartCommandV1,
    AutonomousCampaignAdmissionStartResultV1,
)
from redagent_platform.campaign_service.admission_start_service import (
    AutonomousCampaignAdmissionStartService,
)
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
    AutonomousCampaignLifecycle,
)


_ETAG = re.compile(r'^"r173-([1-9][0-9]*)-([0-9a-f]{64})"$')


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AutonomousCampaignAdmissionStartRequest(_StrictModel):
    approval_receipt_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    approval_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AutonomousCampaignAdmissionData(_StrictModel):
    receipt_id: str
    receipt_sha256: str
    outcome: Literal["admitted", "denied"]
    reason_code: str
    denial_stage: str | None
    reservation_id: str | None


class AutonomousCampaignStartData(_StrictModel):
    execution_run_id: str | None
    workflow_id: str | None
    workflow_run_id: str | None
    workflow_request_sha256: str | None
    state: str | None
    reason_code: str | None


class AutonomousCampaignAdmissionApplicationData(_StrictModel):
    campaign_id: str
    lifecycle_state: str
    aggregate_revision: int = Field(ge=1)
    admission_ready: bool
    start_ready: bool
    unavailable_reason: str


class AutonomousCampaignAdmissionStartData(_StrictModel):
    approval_receipt_id: str
    approval_receipt_sha256: str
    admission: AutonomousCampaignAdmissionData
    start: AutonomousCampaignStartData
    application: AutonomousCampaignAdmissionApplicationData
    replayed: bool


class AutonomousCampaignAdmissionStartResponse(_StrictModel):
    data: AutonomousCampaignAdmissionStartData


def _now() -> datetime:
    return datetime.now(timezone.utc)


def register_autonomous_campaign_admission_start_routes(
    router: APIRouter,
    *,
    require_guard: Callable[..., Callable[..., object]],
    api_error: Callable[[int, str, str], Exception],
) -> None:
    @router.post(
        "/api/v1/autonomous-campaigns/{campaign_id}/admission-start",
        operation_id="admit_and_queue_autonomous_campaign",
        response_model=AutonomousCampaignAdmissionStartResponse,
    )
    async def admit_and_queue(
        payload: AutonomousCampaignAdmissionStartRequest,
        request: Request,
        response: Response,
        campaign_id: str = Path(
            min_length=1,
            max_length=64,
            pattern=r"^[A-Za-z0-9._:-]+$",
        ),
        if_match: str = Header(min_length=3, max_length=100, alias="If-Match"),
        guard: RequestGuard = Depends(require_guard("campaign:admit", mutation=True)),
    ) -> object:
        revision = _expected_revision(
            if_match,
            payload.approval_receipt_sha256,
            api_error,
        )
        command = AutonomousCampaignAdmissionStartCommandV1(
            schema_version=ADMISSION_START_SCHEMA_VERSION,
            tenant_id=guard.security.tenant_id,
            campaign_id=campaign_id,
            approval_receipt_id=payload.approval_receipt_id,
            approval_receipt_sha256=payload.approval_receipt_sha256,
            actor_user_id=guard.security.subject,
            actor_roles=_actor_roles(request),
            actor_permissions=tuple(sorted(guard.security.permissions)),
            policy_reference=guard.policy_reference,
            expected_revision=revision,
            idempotency_key=str(guard.idempotency_key),
            correlation_id=guard.correlation_id,
            occurred_at=_now(),
        )
        try:
            result = await _service(request, api_error).admit_and_queue(command)
        except ApplicationOutcomeError as exc:
            _raise_api_error(exc, api_error)
        if not isinstance(result, AutonomousCampaignAdmissionStartResultV1):
            raise ValueError("admission_start_result_invalid")
        response.headers["ETag"] = result.etag
        response.headers["Cache-Control"] = "no-store"
        return {"data": _result_payload(result)}


def _service(
    request: Request,
    api_error: Callable[[int, str, str], Exception],
) -> AutonomousCampaignAdmissionStartService:
    service = request.app.state.autonomous_campaign_admission_start_service
    if not isinstance(service, AutonomousCampaignAdmissionStartService):
        raise api_error(
            503,
            "autonomous_campaign_admission_not_configured",
            "Autonomous campaign admission is unavailable.",
        )
    return service


def _expected_revision(
    if_match: str,
    approval_receipt_sha256: str,
    api_error: Callable[[int, str, str], Exception],
) -> int:
    match = _ETAG.fullmatch(if_match)
    if match is None or match.group(2) != approval_receipt_sha256:
        raise api_error(
            409,
            "admission_start_etag_mismatch",
            "The approved campaign changed; refresh before admission.",
        )
    return int(match.group(1))


def _actor_roles(request: Request) -> tuple[str, ...]:
    resolved = getattr(request.state, "identity", None)
    principal = getattr(resolved, "principal", None)
    roles = getattr(principal, "roles", None)
    if roles:
        return tuple(sorted(set(roles)))
    return ("test-operator",)


def _result_payload(
    result: AutonomousCampaignAdmissionStartResultV1,
) -> dict[str, object]:
    lifecycle = result.application.lifecycle_state
    if lifecycle is AutonomousCampaignLifecycle.ADMITTED:
        reason = "start_bridge_pending"
    elif lifecycle is AutonomousCampaignLifecycle.EXECUTION_QUEUED:
        reason = "r174_not_accepted"
    elif lifecycle is AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED:
        reason = result.start_reason_code or "start_outcome_unknown"
    elif lifecycle is AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED:
        reason = result.start_reason_code or "start_binding_manual_review"
    else:
        reason = result.start_reason_code or result.admission_receipt.reason_code
    return {
        "approval_receipt_id": result.approval_receipt_id,
        "approval_receipt_sha256": result.approval_receipt_sha256,
        "admission": {
            "receipt_id": result.admission_receipt.receipt_id,
            "receipt_sha256": result.admission_receipt.receipt_sha256,
            "outcome": result.admission_receipt.outcome.value,
            "reason_code": result.admission_receipt.reason_code,
            "denial_stage": result.admission_receipt.denial_stage,
            "reservation_id": result.admission_receipt.reservation_id,
        },
        "start": {
            "execution_run_id": result.execution_run_id,
            "workflow_id": result.workflow_id,
            "workflow_run_id": result.workflow_run_id,
            "workflow_request_sha256": result.workflow_request_sha256,
            "state": result.start_state.value if result.start_state is not None else None,
            "reason_code": result.start_reason_code,
        },
        "application": {
            "campaign_id": result.application.campaign_id,
            "lifecycle_state": lifecycle.value,
            "aggregate_revision": result.application.aggregate_revision,
            "admission_ready": False,
            "start_ready": False,
            "unavailable_reason": reason,
        },
        "replayed": result.replayed,
    }


def _raise_api_error(
    exc: Exception,
    api_error: Callable[[int, str, str], Exception],
) -> None:
    if isinstance(exc, ApplicationNotFound):
        raise api_error(404, str(exc), "Autonomous campaign was not found.") from exc
    if isinstance(exc, ApplicationApprovalForbidden):
        raise api_error(403, str(exc), "Campaign admission is not permitted.") from exc
    if isinstance(
        exc,
        (
            ApplicationBindingConflict,
            ApplicationIdempotencyConflict,
            ApplicationRevisionConflict,
            ApplicationTransitionConflict,
            ApplicationPlanInvalid,
            ApplicationApprovalExpired,
        ),
    ):
        raise api_error(
            409,
            str(exc),
            "The admission request conflicts with current campaign authority.",
        ) from exc
    if isinstance(
        exc,
        (
            ApplicationDependencyUnavailable,
            ApplicationModeDisabled,
            ApplicationPlanUnavailable,
        ),
    ):
        raise api_error(503, str(exc), "Autonomous campaign admission is unavailable.") from exc
    raise exc
