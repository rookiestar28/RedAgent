"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from fastapi import (
    Depends,
    Request,
    Response,
    status,
)
from redagent_platform.api.contracts import (
    ApiError,
    RequestGuard,
)
from redagent_platform.api.router_primitives import (
    _idempotency,
    _list_response,
    _match_roe_reference,
    _mutation_response,
    _now,
    _orchestration,
    _repository,
)
from redagent_platform.api.schemas.campaigns import (
    CampaignCreateRequest,
    CampaignListResponse,
    CampaignMutationResponse,
    CampaignResponse,
)
from redagent_platform.api.schemas.common import PaginationQuery
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CampaignWorkflowInput,
    JobWorkflowInput,
    deterministic_campaign_workflow_id,
)
from redagent_platform.persistence.repository import MutationResult

def register_campaign_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    enforce_workflow_boundary = dependencies.enforce_workflow_boundary
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope
    test_issuer_enabled = dependencies.test_issuer_enabled

    @app.get("/api/v1/campaigns", operation_id="list_campaigns", response_model=CampaignListResponse)
    async def list_campaigns(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("campaign:read")),
    ) -> dict:
        async with session_scope(request) as session:
            rows = await _repository(session, guard).list_campaigns(limit=query.limit, offset=query.offset)
        return _list_response(rows, query)

    @app.post(
        "/api/v1/campaigns",
        operation_id="create_campaign",
        status_code=status.HTTP_201_CREATED,
        response_model=CampaignMutationResponse,
        deprecated=True,
    )
    async def create_campaign(
        payload: CampaignCreateRequest,
        request: Request,
        response: Response,
        guard: RequestGuard = Depends(require_guard("campaign:create", mutation=True, roe_required=True)),
    ) -> dict:
        identity = getattr(request.state, "identity", None)
        service_identity = (
            (identity is not None and not identity.is_browser)
            or (
                test_issuer_enabled
                and guard.security.subject.startswith("service:")
            )
        )
        # CRITICAL: caller-created campaign/job identities are temporary compat_096 M2M recovery only.
        if not service_identity:
            raise ApiError(
                403,
                "m2m_compatibility_required",
                "The caller-ID campaign compatibility path requires a service identity.",
            )
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = "Wed, 23 Sep 2026 00:00:00 GMT"
        response.headers["X-RedAgent-Remove-By"] = "2026-09-23"
        response.headers["X-RedAgent-Compatibility-Path"] = "r096-caller-id-m2m"
        _match_roe_reference(guard, payload.roe_version_id)
        workflow_id = deterministic_campaign_workflow_id(guard.security.tenant_id, payload.campaign_id)
        async with session_scope(request) as session:
            result = await _repository(session, guard).create_campaign(
                campaign_id=payload.campaign_id,
                engagement_id=payload.engagement_id,
                roe_version_id=payload.roe_version_id,
                name=payload.name,
                jobs=[job.model_dump() for job in payload.jobs],
                workflow_id=workflow_id,
                policy_reference=guard.policy_reference,
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        child_inputs = tuple(
            JobWorkflowInput(
                CONTRACT_SCHEMA_VERSION,
                guard.security.tenant_id,
                job.job_id,
                payload.engagement_id,
                payload.roe_version_id,
                guard.policy_reference,
                1,
                job.request.approval_timeout_seconds,
                job.request.max_activity_attempts,
                job.request.capability == "synthetic-conformance",
            )
            for job in payload.jobs
        )
        for child in child_inputs:
            await enforce_workflow_boundary(
                request, guard, job_id=child.job_id, action="job.start",
                job_status="pending", expected_version=child.expected_job_version,
                dispatch_blocked=True, roe_version_id=child.roe_version_id,
            )
        reference = await _orchestration(request).start_campaign(
            CampaignWorkflowInput(
                CONTRACT_SCHEMA_VERSION,
                guard.security.tenant_id,
                payload.campaign_id,
                child_inputs,
            )
        )
        if reference.run_id:
            resource = {**result.resource, "workflow_run_id": reference.run_id}
            result = MutationResult(resource, result.replayed, result.audit_id, result.outbox_id)
        return _mutation_response(result)

    @app.get(
        "/api/v1/campaigns/{campaign_id}",
        operation_id="get_campaign",
        response_model=CampaignResponse,
    )
    async def get_campaign(
        campaign_id: str,
        request: Request,
        guard: RequestGuard = Depends(require_guard("campaign:read", roe_required=True)),
    ) -> dict:
        async with session_scope(request) as session:
            resource = await _repository(session, guard).get_campaign(campaign_id)
        if resource is None:
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        _match_roe_reference(guard, str(resource["roe_version_id"]))
        return {"data": resource}
