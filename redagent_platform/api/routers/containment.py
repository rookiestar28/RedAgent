"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from fastapi import (
    Depends,
    Request,
    status,
)
from redagent_platform.api.contracts import (
    ApiError,
    RequestGuard,
)
from redagent_platform.api.router_primitives import (
    _idempotency,
    _list_response,
    _now,
    _orchestration,
    _probe_limit,
    _repository,
)
from redagent_platform.api.schemas.common import PaginationQuery
from redagent_platform.api.schemas.containment import (
    ContainmentApprovalRequest,
    ContainmentControlListResponse,
    ContainmentControlResponse,
    ContainmentRecoveryRequest,
    ContainmentStopRequest,
    JobContainmentResponse,
    QuotaStatusResponse,
)
from redagent_platform.containment_service.contracts import (
    ControlScope,
    ControlScopeKind,
    StopApproval,
    StopRequest,
)
from redagent_platform.containment_service.repository import (
    ContainmentRepository,
    ContainmentRepositoryConflict,
)
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    EmergencyStopSignal,
)

async def _signal_containment_jobs(
    request: Request,
    guard: RequestGuard,
    control: dict[str, object],
    reason: str,
) -> int:
    """Signal matching durable jobs after the control transaction is committed."""
    rows: list[dict[str, object]] = []
    offset = 0
    factory = request.app.state.session_factory
    if factory is None:
        raise ApiError(503, "database_not_configured", "Control-plane database is not configured.")
    while offset < 10_000:
        async with factory() as session, session.begin():
            page = await _repository(session, guard).list_jobs(limit=500, offset=offset)
        rows.extend(page)
        if len(page) < 500:
            break
        offset += 500
    if len(rows) == 10_000:
        async with factory() as session, session.begin():
            overflow = await _repository(session, guard).list_jobs(limit=1, offset=10_000)
        if overflow:
            raise ApiError(
                503, "containment_fanout_limit_exceeded",
                "Containment remains active, but workflow fan-out requires operator escalation.",
            )
    scope_kind = str(control["scope_kind"])
    scope_id = control["scope_id"]

    def matches(job: dict[str, object]) -> bool:
        if scope_kind == "global":
            return True
        if scope_kind == "tenant":
            return scope_id == guard.security.tenant_id
        if scope_kind == "job":
            return scope_id == job["job_id"]
        if scope_kind == "campaign":
            return scope_id == job["campaign_id"]
        if scope_kind == "capability":
            request_data = job.get("request")
            return isinstance(request_data, dict) and request_data.get("capability") == scope_id
        return False

    candidates = [
        job for job in rows
        if matches(job) and str(job["orchestration_state"]) not in {"succeeded", "failed", "cancelled"}
    ]
    if not candidates:
        return 0
    gateway = _orchestration(request)
    for job in candidates:
        await gateway.stop_job(
            str(job["workflow_id"]),
            EmergencyStopSignal(
                CONTRACT_SCHEMA_VERSION, str(control["stop_id"]),
                guard.security.subject, str(job["policy_reference"]), reason,
                str(control["control_id"]),
            ),
        )
    return len(candidates)


def register_containment_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/jobs/{job_id}/containment",
        operation_id="get_job_containment",
        response_model=JobContainmentResponse,
    )
    async def get_job_containment(
        job_id: str,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            existing = await _repository(session, guard).get_job(job_id)
            if existing is None:
                raise ApiError(404, "resource_not_found", "The requested resource was not found.")
            resource = await ContainmentRepository(
                session,
                tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject,
                correlation_id=guard.correlation_id,
            ).job_containment_status(job_id)
        if resource is None:
            raise ApiError(404, "containment_not_found", "No containment operation exists for this job.")
        return {"data": resource}

    @app.get(
        "/api/v1/containment-controls",
        operation_id="list_containment_controls",
        response_model=ContainmentControlListResponse,
    )
    async def list_containment_controls(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            rows = await ContainmentRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).list_controls(limit=_probe_limit(query), offset=query.offset)
        return _list_response(rows, query)

    @app.post(
        "/api/v1/containment-controls",
        operation_id="request_containment_control",
        response_model=ContainmentControlResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def request_containment_control(
        payload: ContainmentStopRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard(
            "job:stop", mutation=True, safety_preserving=True,
        )),
    ) -> dict:
        if payload.scope_kind == "tenant" and payload.scope_id != guard.security.tenant_id:
            raise ApiError(403, "containment_scope_mismatch", "Tenant containment may only target the current tenant.")
        stop = StopRequest(
            schema_version="1.0", stop_id=payload.stop_id,
            tenant_id=guard.security.tenant_id,
            scope=ControlScope(ControlScopeKind(payload.scope_kind), payload.scope_id),
            initiated_by=guard.security.subject, reason=payload.reason,
            requested_at=_now(), expected_version=payload.expected_version,
            idempotency_key=_idempotency(guard),
        )
        try:
            async with session_scope(request) as session:
                repository = ContainmentRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                )
                created = await repository.request_stop(stop)
                resource = await repository.get_control(str(created["id"]))
        except ContainmentRepositoryConflict as exc:
            raise ApiError(409, "containment_conflict", str(exc)) from exc
        if resource is None:
            raise ApiError(500, "containment_persistence_failed", "The containment control was not persisted.")
        if resource["control_state"] == "active":
            await _signal_containment_jobs(request, guard, resource, payload.reason)
        return {"data": resource}

    @app.get(
        "/api/v1/containment-controls/{control_id}",
        operation_id="get_containment_control",
        response_model=ContainmentControlResponse,
    )
    async def get_containment_control(
        control_id: str,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            resource = await ContainmentRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).get_control(control_id)
        if resource is None:
            raise ApiError(404, "containment_not_found", "The containment control was not found.")
        return {"data": resource}

    @app.post(
        "/api/v1/containment-controls/{control_id}/approve",
        operation_id="approve_containment_control",
        response_model=ContainmentControlResponse,
    )
    async def approve_containment_control(
        control_id: str,
        payload: ContainmentApprovalRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard(
            "job:approve", mutation=True, safety_preserving=True,
        )),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = ContainmentRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                )
                current = await repository.get_control(control_id)
                if current is None:
                    raise ApiError(404, "containment_not_found", "The containment control was not found.")
                await repository.approve_stop(StopApproval(
                    approval_id=payload.approval_id, stop_id=str(current["stop_id"]),
                    tenant_id=guard.security.tenant_id,
                    approver_user_id=guard.security.subject,
                    request_hash=payload.request_hash, approved_at=_now(),
                    expected_version=payload.expected_version,
                ))
                resource = await repository.get_control(control_id)
        except ContainmentRepositoryConflict as exc:
            raise ApiError(409, "containment_conflict", str(exc)) from exc
        if resource is None:
            raise ApiError(500, "containment_persistence_failed", "The containment approval was not persisted.")
        await _signal_containment_jobs(request, guard, resource, "Approved broad containment activation")
        return {"data": resource}

    @app.post(
        "/api/v1/containment-controls/{control_id}/recover",
        operation_id="recover_containment_control",
        response_model=ContainmentControlResponse,
    )
    async def recover_containment_control(
        control_id: str,
        payload: ContainmentRecoveryRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                resource = await ContainmentRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).recover_control(
                    control_id=control_id, review_id=payload.review_id,
                    expected_version=payload.expected_version, occurred_at=_now(),
                )
        except ContainmentRepositoryConflict as exc:
            raise ApiError(409, "containment_conflict", str(exc)) from exc
        return {"data": resource}


def register_quota_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/quotas/status",
        operation_id="get_quota_status",
        response_model=QuotaStatusResponse,
    )
    async def get_quota_status(
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            rows = await ContainmentRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).quota_status(occurred_at=_now())
        return {"data": rows}
