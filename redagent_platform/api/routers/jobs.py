"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from fastapi import (
    Depends,
    Header,
    Request,
    status,
)
from redagent_platform.api.contracts import (
    ApiError,
    RequestGuard,
    SecurityContext,
)
from redagent_platform.api.router_primitives import (
    _idempotency,
    _list_response,
    _match_roe_reference,
    _mutation_response,
    _now,
    _orchestration,
    _probe_limit,
    _repository,
)
from redagent_platform.api.schemas.common import PaginationQuery
from redagent_platform.api.schemas.jobs import (
    JobCommandResponse,
    JobCreateRequest,
    JobEmergencyStopRequest,
    JobLifecycleCommandRequest,
    JobListResponse,
    JobMutationResponse,
    JobResponse,
    JobStopResponse,
)
from redagent_platform.containment_service.contracts import (
    ControlScope,
    ControlScopeKind,
    StopRequest,
)
from redagent_platform.containment_service.repository import (
    ContainmentRepository,
    ContainmentRepositoryConflict,
)
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CommandAction,
    EmergencyStopSignal,
    JobWorkflowInput,
    OperatorCommand,
    deterministic_job_workflow_id,
)
from redagent_platform.persistence.repository import MutationResult

def register_job_list_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get("/api/v1/jobs", operation_id="list_jobs", response_model=JobListResponse)
    async def list_jobs(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            rows = await _repository(session, guard).list_jobs(
                limit=_probe_limit(query), offset=query.offset
            )
        return _list_response(rows, query)


def register_job_mutation_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    enforce_workflow_boundary = dependencies.enforce_workflow_boundary
    require_guard = dependencies.require_guard
    require_security_context = dependencies.require_security_context
    session_scope = dependencies.session_scope

    async def lifecycle_command_guard(
        payload: JobLifecycleCommandRequest,
        request: Request,
        security: SecurityContext = Depends(require_security_context),
        policy_reference: str | None = Header(default=None, alias="X-RedAgent-Policy-Reference"),
        roe_header: str | None = Header(default=None, alias="X-RedAgent-ROE-Version"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> RequestGuard:
        permission = "job:approve" if payload.action == "approve" else "job:update"
        dependency = require_guard(permission, mutation=True, roe_required=True)
        return await dependency(request, security, policy_reference, roe_header, idempotency_key)

    @app.post(
        "/api/v1/jobs",
        status_code=status.HTTP_201_CREATED,
        operation_id="create_job",
        response_model=JobMutationResponse,
    )
    async def create_job(
        payload: JobCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        _match_roe_reference(guard, payload.roe_version_id)
        async with session_scope(request) as session:
            workflow_id = deterministic_job_workflow_id(guard.security.tenant_id, payload.job_id)
            result = await _repository(session, guard).create_job(
                job_id=payload.job_id,
                engagement_id=payload.engagement_id,
                roe_version_id=payload.roe_version_id,
                request=payload.request.model_dump(),
                workflow_id=workflow_id,
                policy_reference=guard.policy_reference,
                campaign_id=None,
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        await enforce_workflow_boundary(
            request, guard, job_id=payload.job_id, action="job.start",
            job_status=str(result.resource["status"]),
            expected_version=int(result.resource["orchestration_revision"]),
            dispatch_blocked=bool(result.resource["dispatch_blocked"]),
            roe_version_id=payload.roe_version_id,
        )
        reference = await _orchestration(request).start_job(
            JobWorkflowInput(
                CONTRACT_SCHEMA_VERSION,
                guard.security.tenant_id,
                payload.job_id,
                payload.engagement_id,
                payload.roe_version_id,
                guard.policy_reference,
                1,
                payload.request.approval_timeout_seconds,
                payload.request.max_activity_attempts,
                payload.request.capability == "synthetic-conformance",
            )
        )
        if reference.run_id:
            resource = {**result.resource, "workflow_run_id": reference.run_id}
            result = MutationResult(resource, result.replayed, result.audit_id, result.outbox_id)
        return _mutation_response(result)

    @app.get("/api/v1/jobs/{job_id}", operation_id="get_job", response_model=JobResponse)
    async def get_job(
        job_id: str,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:read", roe_required=True)),
    ) -> dict:
        async with session_scope(request) as session:
            resource = await _repository(session, guard).get_job(job_id)
        if resource is None:
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        _match_roe_reference(guard, str(resource["roe_version_id"]))
        return {"data": resource}

    @app.post(
        "/api/v1/jobs/{job_id}/commands",
        operation_id="command_job_lifecycle",
        response_model=JobCommandResponse,
    )
    async def command_job_lifecycle(
        job_id: str,
        payload: JobLifecycleCommandRequest,
        request: Request,
        guard: RequestGuard = Depends(lifecycle_command_guard),
    ) -> dict:
        async with session_scope(request) as session:
            repo = _repository(session, guard)
            existing = await repo.get_job(job_id)
            if existing is None:
                raise ApiError(404, "resource_not_found", "The requested resource was not found.")
            _match_roe_reference(guard, str(existing["roe_version_id"]))
            if payload.action == "approve" and existing["created_by_user_id"] == guard.security.subject:
                raise ApiError(403, "separation_of_duties_required", "A distinct approver is required.")
            workflow_id = str(existing["workflow_id"])
        await enforce_workflow_boundary(
            request, guard, job_id=job_id, action="job.command",
            job_status=str(existing["status"]),
            expected_version=int(existing["orchestration_revision"]),
            dispatch_blocked=bool(existing["dispatch_blocked"]),
            roe_version_id=str(existing["roe_version_id"]),
        )
        command = OperatorCommand(
            CONTRACT_SCHEMA_VERSION,
            payload.command_id,
            CommandAction(payload.action),
            guard.security.subject,
            payload.expected_revision,
            guard.policy_reference,
            payload.reason,
        )
        decision = await _orchestration(request).command_job(workflow_id, command)
        async with session_scope(request) as session:
            resource = await _repository(session, guard).get_job(job_id)
        if resource is None:
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        return {
            "data": resource,
            "meta": {
                "replayed": bool(getattr(decision, "replayed", False)),
                "command_id": payload.command_id,
            },
        }

    @app.post(
        "/api/v1/jobs/{job_id}/emergency-stop",
        operation_id="emergency_stop_job",
        status_code=status.HTTP_202_ACCEPTED,
        response_model=JobStopResponse,
    )
    async def emergency_stop_job(
        job_id: str,
        payload: JobEmergencyStopRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            existing = await _repository(session, guard).get_job(job_id)
        if existing is None:
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        _match_roe_reference(guard, str(existing["roe_version_id"]))
        await enforce_workflow_boundary(
            request, guard, job_id=job_id, action="job.stop",
            job_status=str(existing["status"]),
            expected_version=int(existing["orchestration_revision"]),
            dispatch_blocked=bool(existing["dispatch_blocked"]),
            roe_version_id=str(existing["roe_version_id"]),
        )
        requested_at = _now()
        try:
            async with session_scope(request) as session:
                control = await ContainmentRepository(
                    session,
                    tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                ).request_stop(StopRequest(
                    schema_version="1.0", stop_id=payload.signal_id,
                    tenant_id=guard.security.tenant_id,
                    scope=ControlScope(ControlScopeKind.JOB, job_id),
                    initiated_by=guard.security.subject, reason=payload.reason,
                    requested_at=requested_at, expected_version=1,
                    idempotency_key=payload.signal_id,
                ))
        except ContainmentRepositoryConflict as exc:
            raise ApiError(409, "containment_conflict", str(exc)) from exc
        await _orchestration(request).stop_job(
            str(existing["workflow_id"]),
            EmergencyStopSignal(
                CONTRACT_SCHEMA_VERSION,
                payload.signal_id,
                guard.security.subject,
                guard.policy_reference,
                payload.reason,
                str(control["id"]),
            ),
        )
        return {
            "data": {
                "job_id": job_id,
                "workflow_id": existing["workflow_id"],
                "stop_id": payload.signal_id,
                "control_id": control["id"],
                "state": "stop_requested",
                "containment_complete": False,
                "completion_owner": "R101",
            }
        }
