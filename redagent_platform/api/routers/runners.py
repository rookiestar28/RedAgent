"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    AsyncSession,
    Depends,
    PaginationQuery,
    Request,
    RequestGuard,
    RunnerExecutionListResponse,
    RunnerManifestListResponse,
    RunnerRegistrationListResponse,
    RunnerRepository,
    RunnerStatusResponse,
    _list_response,
    _probe_limit,
)

def _runner_repository(session: AsyncSession, guard: RequestGuard) -> RunnerRepository:
    return RunnerRepository(
        session,
        tenant_id=guard.security.tenant_id,
        actor_user_id=guard.security.subject,
        correlation_id=guard.correlation_id,
    )


def register_runner_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/runners/status",
        operation_id="get_runner_status",
        response_model=RunnerStatusResponse,
    )
    async def get_runner_status(
        request: Request,
        guard: RequestGuard = Depends(require_guard("runner:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            data = await _runner_repository(session, guard).operational_status()
        return {"data": data}

    @app.get(
        "/api/v1/runners/registrations",
        operation_id="list_runner_registrations",
        response_model=RunnerRegistrationListResponse,
    )
    async def list_runner_registrations(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("runner:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            rows = await _runner_repository(session, guard).list_registrations(
                limit=_probe_limit(query), offset=query.offset,
            )
        return _list_response(rows, query)

    @app.get(
        "/api/v1/runner-manifests",
        operation_id="list_runner_manifests",
        response_model=RunnerManifestListResponse,
    )
    async def list_runner_manifests(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("runner:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            rows = await _runner_repository(session, guard).list_manifests(
                limit=_probe_limit(query), offset=query.offset,
            )
        return _list_response(rows, query)

    @app.get(
        "/api/v1/runner-executions",
        operation_id="list_runner_executions",
        response_model=RunnerExecutionListResponse,
    )
    async def list_runner_executions(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("runner:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            rows = await _runner_repository(session, guard).list_executions(
                limit=_probe_limit(query), offset=query.offset,
            )
        return _list_response(rows, query)
