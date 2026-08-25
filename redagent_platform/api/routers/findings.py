"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    Depends,
    FindingIngestRequest,
    Request,
    RequestGuard,
    _idempotency,
    _mutation_response,
    _now,
    _repository,
    status,
)

def register_finding_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.post(
        "/api/v1/findings/ingest",
        status_code=status.HTTP_201_CREATED,
        operation_id="ingest_finding",
    )
    async def ingest_finding(
        payload: FindingIngestRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("finding:ingest", mutation=True)),
    ) -> dict:
        async with session_scope(request) as session:
            result = await _repository(session, guard).ingest_finding(
                **payload.model_dump(),
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)
