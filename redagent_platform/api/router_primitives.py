from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from fastapi import Request
from redagent_platform.api.contracts import (
    ApiError,
    RequestGuard,
)
from redagent_platform.api.schemas.common import PaginationQuery
from redagent_platform.orchestration.gateway import TemporalOrchestrationGateway
from redagent_platform.persistence.repository import (
    ControlPlaneRepository,
    MutationResult,
)
from sqlalchemy.ext.asyncio import AsyncSession


def _repository(session: AsyncSession, guard: RequestGuard) -> ControlPlaneRepository:
    return ControlPlaneRepository(
        session,
        tenant_id=guard.security.tenant_id,
        actor_user_id=guard.security.subject,
        correlation_id=guard.correlation_id,
    )


def _orchestration(request: Request) -> TemporalOrchestrationGateway:
    gateway = request.app.state.orchestration_gateway
    if gateway is None:
        raise ApiError(503, "workflow_not_configured", "Durable workflow orchestration is not configured.")
    return gateway


def _idempotency(guard: RequestGuard) -> str:
    if guard.idempotency_key is None:
        raise ApiError(400, "idempotency_key_required", "Idempotency-Key is required for mutations.")
    return guard.idempotency_key


def _match_roe_reference(guard: RequestGuard, expected: str) -> None:
    if guard.roe_version_id != expected:
        raise ApiError(403, "roe_reference_mismatch", "The validated ROE reference does not match the resource.")


def _mutation_response(result: MutationResult) -> dict[str, object]:
    return {
        "data": result.resource,
        "meta": {
            "replayed": result.replayed,
            "audit_id": result.audit_id,
            "outbox_id": result.outbox_id,
        },
    }


def _list_response(rows: list[dict[str, object]], query: PaginationQuery) -> dict[str, object]:
    page_rows = rows[: query.limit]
    has_more = len(rows) > query.limit
    return {
        "data": page_rows,
        "page": {
            "limit": query.limit,
            "offset": query.offset,
            "returned": len(page_rows),
            "next_offset": query.offset + len(page_rows) if has_more else None,
        },
    }


def _probe_limit(query: PaginationQuery) -> int:
    # IMPORTANT: one extra row is an internal bounded continuation probe; never expose it.
    return query.limit + 1


def _now() -> datetime:
    return datetime.now(timezone.utc)
