"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiError,
    Request,
    SQLAlchemyError,
    text,
)

def register_foundation_routes(app: APIRouter, dependencies: ApiDependencies) -> None:


    @app.get("/health/live", operation_id="health_live")
    async def live() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready", operation_id="health_ready")
    async def ready(request: Request) -> dict[str, str]:
        factory = request.app.state.session_factory
        expected = request.app.state.expected_revision
        if factory is None:
            raise ApiError(503, "database_not_configured", "Control-plane database is not configured.")
        try:
            async with factory() as session:
                revision = await session.scalar(text("SELECT version_num FROM alembic_version"))
        except (SQLAlchemyError, OSError) as exc:
            raise ApiError(503, "database_unavailable", "The control-plane database is unavailable.") from exc
        if revision != expected:
            raise ApiError(503, "schema_revision_mismatch", "The control-plane schema revision is incompatible.")
        if request.app.state.temporal_required:
            gateway = request.app.state.orchestration_gateway
            if gateway is None or not await gateway.health():
                raise ApiError(503, "workflow_unavailable", "Durable workflow orchestration is unavailable.")
        policy_sdk = request.app.state.policy_sdk
        if request.app.state.policy_required:
            if policy_sdk is None:
                raise ApiError(503, "policy_unavailable", "Policy enforcement is unavailable.")
            await policy_sdk.assess_readiness()
        return {"status": "ready", "revision": str(revision)}
