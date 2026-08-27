"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from fastapi import (
    Depends,
    Request,
)
from redagent_platform.api.contracts import RequestGuard
from redagent_platform.api.schemas.lab import LabDashboardResponse
from redagent_platform.lab_service.repository import LabRepository

def register_lab_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/lab/dashboard",
        operation_id="get_lab_dashboard",
        response_model=LabDashboardResponse,
    )
    async def get_lab_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await LabRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).dashboard()
        bundle = data["bundle"]
        teardown = data["latest_teardown"]
        return {"data": {
            "bundle": None if bundle is None else {key: bundle[key] for key in (
                "bundle_id", "bundle_revision", "fixture_digest", "network_id",
                "bundle_state", "expires_at",
            )},
            "scenarios": [{key: row[key] for key in (
                "run_id", "scenario_id", "scenario_state", "reason_code",
                "current_step", "version",
            )} for row in data["scenarios"]],
            "measurements": [{key: row[key] for key in (
                "measurement_id", "metric_id", "comparison", "observed_millionths",
                "threshold_millionths", "unit", "sample_count", "result_state",
            )} for row in data["measurements"]],
            "latest_teardown": None if teardown is None else {key: teardown[key] for key in (
                "receipt_id", "residual_resource_count", "teardown_complete",
                "inventory_sha256", "completed_at",
            )},
            "emergency_stop_path": "/jobs/{job_id}/emergency-stop",
            "arbitrary_target_input_allowed": False,
        }}
