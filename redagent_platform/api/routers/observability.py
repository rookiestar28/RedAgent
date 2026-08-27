"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from fastapi import (
    Depends,
    Request,
)
from redagent_platform.api.contracts import (
    ApiError,
    RequestGuard,
)
from redagent_platform.api.router_primitives import (
    _list_response,
    _now,
    _probe_limit,
)
from redagent_platform.api.schemas.common import PaginationQuery
from redagent_platform.api.schemas.observability import (
    CorrelationEventListResponse,
    IncidentActionRequest,
    IncidentListResponse,
    IncidentResponse,
    IncidentRunbookListResponse,
    IncidentTimelineResponse,
    ObservabilityDashboardResponse,
)
from redagent_platform.telemetry_service.catalog import foundation_runbooks
from redagent_platform.telemetry_service.incidents import IncidentAction
from redagent_platform.telemetry_service.operations import (
    IncidentRepository,
    ObservabilityRepositoryConflict,
    SloRepository,
)
from redagent_platform.telemetry_service.repository import (
    TelemetryRepository,
    TelemetryRepositoryConflict,
)

def _public_incident(row: dict[str, object]) -> dict[str, object]:
    return {
        "incident_id": row["incident_id"], "source_kind": row["source_kind"],
        "source_id": row["source_id"], "severity": row["severity"],
        "state": row["incident_state"], "reason_code": row["reason_code"],
        "opened_by_user_id": row["opened_by_user_id"],
        "assigned_to_user_id": row["assigned_to_user_id"],
        "acknowledged_by_user_id": row["acknowledged_by_user_id"],
        "contained_by_user_id": row["contained_by_user_id"],
        "recovered_by_user_id": row["recovered_by_user_id"],
        "reviewed_by_user_id": row["reviewed_by_user_id"],
        "evidence_preserved": row["evidence_preserved"],
        "containment_verified": row["containment_verified"],
        "opened_at": row["opened_at"], "closed_at": row["closed_at"],
        "version": row["version"],
    }


def _public_incident_timeline(row: dict[str, object]) -> dict[str, object]:
    return {
        "event_id": row["event_id"], "event_type": row["event_type"],
        "actor_user_id": row["actor_user_id"], "reason_code": row["reason_code"],
        "occurred_at": row["occurred_at"],
    }


def _public_correlation_event(row: dict[str, object]) -> dict[str, object]:
    envelope = row["envelope"] if isinstance(row["envelope"], dict) else {}
    return {
        "operation_id": row["operation_id"], "event_id": row["event_id"],
        "correlation_id": envelope.get("correlation_id", "unknown"),
        "signal_kind": row["signal_kind"], "priority": row["priority"],
        "export_state": row["export_state"], "reason_code": row["last_reason_code"],
        "occurred_at": row["occurred_at"],
    }


def register_observability_dashboard_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/observability/dashboard",
        operation_id="get_observability_dashboard",
        response_model=ObservabilityDashboardResponse,
    )
    async def get_observability_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await SloRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).dashboard()
        return {"data": data}


def register_observability_incident_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/observability/correlations/{correlation_id}",
        operation_id="lookup_observability_correlation",
        response_model=CorrelationEventListResponse,
    )
    async def lookup_observability_correlation(
        correlation_id: str,
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                rows = await TelemetryRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).lookup_correlation(
                    correlation_id=correlation_id,
                    limit=_probe_limit(query),
                    offset=query.offset,
                )
        except TelemetryRepositoryConflict as exc:
            raise ApiError(400, "telemetry_lookup_invalid", str(exc)) from exc
        public = [_public_correlation_event(row) for row in rows]
        return _list_response(public, query)

    @app.get(
        "/api/v1/incidents", operation_id="list_incidents", response_model=IncidentListResponse,
    )
    async def list_incidents(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            rows = await IncidentRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).list_incidents(limit=_probe_limit(query), offset=query.offset)
        return _list_response([_public_incident(row) for row in rows], query)

    @app.get(
        "/api/v1/incidents/runbooks",
        operation_id="list_incident_runbooks", response_model=IncidentRunbookListResponse,
    )
    async def list_incident_runbooks(
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        del guard
        return {"data": [
            {
                "runbook_id": item.runbook_id, "owner": item.owner,
                "triage": list(item.triage), "containment": list(item.containment),
                "evidence": list(item.evidence), "recovery": list(item.recovery),
                "review": list(item.review),
            }
            for item in foundation_runbooks()
        ]}

    @app.get(
        "/api/v1/incidents/{incident_id}/timeline",
        operation_id="get_incident_timeline", response_model=IncidentTimelineResponse,
    )
    async def get_incident_timeline(
        incident_id: str,
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                rows = await IncidentRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).timeline(incident_id=incident_id)
        except ObservabilityRepositoryConflict as exc:
            raise ApiError(404, "incident_not_found", str(exc)) from exc
        return {"data": [_public_incident_timeline(row) for row in rows]}

    @app.post(
        "/api/v1/incidents/{incident_id}/actions",
        operation_id="apply_incident_action", response_model=IncidentResponse,
    )
    async def apply_incident_operation(
        incident_id: str,
        payload: IncidentActionRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await IncidentRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).apply_action(
                    incident_id=incident_id, action_id=payload.action_id,
                    action=IncidentAction(payload.action), expected_version=payload.expected_version,
                    occurred_at=_now(), assignee_id=payload.assignee_id,
                )
        except ObservabilityRepositoryConflict as exc:
            raise ApiError(409, "incident_conflict", str(exc)) from exc
        return {"data": _public_incident(row)}
