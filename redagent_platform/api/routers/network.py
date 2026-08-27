"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from datetime import timedelta
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
    _match_roe_reference,
    _now,
    _orchestration,
)
from redagent_platform.api.schemas.network import (
    NetworkCancelRequest,
    NetworkCompileRequest,
    NetworkDashboardResponse,
    NetworkPlanResponse,
    NetworkProfileListResponse,
    NetworkRunCreateRequest,
    NetworkRunResponse,
)
from redagent_platform.network_service.compiler import compile_network_plan
from redagent_platform.network_service.contracts import (
    NetworkAuthorization,
    NetworkProfileId,
    NetworkProtocol,
    NetworkTargetBinding,
    certified_profiles as certified_network_profiles,
)
from redagent_platform.network_service.repository import (
    NetworkRepository,
    NetworkRepositoryConflict,
)
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    EmergencyStopSignal,
)
from redagent_platform.persistence.models import metadata
from sqlalchemy import select

def _public_network_profile(profile) -> dict[str, object]:
    return {
        "profile_id": profile.profile_id.value,
        "profile_revision": 1,
        "engine_id": "redagent-stdlib-tcp-connect",
        "category": "low-risk-connect-discovery",
        "max_targets": profile.max_targets,
        "max_ports_per_target": profile.max_ports_per_target,
        "max_attempts": profile.max_attempts,
        "rate_per_second": profile.rate_per_second,
        "concurrency_limit": profile.concurrency,
        "max_retries": profile.max_retries,
        "connect_timeout_seconds": profile.connect_timeout_seconds,
        "run_timeout_seconds": profile.run_timeout_seconds,
        "banner_bytes": profile.banner_bytes,
        "output_bytes": profile.output_bytes,
        "profile_state": "certified-local-lab",
        "production_qualified": False,
    }


def _public_network_plan(
    row: dict[str, object],
    profile_id: str,
    target_set_id: str,
    *,
    tuple_count: int | None = None,
) -> dict[str, object]:
    budgets = row["budgets"]
    if not isinstance(budgets, dict):
        budgets = {}
    return {
        "plan_id": row["plan_id"],
        "profile_id": profile_id,
        "target_set_id": target_set_id,
        "policy_decision_id": row["policy_decision_id"],
        "policy_revision": row["policy_revision"],
        "roe_version_id": row["roe_version_id"],
        "reservation_id": row["reservation_id"],
        "plan_sha256": row["plan_sha256"],
        "tuple_count": tuple_count if tuple_count is not None else int(budgets.get("attempts", 0)),
        "budgets": {str(key): int(value) for key, value in budgets.items()},
        "plan_state": row["plan_state"],
        "expires_at": row["expires_at"],
        "version": row["version"],
    }


def _public_network_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {
        "run_id": row["run_id"],
        "plan_id": plan_id,
        "job_id": row["job_id"],
        "runner_id": row["runner_id"],
        "run_state": row["run_state"],
        "completed_tuples": row["completed_tuples"],
        "total_tuples": row["total_tuples"],
        "partial": row["partial"],
        "reason_code": row["reason_code"],
        "version": row["version"],
    }


def register_network_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/network-assessment/profiles",
        operation_id="list_network_assessment_profiles",
        response_model=NetworkProfileListResponse,
    )
    async def list_network_assessment_profiles(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        return {"data": [_public_network_profile(profile) for profile in certified_network_profiles().values()]}

    @app.post(
        "/api/v1/network-assessment/plans",
        operation_id="compile_network_assessment_plan",
        response_model=NetworkPlanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_network_assessment_plan(
        payload: NetworkCompileRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        now = _now()
        _match_roe_reference(guard, payload.roe_version_id)
        profile_id = NetworkProfileId(payload.profile_id)
        try:
            async with session_scope(request) as session:
                targets = metadata.tables["network_target_sets"]
                topologies = metadata.tables["network_topology_attestations"]
                target_row = (await session.execute(select(
                    targets.c.id,
                    targets.c.target_set_id,
                    targets.c.literal_targets,
                    targets.c.allowed_ports,
                    targets.c.protocol,
                    topologies.c.topology_sha256,
                    topologies.c.route_sha256,
                    topologies.c.network_id,
                    topologies.c.non_production,
                    topologies.c.created_at.label("topology_issued_at"),
                    topologies.c.expires_at,
                ).join(topologies, targets.c.topology_record_id == topologies.c.id).where(
                    targets.c.tenant_id == guard.security.tenant_id,
                    targets.c.target_set_id == payload.target_set_id,
                    targets.c.target_set_state == "active-local-lab",
                    topologies.c.tenant_id == guard.security.tenant_id,
                    topologies.c.network_id == "redagent-r107-gateway-target",
                    topologies.c.non_production.is_(True),
                    topologies.c.no_public_route.is_(True),
                    topologies.c.no_direct_target_route.is_(True),
                    topologies.c.expires_at > now,
                ))).mappings().one_or_none()
                decisions = metadata.tables["policy_decisions"]
                decision = (await session.execute(select(decisions.c.id).where(
                    decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id,
                    decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "network.plan.compile",
                    decisions.c.resource_type == "network_profile",
                    decisions.c.resource_id == payload.profile_id,
                    decisions.c.allowed.is_(True),
                    decisions.c.valid_until > now,
                ))).one_or_none()
                roes = metadata.tables["roe_versions"]
                roe = (await session.execute(select(roes.c.id).where(
                    roes.c.tenant_id == guard.security.tenant_id,
                    roes.c.id == payload.roe_version_id,
                    roes.c.status == "approved",
                ))).one_or_none()
                reservations = metadata.tables["quota_reservations"]
                reservation = (await session.execute(select(reservations.c.id).where(
                    reservations.c.tenant_id == guard.security.tenant_id,
                    reservations.c.reservation_id == payload.reservation_id,
                    reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
                    reservations.c.expires_at > now,
                ))).one_or_none()
                if target_row is None:
                    raise ApiError(403, "network_target_attestation_required", "An active isolated target set is required.")
                if decision is None:
                    raise ApiError(403, "network_policy_decision_required", "A current profile-bound policy decision is required.")
                if roe is None:
                    raise ApiError(403, "network_roe_approval_required", "An approved ROE version is required.")
                if reservation is None:
                    raise ApiError(403, "network_quota_reservation_required", "An active quota reservation is required.")
                target = NetworkTargetBinding(
                    target_set_id=str(target_row["target_set_id"]),
                    topology_sha256=str(target_row["topology_sha256"]),
                    route_sha256=str(target_row["route_sha256"]),
                    literal_targets=tuple(str(item) for item in target_row["literal_targets"]),
                    allowed_ports=tuple(int(item) for item in target_row["allowed_ports"]),
                    protocol=NetworkProtocol(str(target_row["protocol"])),
                    network_id=str(target_row["network_id"]),
                    non_production=bool(target_row["non_production"]),
                    issued_at=target_row["topology_issued_at"],
                    expires_at=target_row["expires_at"],
                )
                authorization = NetworkAuthorization(
                    tenant_id=guard.security.tenant_id,
                    policy_decision_id=payload.policy_decision_id,
                    policy_revision=payload.policy_revision,
                    roe_version_id=payload.roe_version_id,
                    reservation_id=payload.reservation_id,
                    topology_sha256=target.topology_sha256,
                    approved_profile_ids=(profile_id,),
                    approved_at=now,
                    expires_at=min(target.expires_at, now + timedelta(minutes=10)),
                )
                compiled = compile_network_plan(
                    profile_id=profile_id,
                    authorization=authorization,
                    target_binding=target,
                    now=now,
                )
                row = await NetworkRepository(
                    session,
                    tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                ).store_plan(
                    plan_id=payload.plan_id,
                    compiled=compiled,
                    target=target,
                    authorization=authorization,
                    occurred_at=now,
                )
        except NetworkRepositoryConflict as exc:
            raise ApiError(409, "network_plan_conflict", str(exc)) from exc
        return {"data": _public_network_plan(row, payload.profile_id, payload.target_set_id)}

    @app.post(
        "/api/v1/network-assessment/runs",
        operation_id="create_network_assessment_run",
        response_model=NetworkRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def create_network_assessment_run(
        payload: NetworkRunCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await NetworkRepository(
                    session,
                    tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                ).create_run(
                    run_id=payload.run_id,
                    plan_id=payload.plan_id,
                    job_id=payload.job_id,
                    runner_id=payload.runner_id,
                    occurred_at=_now(),
                )
        except NetworkRepositoryConflict as exc:
            raise ApiError(409, "network_run_conflict", str(exc)) from exc
        return {"data": _public_network_run(row, payload.plan_id)}

    @app.post(
        "/api/v1/network-assessment/runs/{run_id}/cancel",
        operation_id="cancel_network_assessment_run",
        response_model=NetworkRunResponse,
    )
    async def cancel_network_assessment_run(
        run_id: str,
        payload: NetworkCancelRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = NetworkRepository(
                    session,
                    tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                )
                row = await repository.request_cancel(
                    run_id=run_id,
                    expected_version=payload.expected_version,
                    occurred_at=_now(),
                )
                plans = metadata.tables["network_plans"]
                plan = (await session.execute(select(plans.c.plan_id).where(
                    plans.c.tenant_id == guard.security.tenant_id,
                    plans.c.id == row["plan_record_id"],
                ))).one()
                jobs = metadata.tables["jobs"]
                job = (await session.execute(select(jobs.c.workflow_id).where(
                    jobs.c.tenant_id == guard.security.tenant_id,
                    jobs.c.id == row["job_id"],
                ))).one_or_none()
            if job is None or not job.workflow_id:
                raise ApiError(503, "network_workflow_missing", "The bound durable workflow is unavailable.")
            await _orchestration(request).stop_job(
                str(job.workflow_id),
                EmergencyStopSignal(
                    CONTRACT_SCHEMA_VERSION,
                    f"network-cancel-{run_id}"[:100],
                    guard.security.subject,
                    guard.policy_reference,
                    payload.reason,
                ),
            )
        except NetworkRepositoryConflict as exc:
            raise ApiError(409, "network_cancel_conflict", str(exc)) from exc
        return {"data": _public_network_run(row, str(plan.plan_id))}

    @app.get(
        "/api/v1/network-assessment/dashboard",
        operation_id="get_network_assessment_dashboard",
        response_model=NetworkDashboardResponse,
    )
    async def get_network_assessment_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await NetworkRepository(
                session,
                tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject,
                correlation_id=guard.correlation_id,
            ).dashboard()
            target_sets = metadata.tables["network_target_sets"]
            target_rows = (await session.execute(select(
                target_sets.c.id, target_sets.c.target_set_id,
            ).where(target_sets.c.tenant_id == guard.security.tenant_id))).all()
            tuples = metadata.tables["network_plan_tuples"]
            tuple_rows = (await session.execute(select(
                tuples.c.plan_record_id, tuples.c.id,
            ).where(tuples.c.tenant_id == guard.security.tenant_id))).all()
        target_by_record = {str(item.id): str(item.target_set_id) for item in target_rows}
        tuple_count: dict[str, int] = {}
        for item in tuple_rows:
            tuple_count[str(item.plan_record_id)] = tuple_count.get(str(item.plan_record_id), 0) + 1
        plan_by_record = {str(row["id"]): row for row in data["plans"]}
        return {"data": {
            "profiles": [_public_network_profile(certified_network_profiles()[NetworkProfileId(str(row["profile_id"]))]) for row in data["profiles"]],
            "plans": [_public_network_plan(
                row,
                "tcp-connect-discovery-v1",
                target_by_record[str(row["target_set_record_id"])],
                tuple_count=tuple_count.get(str(row["id"]), 0),
            ) for row in data["plans"]],
            "runs": [_public_network_run(
                row,
                str(plan_by_record[str(row["plan_record_id"])]["plan_id"]),
            ) for row in data["runs"]],
            "observations": [{key: row[key] for key in (
                "observation_id", "tuple_id", "connection_state", "latency_bucket",
                "service_class", "sample_sha256", "uncertainty", "redaction_state",
                "evidence_instance_id",
            )} for row in data["observations"]],
            "cleanups": [{key: row[key] for key in (
                "receipt_id", "residual_resource_count", "completed_at",
            )} for row in data["cleanups"]],
            "target_options": [{key: row[key] for key in (
                "target_set_id", "target_set_state", "non_production", "no_public_route",
                "no_direct_target_route", "expires_at",
            )} for row in data["target_options"]],
            "runner_options": [{key: row[key] for key in (
                "runner_id", "environment", "network_plane", "required_policy_revision",
                "registration_state", "expires_at",
            )} for row in data["runner_options"]],
            "job_options": [{"job_id": row["id"], **{key: row[key] for key in (
                "engagement_id", "roe_version_id", "status", "current_gate", "dispatch_blocked", "stop_requested",
            )}} for row in data["job_options"]],
            "reservation_options": [{
                **{key: row[key] for key in (
                    "reservation_id", "reserved_amount", "consumed_amount", "released_amount",
                    "reservation_state", "expires_at",
                )},
                "remaining_amount": int(row["reserved_amount"]) - int(row["consumed_amount"]) - int(row["released_amount"]),
            } for row in data["reservation_options"]],
        }}
