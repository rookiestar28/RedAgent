"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiError,
    CONTRACT_SCHEMA_VERSION,
    CloudCancelRequest,
    CloudCompileRequest,
    CloudDashboardResponse,
    CloudPlanResponse,
    CloudProfileListResponse,
    CloudRepository,
    CloudRepositoryConflict,
    CloudRunCreateRequest,
    CloudRunResponse,
    CollectionAuthorization,
    Depends,
    EmergencyStopSignal,
    Request,
    RequestGuard,
    _match_roe_reference,
    _now,
    _orchestration,
    compile_collection_plan,
    emulator_profiles,
    metadata,
    select,
    status,
    timedelta,
)

def _public_cloud_profile(profile) -> dict[str, object]:
    return {
        "profile_id": profile.profile_id,
        "provider": profile.provider.value,
        "expected_identity": f"{profile.provider.value}:{profile.expected_identity.tenant}",
        "operations": [
            {
                "operation_id": item.operation_id,
                "action": item.action,
                "resource_scope": item.resource_scope,
                "data_class": item.data_class.value,
                "mutation": False,
            }
            for item in profile.operations
        ],
        "max_api_calls": profile.max_api_calls,
        "max_pages": profile.max_pages,
        "max_resources": profile.max_resources,
        "max_response_bytes": profile.max_response_bytes,
        "profile_state": "certified-local-lab",
        "emulator_only": True,
        "production_qualified": False,
    }


def _public_cloud_plan(
    row: dict[str, object], profile_id: str, identity_binding_id: str
) -> dict[str, object]:
    return {
        "plan_id": row["plan_id"],
        "profile_id": profile_id,
        "identity_binding_id": identity_binding_id,
        "policy_decision_id": row["policy_decision_id"],
        "policy_revision": row["policy_revision"],
        "reservation_id": row["reservation_id"],
        "credential_lease_id": row["credential_lease_id"],
        "plan_sha256": row["plan_sha256"],
        "plan_state": row["plan_state"],
        "expires_at": row["expires_at"],
        "version": row["version"],
    }


def _public_cloud_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {
        "run_id": row["run_id"],
        "plan_id": plan_id,
        "job_id": row["job_id"],
        "runner_id": row["runner_id"],
        "run_state": row["run_state"],
        "complete": row["complete"],
        "partial_reasons": list(row["partial_reasons"]),
        "snapshot_sha256": row["snapshot_sha256"],
        "version": row["version"],
    }


def register_cloud_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/cloud-posture/profiles",
        operation_id="list_cloud_posture_profiles",
        response_model=CloudProfileListResponse,
    )
    async def list_cloud_posture_profiles(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        return {"data": [_public_cloud_profile(profile) for profile in emulator_profiles().values()]}

    @app.post(
        "/api/v1/cloud-posture/plans",
        operation_id="compile_cloud_posture_plan",
        response_model=CloudPlanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_cloud_posture_plan(
        payload: CloudCompileRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        now = _now()
        _match_roe_reference(guard, payload.roe_version_id)
        profiles = {profile.profile_id: profile for profile in emulator_profiles().values()}
        profile = profiles[payload.profile_id]
        try:
            async with session_scope(request) as session:
                bindings = metadata.tables["cloud_identity_bindings"]
                binding = (await session.execute(select(bindings).where(
                    bindings.c.tenant_id == guard.security.tenant_id,
                    bindings.c.binding_id == payload.identity_binding_id,
                    bindings.c.provider == profile.provider.value,
                    bindings.c.expected_tenant == profile.expected_identity.tenant,
                    bindings.c.binding_state == "active-local-emulator",
                ))).mappings().one_or_none()
                decisions = metadata.tables["policy_decisions"]
                decision = (await session.execute(select(decisions.c.id).where(
                    decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id,
                    decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "cloud.plan.compile",
                    decisions.c.resource_type == "cloud_profile",
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
                reservation = (await session.execute(select(reservations).where(
                    reservations.c.tenant_id == guard.security.tenant_id,
                    reservations.c.reservation_id == payload.reservation_id,
                    reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
                    reservations.c.expires_at > now,
                ))).mappings().one_or_none()
                leases = metadata.tables["secret_leases"]
                lease = (await session.execute(select(leases).where(
                    leases.c.tenant_id == guard.security.tenant_id,
                    leases.c.id == payload.credential_lease_id,
                    leases.c.lease_state == "active",
                    leases.c.roe_version_id == payload.roe_version_id,
                    leases.c.expires_at > now,
                    leases.c.revoked_at.is_(None),
                ))).mappings().one_or_none()
                if binding is None:
                    raise ApiError(403, "cloud_identity_binding_required", "An active exact local-emulator identity binding is required.")
                if decision is None or roe is None:
                    raise ApiError(403, "cloud_policy_approval_required", "A current profile-bound policy decision and approved ROE are required.")
                if reservation is None:
                    raise ApiError(403, "cloud_quota_reservation_required", "An active quota reservation is required.")
                if lease is None or lease["permission_digest"] != binding["permission_digest"]:
                    raise ApiError(403, "cloud_read_only_lease_required", "An active exact-permission read-only lease is required.")
                permissions = tuple(str(item) for item in binding["permissions"])
                authorization = CollectionAuthorization(
                    tenant_id=guard.security.tenant_id,
                    policy_decision_id=payload.policy_decision_id,
                    policy_revision=payload.policy_revision,
                    reservation_id=payload.reservation_id,
                    credential_lease_id=payload.credential_lease_id,
                    profile_id=payload.profile_id,
                    effective_permissions=permissions,
                    approved_permissions=permissions,
                    approved_at=now,
                    expires_at=min(lease["expires_at"], reservation["expires_at"], now + timedelta(minutes=10)),
                )
                compiled = compile_collection_plan(profile=profile, authorization=authorization, now=now)
                row = await CloudRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).store_plan(
                    plan_id=payload.plan_id, binding_id=payload.identity_binding_id,
                    compiled=compiled, authorization=authorization,
                    roe_version_id=payload.roe_version_id, occurred_at=now,
                )
        except CloudRepositoryConflict as exc:
            raise ApiError(409, "cloud_plan_conflict", str(exc)) from exc
        return {"data": _public_cloud_plan(row, payload.profile_id, payload.identity_binding_id)}

    @app.post(
        "/api/v1/cloud-posture/runs",
        operation_id="create_cloud_posture_run",
        response_model=CloudRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def create_cloud_posture_run(
        payload: CloudRunCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await CloudRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).create_run(run_id=payload.run_id, plan_id=payload.plan_id, job_id=payload.job_id, runner_id=payload.runner_id, occurred_at=_now())
        except CloudRepositoryConflict as exc:
            raise ApiError(409, "cloud_run_conflict", str(exc)) from exc
        return {"data": _public_cloud_run(row, payload.plan_id)}

    @app.post(
        "/api/v1/cloud-posture/runs/{run_id}/cancel",
        operation_id="cancel_cloud_posture_run",
        response_model=CloudRunResponse,
    )
    async def cancel_cloud_posture_run(
        run_id: str,
        payload: CloudCancelRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = CloudRepository(session, tenant_id=guard.security.tenant_id, actor_user_id=guard.security.subject, correlation_id=guard.correlation_id)
                row = await repository.request_cancel(run_id=run_id, expected_version=payload.expected_version, occurred_at=_now())
                plans = metadata.tables["cloud_collection_plans"]
                plan = (await session.execute(select(plans.c.plan_id).where(plans.c.tenant_id == guard.security.tenant_id, plans.c.id == row["plan_record_id"]))).one()
                jobs = metadata.tables["jobs"]
                job = (await session.execute(select(jobs.c.workflow_id).where(jobs.c.tenant_id == guard.security.tenant_id, jobs.c.id == row["job_id"]))).one_or_none()
            if job is None or not job.workflow_id:
                raise ApiError(503, "cloud_workflow_missing", "The bound durable workflow is unavailable.")
            await _orchestration(request).stop_job(str(job.workflow_id), EmergencyStopSignal(
                CONTRACT_SCHEMA_VERSION, f"cloud-cancel-{run_id}"[:100], guard.security.subject,
                guard.policy_reference, payload.reason,
            ))
        except CloudRepositoryConflict as exc:
            raise ApiError(409, "cloud_cancel_conflict", str(exc)) from exc
        return {"data": _public_cloud_run(row, str(plan.plan_id))}

    @app.get(
        "/api/v1/cloud-posture/dashboard",
        operation_id="get_cloud_posture_dashboard",
        response_model=CloudDashboardResponse,
    )
    async def get_cloud_posture_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await CloudRepository(session, tenant_id=guard.security.tenant_id, actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).dashboard()
        profile_by_record = {str(row["id"]): str(row["profile_id"]) for row in data["profiles"]}
        binding_by_record = {str(row["id"]): str(row["binding_id"]) for row in data["bindings"]}
        plan_by_record = {str(row["id"]): row for row in data["plans"]}
        profiles = {profile.profile_id: profile for profile in emulator_profiles().values()}
        return {"data": {
            "profiles": [_public_cloud_profile(profiles[str(row["profile_id"])]) for row in data["profiles"]],
            "plans": [_public_cloud_plan(row, profile_by_record[str(row["profile_record_id"])], binding_by_record[str(row["identity_binding_id"])]) for row in data["plans"]],
            "runs": [_public_cloud_run(row, str(plan_by_record[str(row["plan_record_id"])] ["plan_id"])) for row in data["runs"]],
            "results": [{key: row[key] for key in ("result_id", "control_pack_id", "check_id", "resource_id", "passed", "severity", "evidence_instance_id")} for row in data["results"]],
            "cleanups": [{key: row[key] for key in ("receipt_id", "lease_revoked", "new_requests_blocked", "residual_resource_count", "completed_at")} for row in data["cleanups"]],
            "identity_options": [{
                "binding_id": row["binding_id"],
                "profile_id": profile_by_record[str(row["profile_record_id"])],
                "provider": row["provider"],
                "expected_identity": f"{row['provider']}:{row['expected_tenant']}",
                "permission_digest": row["permission_digest"],
                "binding_state": row["binding_state"],
            } for row in data["identity_options"]],
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
            "lease_options": [{"lease_id": row["id"], **{key: row[key] for key in (
                "job_id", "roe_version_id", "permission_digest", "lease_state", "expires_at",
            )}} for row in data["lease_options"]],
        }}
