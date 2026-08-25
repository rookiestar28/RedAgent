"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiError,
    ArtifactAuthorization,
    ArtifactCancelRequest,
    ArtifactCompileRequest,
    ArtifactDashboardResponse,
    ArtifactKind,
    ArtifactPipelineRepository,
    ArtifactPlanResponse,
    ArtifactProfileListResponse,
    ArtifactRepositoryConflict,
    ArtifactRunCreateRequest,
    ArtifactRunResponse,
    Depends,
    Request,
    RequestGuard,
    _match_roe_reference,
    _now,
    certified_artifact_profiles,
    compile_artifact_plan,
    metadata,
    select,
    status,
    timedelta,
)

def _public_artifact_profile(profile) -> dict[str, object]:
    return {"profile_id": profile.profile_id, "artifact_kind": profile.artifact_kind.value,
        "stages": [item.value for item in profile.stages], "max_files": profile.max_files,
        "max_bytes": profile.max_bytes, "max_depth": profile.max_depth,
        "max_expansion_ratio": profile.max_expansion_ratio, "profile_state": "certified-local-lab",
        "zero_execution": True, "production_qualified": False}


def _public_artifact_plan(row: dict[str, object], profile_id: str, artifact_binding_id: str) -> dict[str, object]:
    return {"plan_id": row["plan_id"], "profile_id": profile_id, "artifact_binding_id": artifact_binding_id,
        "policy_decision_id": row["policy_decision_id"], "reservation_id": row["reservation_id"],
        "artifact_lease_id": row["artifact_lease_id"], "plan_sha256": row["plan_sha256"],
        "plan_state": row["plan_state"], "expires_at": row["expires_at"], "version": row["version"]}


def _public_artifact_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {"run_id": row["run_id"], "plan_id": plan_id, "job_id": row["job_id"], "runner_id": row["runner_id"],
        "run_state": row["run_state"], "complete": row["complete"], "partial_reasons": list(row["partial_reasons"]),
        "result_sha256": row["result_sha256"], "untrusted_execution_count": row["untrusted_execution_count"], "version": row["version"]}


def register_artifact_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get("/api/v1/artifact-posture/profiles", operation_id="list_artifact_posture_profiles", response_model=ArtifactProfileListResponse)
    async def list_artifact_posture_profiles(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        return {"data": [_public_artifact_profile(profile) for profile in certified_artifact_profiles().values()]}

    @app.post("/api/v1/artifact-posture/plans", operation_id="compile_artifact_posture_plan", response_model=ArtifactPlanResponse, status_code=status.HTTP_201_CREATED)
    async def create_artifact_posture_plan(
        payload: ArtifactCompileRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        now = _now(); _match_roe_reference(guard, payload.roe_version_id)
        profile = certified_artifact_profiles()[payload.profile_id]
        try:
            async with session_scope(request) as session:
                bindings = metadata.tables["artifact_bindings"]
                binding = (await session.execute(select(bindings).where(
                    bindings.c.tenant_id == guard.security.tenant_id,
                    bindings.c.binding_id == payload.artifact_binding_id,
                    bindings.c.artifact_kind == profile.artifact_kind.value,
                    bindings.c.binding_state == "active-canonical-fixture",
                    bindings.c.expires_at > now,
                ))).mappings().one_or_none()
                decisions = metadata.tables["policy_decisions"]
                decision = (await session.execute(select(decisions.c.id).where(
                    decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id,
                    decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "artifact.plan.compile",
                    decisions.c.resource_type == "artifact_profile",
                    decisions.c.resource_id == payload.profile_id,
                    decisions.c.allowed.is_(True), decisions.c.valid_until > now,
                ))).one_or_none()
                roes = metadata.tables["roe_versions"]
                roe = (await session.execute(select(roes.c.id).where(
                    roes.c.tenant_id == guard.security.tenant_id, roes.c.id == payload.roe_version_id,
                    roes.c.status == "approved",
                ))).one_or_none()
                reservations = metadata.tables["quota_reservations"]
                reservation = (await session.execute(select(reservations).where(
                    reservations.c.tenant_id == guard.security.tenant_id,
                    reservations.c.reservation_id == payload.reservation_id,
                    reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
                    reservations.c.expires_at > now,
                ))).mappings().one_or_none()
                if binding is None:
                    raise ApiError(403, "artifact_binding_required", "An active immutable canonical artifact binding is required.")
                if payload.artifact_lease_id != payload.artifact_binding_id:
                    raise ApiError(403, "artifact_lease_binding_mismatch", "The stored artifact lease must match the immutable binding.")
                if decision is None or roe is None:
                    raise ApiError(403, "artifact_policy_approval_required", "A current profile-bound policy decision and approved ROE are required.")
                if reservation is None:
                    raise ApiError(403, "artifact_quota_reservation_required", "An active quota reservation is required.")
                authorization = ArtifactAuthorization(
                    authorization_id=f"authorization-{payload.plan_id}", policy_decision_id=payload.policy_decision_id,
                    policy_revision=payload.policy_revision, reservation_id=payload.reservation_id,
                    artifact_lease_id=payload.artifact_lease_id, artifact_binding_id=payload.artifact_binding_id,
                    artifact_sha256=str(binding["artifact_sha256"]), artifact_kind=ArtifactKind(str(binding["artifact_kind"])),
                    manifest_sha256=str(binding["manifest_sha256"]), profile_id=payload.profile_id,
                    stage_ids=tuple(item.value for item in profile.stages), approved_at=now,
                    expires_at=min(binding["expires_at"], reservation["expires_at"], now + timedelta(minutes=10)),
                )
                compiled = compile_artifact_plan(profile=profile, authorization=authorization, now=now)
                row = await ArtifactPipelineRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).store_plan(
                    plan_id=payload.plan_id, compiled=compiled, authorization=authorization, occurred_at=now,
                )
        except ArtifactRepositoryConflict as exc:
            raise ApiError(409, "artifact_plan_conflict", str(exc)) from exc
        return {"data": _public_artifact_plan(row, payload.profile_id, payload.artifact_binding_id)}

    @app.post("/api/v1/artifact-posture/runs", operation_id="create_artifact_posture_run", response_model=ArtifactRunResponse, status_code=status.HTTP_202_ACCEPTED)
    async def create_artifact_posture_run(
        payload: ArtifactRunCreateRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await ArtifactPipelineRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).create_run(
                    run_id=payload.run_id, plan_id=payload.plan_id, job_id=payload.job_id,
                    runner_id=payload.runner_id, occurred_at=_now(),
                )
        except ArtifactRepositoryConflict as exc:
            raise ApiError(409, "artifact_run_conflict", str(exc)) from exc
        return {"data": _public_artifact_run(row, payload.plan_id)}

    @app.post("/api/v1/artifact-posture/runs/{run_id}/cancel", operation_id="cancel_artifact_posture_run", response_model=ArtifactRunResponse)
    async def cancel_artifact_posture_run(
        run_id: str, payload: ArtifactCancelRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = ArtifactPipelineRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id)
                row = await repository.request_cancel(run_id=run_id, expected_version=payload.expected_version, occurred_at=_now())
                plans = metadata.tables["artifact_analysis_plans"]
                plan = (await session.execute(select(plans.c.plan_id).where(
                    plans.c.tenant_id == guard.security.tenant_id, plans.c.id == row["plan_record_id"],
                ))).one()
        except ArtifactRepositoryConflict as exc:
            raise ApiError(409, "artifact_cancel_conflict", str(exc)) from exc
        return {"data": _public_artifact_run(row, str(plan.plan_id))}

    @app.get("/api/v1/artifact-posture/dashboard", operation_id="get_artifact_posture_dashboard", response_model=ArtifactDashboardResponse)
    async def get_artifact_posture_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await ArtifactPipelineRepository(session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).dashboard()
        profile_by_record = {str(row["id"]): str(row["profile_id"]) for row in data["profiles"]}
        binding_by_record = {str(row["id"]): str(row["binding_id"]) for row in data["bindings"]}
        plan_by_record = {str(row["id"]): row for row in data["plans"]}
        profiles = certified_artifact_profiles()
        return {"data": {
            "profiles": [_public_artifact_profile(profiles[str(row["profile_id"])]) for row in data["profiles"]],
            "plans": [_public_artifact_plan(row, profile_by_record[str(row["profile_record_id"])], binding_by_record[str(row["binding_record_id"])]) for row in data["plans"]],
            "runs": [_public_artifact_run(row, str(plan_by_record[str(row["plan_record_id"])] ["plan_id"])) for row in data["runs"]],
            "components": data["components"], "vulnerabilities": data["vulnerabilities"],
            "credential_findings": data["credential_findings"], "static_findings": data["static_findings"],
            "mobile": data["mobile"], "cleanups": data["cleanups"],
            "binding_options": [{key: row[key] for key in (
                "binding_id", "artifact_kind", "declared_files", "declared_bytes", "binding_state", "expires_at",
            )} for row in data["binding_options"]],
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
