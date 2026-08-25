"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiError,
    CONTRACT_SCHEMA_VERSION,
    CertifiedProfileId,
    Depends,
    EmergencyStopSignal,
    Request,
    RequestGuard,
    ZapAuthorization,
    ZapCancelRequest,
    ZapCompileRequest,
    ZapDashboardResponse,
    ZapPlanResponse,
    ZapProfileListResponse,
    ZapRepository,
    ZapRepositoryConflict,
    ZapRunCreateRequest,
    ZapRunResponse,
    ZapTargetBinding,
    _now,
    _orchestration,
    certified_profiles,
    compile_zap_plan,
    metadata,
    profile_values,
    select,
    status,
    timedelta,
)

def _public_zap_profile(row: dict[str, object]) -> dict[str, object]:
    return {key: row[key] for key in (
        "profile_id", "profile_revision", "image_version", "image_digest",
        "addon_inventory_sha256", "profile_sha256", "risk_class",
        "passive_rule_ids", "active_rule_ids", "request_limit",
        "request_rate_per_second", "concurrency_limit", "timeout_seconds",
        "response_bytes_limit", "profile_state",
    )}


def _public_zap_plan(row: dict[str, object], profile_id: str) -> dict[str, object]:
    return {
        "plan_id": row["plan_id"], "profile_id": profile_id,
        **{key: row[key] for key in (
            "target_id", "policy_decision_id", "roe_version_id",
            "plan_sha256", "scope_sha256", "expires_at", "version",
        )},
    }


def _public_zap_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {
        "run_id": row["run_id"], "plan_id": plan_id,
        **{key: row[key] for key in (
            "job_id", "runner_id", "run_state", "current_step",
            "progress_percent", "passive_queue_size", "reason_code", "version",
        )},
    }


def register_zap_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/zap/profiles",
        operation_id="list_zap_profiles",
        response_model=ZapProfileListResponse,
    )
    async def list_zap_profiles(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        return {"data": [profile_values(profile) for profile in certified_profiles().values()]}

    @app.post(
        "/api/v1/zap/plans",
        operation_id="compile_zap_plan",
        response_model=ZapPlanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_zap_plan(
        payload: ZapCompileRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        now = _now()
        profile_id = CertifiedProfileId(payload.profile_id)
        profile = certified_profiles()[profile_id]
        target = ZapTargetBinding(
            target_id=payload.target_id,
            attestation_sha256=payload.target_attestation_sha256,
            endpoint="http://redagent-r104-gateway:8080",
            allowed_paths=profile.allowed_paths,
            network_id="redagent-r104-gateway-target",
            non_production=True,
            issued_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        authorization = ZapAuthorization(
            tenant_id=guard.security.tenant_id,
            policy_decision_id=payload.policy_decision_id,
            policy_revision=payload.policy_revision,
            roe_version_id=payload.roe_version_id,
            approval_class=profile.approval_class,
            approved_profile_ids=(profile_id,),
            credential_reference_ids=tuple(payload.credential_reference_ids),
            approved_at=now,
            expires_at=now + timedelta(minutes=10),
        )
        compiled = compile_zap_plan(
            profile_id=profile_id, target=target, authorization=authorization, now=now,
        )
        try:
            async with session_scope(request) as session:
                decisions = metadata.tables["policy_decisions"]
                target_attestations = metadata.tables["zap_target_attestations"]
                attestation = (await session.execute(select(target_attestations.c.id).where(
                    target_attestations.c.tenant_id == guard.security.tenant_id,
                    target_attestations.c.target_id == payload.target_id,
                    target_attestations.c.attestation_sha256 == payload.target_attestation_sha256,
                    target_attestations.c.network_id == "redagent-r104-gateway-target",
                    target_attestations.c.non_production.is_(True),
                    target_attestations.c.attestation_state == "active",
                    target_attestations.c.issued_at <= now,
                    target_attestations.c.expires_at > now,
                ))).one_or_none()
                decision = (await session.execute(select(decisions).where(
                    decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id,
                    decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "zap.plan.compile",
                    decisions.c.resource_type == "zap_profile",
                    decisions.c.resource_id == payload.profile_id,
                    decisions.c.allowed.is_(True),
                    decisions.c.valid_until > now,
                ))).mappings().one_or_none()
                roes = metadata.tables["roe_versions"]
                roe = (await session.execute(select(roes.c.id).where(
                    roes.c.tenant_id == guard.security.tenant_id,
                    roes.c.id == payload.roe_version_id,
                    roes.c.status == "approved",
                ))).one_or_none()
                if attestation is None:
                    raise ApiError(403, "zap_target_attestation_required", "An active owned-fixture attestation is required.")
                if decision is None:
                    raise ApiError(403, "zap_policy_decision_required", "A current profile-bound policy decision is required.")
                if roe is None:
                    raise ApiError(403, "zap_roe_approval_required", "An approved ROE version is required.")
                row = await ZapRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).store_plan(
                    plan_id=payload.plan_id, compiled=compiled, target=target,
                    authorization=authorization, occurred_at=now,
                )
        except ZapRepositoryConflict as exc:
            raise ApiError(409, "zap_plan_conflict", str(exc)) from exc
        return {"data": _public_zap_plan(row, payload.profile_id)}

    @app.post(
        "/api/v1/zap/runs",
        operation_id="create_zap_run",
        response_model=ZapRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def create_zap_run(
        payload: ZapRunCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await ZapRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).create_run(
                    run_id=payload.run_id, plan_id=payload.plan_id,
                    job_id=payload.job_id, runner_id=payload.runner_id, occurred_at=_now(),
                )
                plan_id = payload.plan_id
        except ZapRepositoryConflict as exc:
            raise ApiError(409, "zap_run_conflict", str(exc)) from exc
        return {"data": _public_zap_run(row, plan_id)}

    @app.post(
        "/api/v1/zap/runs/{run_id}/cancel",
        operation_id="cancel_zap_run",
        response_model=ZapRunResponse,
    )
    async def cancel_zap_run(
        run_id: str,
        payload: ZapCancelRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = ZapRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                )
                row = await repository.request_cancel(
                    run_id=run_id, expected_version=payload.expected_version,
                    reason_code="operator_cancel_requested", occurred_at=_now(),
                )
                plans = metadata.tables["zap_compiled_plans"]
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
                raise ApiError(503, "zap_workflow_missing", "The bound durable workflow is unavailable.")
            await _orchestration(request).stop_job(
                str(job.workflow_id),
                EmergencyStopSignal(
                    CONTRACT_SCHEMA_VERSION, f"zap-cancel-{run_id}"[:100],
                    guard.security.subject, guard.policy_reference, payload.reason,
                ),
            )
        except ZapRepositoryConflict as exc:
            raise ApiError(409, "zap_cancel_conflict", str(exc)) from exc
        return {"data": _public_zap_run(row, str(plan.plan_id))}

    @app.get(
        "/api/v1/zap/dashboard",
        operation_id="get_zap_dashboard",
        response_model=ZapDashboardResponse,
    )
    async def get_zap_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await ZapRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).dashboard()
        profile_by_record = {row["id"]: row["profile_id"] for row in data["profiles"]}
        plan_by_record = {row["id"]: row for row in data["plans"]}
        return {"data": {
            "profiles": [_public_zap_profile(row) for row in data["profiles"]],
            "plans": [_public_zap_plan(row, str(profile_by_record[row["profile_record_id"]])) for row in data["plans"]],
            "runs": [_public_zap_run(row, str(plan_by_record[row["plan_record_id"]]["plan_id"])) for row in data["runs"]],
            "cleanups": [{key: row[key] for key in (
                "receipt_id", "residual_resource_count", "cleanup_complete", "completed_at",
            )} for row in data["cleanups"]],
            "target_options": [{key: row[key] for key in (
                "target_id", "attestation_sha256", "attestation_state", "non_production", "expires_at",
            )} for row in data["target_options"]],
            "runner_options": [{key: row[key] for key in (
                "runner_id", "environment", "network_plane", "registration_state", "expires_at",
            )} for row in data["runner_options"]],
        }}
