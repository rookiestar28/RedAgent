"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiDifferentialAuthorization,
    ApiDifferentialCancelRequest,
    ApiDifferentialCompileRequest,
    ApiDifferentialDashboardResponse,
    ApiDifferentialPlanResponse,
    ApiDifferentialProfileId,
    ApiDifferentialProfileListResponse,
    ApiDifferentialRepository,
    ApiDifferentialRepositoryConflict,
    ApiDifferentialRunCreateRequest,
    ApiDifferentialRunResponse,
    ApiDifferentialTargetBinding,
    ApiError,
    CONTRACT_SCHEMA_VERSION,
    Depends,
    EXPECTED_WHEEL_SHA256,
    EmergencyStopSignal,
    IdentityState,
    Path,
    Request,
    RequestGuard,
    _match_roe_reference,
    _now,
    _orchestration,
    certified_api_differential_profiles,
    compile_differential_plan,
    datetime,
    metadata,
    select,
    status,
    timedelta,
    verify_api_differential_promotion,
)

# IMPORTANT: router modules are one level below api; promotion assets remain workspace-relative.
def _public_api_differential_profile_static(profile, snapshot) -> dict[str, object]:
    return {
        "profile_id": profile.profile_id.value, "profile_revision": 1,
        "engine_version": profile.engine_version,
        "artifact_digest": f"sha256:{EXPECTED_WHEEL_SHA256}",
        "bundle_id": "r106-owned-api-differential", "spec_sha256": snapshot.spec_sha256,
        "operation_ids": list(snapshot.operation_ids),
        "identity_states": [state.value for state in IdentityState],
        "max_requests": profile.max_requests,
        "request_rate_per_second": profile.request_rate_per_second,
        "concurrency_limit": profile.concurrency, "timeout_seconds": profile.timeout_seconds,
        "total_data_bytes": profile.total_data_bytes,
        "profile_state": "certified-local-lab", "production_qualified": False,
    }


def _public_api_differential_profile(row: dict[str, object], snapshot) -> dict[str, object]:
    profile = certified_api_differential_profiles()[ApiDifferentialProfileId(str(row["profile_id"]))]
    public = _public_api_differential_profile_static(profile, snapshot)
    public["profile_revision"] = row["profile_revision"]
    return public


def _public_api_differential_plan(
    row: dict[str, object], profile_id: str, target_id: str,
) -> dict[str, object]:
    compiled = row["compiled_plan"]
    case_count = len(compiled.get("cases", [])) if isinstance(compiled, dict) else 0
    return {
        "plan_id": row["plan_id"], "profile_id": profile_id, "target_id": target_id,
        "policy_decision_id": row["policy_decision_id"],
        "policy_revision": compiled["policy_revision"], "roe_version_id": row["roe_version_id"],
        "spec_sha256": row["spec_sha256"], "plan_sha256": row["plan_sha256"],
        "seed": row["seed"], "case_count": case_count,
        "expires_at": row["expires_at"], "version": row["version"],
    }


def _public_api_differential_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {
        "run_id": row["run_id"], "plan_id": plan_id,
        **{key: row[key] for key in (
            "job_id", "runner_id", "run_state", "progress_percent", "request_count",
            "response_bytes", "finding_count", "reason_code", "version",
        )},
    }


def _require_r106_promotion(now: datetime):
    try:
        return verify_api_differential_promotion(Path(__file__).resolve().parents[3], now=now)
    except (OSError, ValueError) as exc:
        raise ApiError(
            503, "api_diff_supply_chain_unavailable", "The signed API differential bundle is unavailable.",
        ) from exc


def register_api_differential_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/api-differential/profiles",
        operation_id="list_api_differential_profiles",
        response_model=ApiDifferentialProfileListResponse,
    )
    async def list_api_differential_profiles(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        _, snapshot, _, _ = _require_r106_promotion(_now())
        return {"data": [
            _public_api_differential_profile_static(profile, snapshot)
            for profile in certified_api_differential_profiles().values()
        ]}

    @app.post(
        "/api/v1/api-differential/plans",
        operation_id="compile_api_differential_plan",
        response_model=ApiDifferentialPlanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_api_differential_plan(
        payload: ApiDifferentialCompileRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        now = _now()
        _match_roe_reference(guard, payload.roe_version_id)
        _, snapshot, _, _ = _require_r106_promotion(now)
        profile_id = ApiDifferentialProfileId(payload.profile_id)
        authorization = ApiDifferentialAuthorization(
            tenant_id=guard.security.tenant_id, policy_decision_id=payload.policy_decision_id,
            policy_revision=payload.policy_revision, roe_version_id=payload.roe_version_id,
            approved_profile_ids=(profile_id,), approved_spec_sha256=snapshot.spec_sha256,
            approved_at=now, expires_at=now + timedelta(minutes=10),
        )
        compiled = compile_differential_plan(
            profile_id=profile_id, snapshot=snapshot, authorization=authorization,
            identity_handles={
                IdentityState.OWNER: "identity-owner", IdentityState.PEER: "identity-peer",
                IdentityState.TENANT_ADMIN: "identity-admin",
                IdentityState.OTHER_TENANT: "identity-other-tenant",
                IdentityState.EXPIRED: "identity-expired", IdentityState.REVOKED: "identity-revoked",
            }, seed=payload.seed, now=now,
        )
        try:
            async with session_scope(request) as session:
                attestations = metadata.tables["api_diff_target_attestations"]
                attestation = (await session.execute(select(attestations).where(
                    attestations.c.tenant_id == guard.security.tenant_id,
                    attestations.c.target_id == payload.target_id,
                    attestations.c.attestation_sha256 == payload.target_attestation_sha256,
                    attestations.c.endpoint == "http://redagent-r106-gateway:8080",
                    attestations.c.network_id == "redagent-r106-gateway-target",
                    attestations.c.non_production.is_(True),
                    attestations.c.attestation_state == "active",
                    attestations.c.issued_at <= now, attestations.c.expires_at > now,
                ))).mappings().one_or_none()
                decisions = metadata.tables["policy_decisions"]
                decision = (await session.execute(select(decisions.c.id).where(
                    decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id,
                    decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "api_diff.plan.compile",
                    decisions.c.resource_type == "api_diff_profile",
                    decisions.c.resource_id == payload.profile_id,
                    decisions.c.allowed.is_(True), decisions.c.valid_until > now,
                ))).one_or_none()
                roes = metadata.tables["roe_versions"]
                roe = (await session.execute(select(roes.c.id).where(
                    roes.c.tenant_id == guard.security.tenant_id,
                    roes.c.id == payload.roe_version_id, roes.c.status == "approved",
                ))).one_or_none()
                promotions = metadata.tables["api_diff_promotions"]
                promotion = (await session.execute(select(promotions.c.id).where(
                    promotions.c.tenant_id == guard.security.tenant_id,
                    promotions.c.promotion_id == "r106-api-diff-promotion-v1",
                    promotions.c.promotion_state == "active-local-lab",
                ))).one_or_none()
                if attestation is None:
                    raise ApiError(403, "api_diff_target_attestation_required", "An active owned-fixture attestation is required.")
                if decision is None:
                    raise ApiError(403, "api_diff_policy_decision_required", "A current profile-bound policy decision is required.")
                if roe is None:
                    raise ApiError(403, "api_diff_roe_approval_required", "An approved ROE version is required.")
                if promotion is None:
                    raise ApiError(403, "api_diff_promotion_required", "An active signed API bundle promotion is required.")
                target = ApiDifferentialTargetBinding(
                    target_id=payload.target_id,
                    attestation_sha256=payload.target_attestation_sha256,
                    fixture_sha256=str(attestation["fixture_sha256"]), endpoint=str(attestation["endpoint"]),
                    network_id=str(attestation["network_id"]), non_production=True,
                    issued_at=attestation["issued_at"], expires_at=attestation["expires_at"],
                )
                row = await ApiDifferentialRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).store_plan(
                    plan_id=payload.plan_id, compiled=compiled, target=target,
                    authorization=authorization, occurred_at=now,
                )
        except ApiDifferentialRepositoryConflict as exc:
            raise ApiError(409, "api_diff_plan_conflict", str(exc)) from exc
        return {"data": _public_api_differential_plan(row, payload.profile_id, payload.target_id)}

    @app.post(
        "/api/v1/api-differential/runs",
        operation_id="create_api_differential_run",
        response_model=ApiDifferentialRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def create_api_differential_run(
        payload: ApiDifferentialRunCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await ApiDifferentialRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).create_run(
                    run_id=payload.run_id, plan_id=payload.plan_id, job_id=payload.job_id,
                    runner_id=payload.runner_id, occurred_at=_now(),
                )
        except ApiDifferentialRepositoryConflict as exc:
            raise ApiError(409, "api_diff_run_conflict", str(exc)) from exc
        return {"data": _public_api_differential_run(row, payload.plan_id)}

    @app.post(
        "/api/v1/api-differential/runs/{run_id}/cancel",
        operation_id="cancel_api_differential_run",
        response_model=ApiDifferentialRunResponse,
    )
    async def cancel_api_differential_run(
        run_id: str,
        payload: ApiDifferentialCancelRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = ApiDifferentialRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                )
                row = await repository.request_cancel(
                    run_id=run_id, expected_version=payload.expected_version,
                    reason_code="operator_cancel_requested", occurred_at=_now(),
                )
                plans = metadata.tables["api_diff_plans"]
                plan = (await session.execute(select(plans.c.plan_id).where(
                    plans.c.tenant_id == guard.security.tenant_id,
                    plans.c.id == row["plan_record_id"],
                ))).one()
                job = (await session.execute(select(metadata.tables["jobs"].c.workflow_id).where(
                    metadata.tables["jobs"].c.tenant_id == guard.security.tenant_id,
                    metadata.tables["jobs"].c.id == row["job_id"],
                ))).one_or_none()
            if job is None or not job.workflow_id:
                raise ApiError(503, "api_diff_workflow_missing", "The bound durable workflow is unavailable.")
            await _orchestration(request).stop_job(
                str(job.workflow_id),
                EmergencyStopSignal(
                    CONTRACT_SCHEMA_VERSION, f"api-diff-cancel-{run_id}"[:100],
                    guard.security.subject, guard.policy_reference, payload.reason,
                ),
            )
        except ApiDifferentialRepositoryConflict as exc:
            raise ApiError(409, "api_diff_cancel_conflict", str(exc)) from exc
        return {"data": _public_api_differential_run(row, str(plan.plan_id))}

    @app.get(
        "/api/v1/api-differential/dashboard",
        operation_id="get_api_differential_dashboard",
        response_model=ApiDifferentialDashboardResponse,
    )
    async def get_api_differential_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        _, snapshot, _, _ = _require_r106_promotion(_now())
        async with session_scope(request) as session:
            data = await ApiDifferentialRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).dashboard()
            targets = metadata.tables["api_diff_target_attestations"]
            target_rows = (await session.execute(select(targets.c.id, targets.c.target_id).where(
                targets.c.tenant_id == guard.security.tenant_id,
            ))).all()
        target_by_record = {str(item.id): str(item.target_id) for item in target_rows}
        plans = {row["id"]: row for row in data["plans"]}
        return {"data": {
            "profiles": [_public_api_differential_profile(row, snapshot) for row in data["profiles"]],
            "plans": [_public_api_differential_plan(
                row, str(row["compiled_plan"]["profile_id"]), target_by_record[str(row["target_attestation_id"])],
            ) for row in data["plans"]],
            "runs": [_public_api_differential_run(
                row, str(plans[row["plan_record_id"]]["plan_id"]),
            ) for row in data["runs"]],
            "observations": [{key: row[key] for key in (
                "observation_id", "case_id", "finding_type", "violated",
                "evidence_instance_id", "reason_code",
            )} for row in data["observations"]],
            "replays": [{key: row[key] for key in (
                "replay_id", "case_id", "minimized_replay_sha256", "semantic_predicate", "replay_state",
            )} for row in data["replays"]],
            "cleanups": [{key: row[key] for key in (
                "receipt_id", "compensation_complete", "lease_revoked",
                "residual_resource_count", "completed_at",
            )} for row in data["cleanups"]],
            "target_options": [{key: row[key] for key in (
                "target_id", "attestation_sha256", "attestation_state", "non_production", "expires_at",
            )} for row in data["target_options"]],
            "runner_options": [{key: row[key] for key in (
                "runner_id", "environment", "network_plane", "required_policy_revision", "registration_state", "expires_at",
            )} for row in data["runner_options"]],
            "job_options": [{"job_id": row["id"], **{key: row[key] for key in (
                "engagement_id", "roe_version_id", "status", "current_gate", "dispatch_blocked", "stop_requested",
            )}} for row in data["job_options"]],
        }}
