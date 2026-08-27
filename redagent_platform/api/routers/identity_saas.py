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
)
from redagent_platform.api.schemas.identity_saas import (
    IdentitySaasCancelRequest,
    IdentitySaasCompileRequest,
    IdentitySaasDashboardResponse,
    IdentitySaasPlanResponse,
    IdentitySaasProfileListResponse,
    IdentitySaasRunCreateRequest,
    IdentitySaasRunResponse,
)
from redagent_platform.identity_saas.compiler import compile_identity_plan
from redagent_platform.identity_saas.contracts import IdentityAuthorization
from redagent_platform.identity_saas.profiles import emulator_profiles as identity_emulator_profiles
from redagent_platform.identity_saas.repository import (
    IdentityRepositoryConflict,
    IdentitySaasRepository,
)
from redagent_platform.persistence.models import metadata
from sqlalchemy import select

def _public_identity_profile(profile) -> dict[str, object]:
    return {
        "profile_id": profile.profile_id, "provider": profile.provider.value,
        "provider_tenant_id": profile.tenant_id, "audience": profile.audience,
        "consent_mode": profile.consent_mode.value,
        "operations": [{"operation_id": item.operation_id, "method": "GET", "api_version": item.api_version,
            "permission_scope": item.permission_scope, "effective_role_permission": item.effective_role_permission,
            "selected_fields": list(item.selected_fields), "data_class": item.data_class.value,
            "graph_eligible": item.graph_eligible} for item in profile.operations],
        "retention_days": profile.snapshot_retention_days, "profile_state": "certified-local-lab",
        "emulator_only": True, "production_qualified": False,
    }


def _public_identity_plan(row: dict[str, object], profile_id: str, tenant_binding_id: str) -> dict[str, object]:
    return {"plan_id": row["plan_id"], "profile_id": profile_id, "tenant_binding_id": tenant_binding_id,
        "policy_decision_id": row["policy_decision_id"], "reservation_id": row["reservation_id"],
        "credential_lease_id": row["credential_lease_id"], "plan_sha256": row["plan_sha256"],
        "plan_state": row["plan_state"], "expires_at": row["expires_at"], "version": row["version"]}


def _public_identity_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {"run_id": row["run_id"], "plan_id": plan_id, "job_id": row["job_id"], "runner_id": row["runner_id"],
        "run_state": row["run_state"], "complete": row["complete"], "partial_reasons": list(row["partial_reasons"]),
        "snapshot_sha256": row["snapshot_sha256"], "version": row["version"]}


def register_identity_saas_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/identity-posture/profiles",
        operation_id="list_identity_posture_profiles",
        response_model=IdentitySaasProfileListResponse,
    )
    async def list_identity_posture_profiles(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        return {"data": [_public_identity_profile(profile) for profile in identity_emulator_profiles().values()]}

    @app.post(
        "/api/v1/identity-posture/plans",
        operation_id="compile_identity_posture_plan",
        response_model=IdentitySaasPlanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_identity_posture_plan(
        payload: IdentitySaasCompileRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        now = _now()
        _match_roe_reference(guard, payload.roe_version_id)
        profiles = {profile.profile_id: profile for profile in identity_emulator_profiles().values()}
        profile = profiles[payload.profile_id]
        try:
            async with session_scope(request) as session:
                bindings = metadata.tables["identity_tenant_bindings"]
                binding = (await session.execute(select(bindings).where(
                    bindings.c.tenant_id == guard.security.tenant_id,
                    bindings.c.binding_id == payload.tenant_binding_id,
                    bindings.c.provider_tenant_id == profile.tenant_id,
                    bindings.c.audience == profile.audience,
                    bindings.c.consent_mode == profile.consent_mode.value,
                    bindings.c.binding_state == "active-local-emulator",
                ))).mappings().one_or_none()
                decisions = metadata.tables["policy_decisions"]
                decision = (await session.execute(select(decisions.c.id).where(
                    decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id,
                    decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "identity.plan.compile",
                    decisions.c.resource_type == "identity_profile",
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
                leases = metadata.tables["secret_leases"]
                lease = (await session.execute(select(leases).where(
                    leases.c.tenant_id == guard.security.tenant_id, leases.c.id == payload.credential_lease_id,
                    leases.c.lease_state == "active", leases.c.roe_version_id == payload.roe_version_id,
                    leases.c.expires_at > now, leases.c.revoked_at.is_(None),
                ))).mappings().one_or_none()
                if binding is None:
                    raise ApiError(403, "identity_exact_binding_required", "An active exact local-emulator tenant binding is required.")
                if decision is None or roe is None:
                    raise ApiError(403, "identity_policy_approval_required", "A current profile-bound policy decision and approved ROE are required.")
                if reservation is None:
                    raise ApiError(403, "identity_quota_reservation_required", "An active quota reservation is required.")
                if lease is None or lease["permission_digest"] != binding["permission_digest"]:
                    raise ApiError(403, "identity_exact_lease_required", "An active exact-permission opaque lease is required.")
                authorization = IdentityAuthorization(
                    authorization_id=f"authorization-{payload.plan_id}", policy_decision_id=payload.policy_decision_id,
                    policy_revision=payload.policy_revision, reservation_id=payload.reservation_id,
                    credential_lease_id=payload.credential_lease_id, tenant_id=profile.tenant_id,
                    audience=profile.audience, consent_mode=profile.consent_mode,
                    granted_scopes=tuple(str(item) for item in binding["scopes"]),
                    effective_role_permissions=tuple(str(item) for item in binding["role_permissions"]),
                    approved_at=now, expires_at=min(lease["expires_at"], reservation["expires_at"], now + timedelta(minutes=10)),
                )
                compiled = compile_identity_plan(profile=profile, authorization=authorization, now=now)
                row = await IdentitySaasRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).store_plan(
                    plan_id=payload.plan_id, binding_id=payload.tenant_binding_id,
                    compiled=compiled, authorization=authorization, occurred_at=now,
                )
        except IdentityRepositoryConflict as exc:
            raise ApiError(409, "identity_plan_conflict", str(exc)) from exc
        return {"data": _public_identity_plan(row, payload.profile_id, payload.tenant_binding_id)}

    @app.post(
        "/api/v1/identity-posture/runs",
        operation_id="create_identity_posture_run",
        response_model=IdentitySaasRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def create_identity_posture_run(
        payload: IdentitySaasRunCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await IdentitySaasRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).create_run(
                    run_id=payload.run_id, plan_id=payload.plan_id, job_id=payload.job_id,
                    runner_id=payload.runner_id, occurred_at=_now(),
                )
        except IdentityRepositoryConflict as exc:
            raise ApiError(409, "identity_run_conflict", str(exc)) from exc
        return {"data": _public_identity_run(row, payload.plan_id)}

    @app.post(
        "/api/v1/identity-posture/runs/{run_id}/cancel",
        operation_id="cancel_identity_posture_run",
        response_model=IdentitySaasRunResponse,
    )
    async def cancel_identity_posture_run(
        run_id: str, payload: IdentitySaasCancelRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = IdentitySaasRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id)
                row = await repository.request_cancel(run_id=run_id, expected_version=payload.expected_version, occurred_at=_now())
                plans = metadata.tables["identity_collection_plans"]
                plan = (await session.execute(select(plans.c.plan_id).where(
                    plans.c.tenant_id == guard.security.tenant_id, plans.c.id == row["plan_record_id"],
                ))).one()
        except IdentityRepositoryConflict as exc:
            raise ApiError(409, "identity_cancel_conflict", str(exc)) from exc
        return {"data": _public_identity_run(row, str(plan.plan_id))}

    @app.get(
        "/api/v1/identity-posture/dashboard",
        operation_id="get_identity_posture_dashboard",
        response_model=IdentitySaasDashboardResponse,
    )
    async def get_identity_posture_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await IdentitySaasRepository(session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).dashboard()
        profile_by_record = {str(row["id"]): str(row["profile_id"]) for row in data["profiles"]}
        binding_by_record = {str(row["id"]): str(row["binding_id"]) for row in data["bindings"]}
        plan_by_record = {str(row["id"]): row for row in data["plans"]}
        profiles = {profile.profile_id: profile for profile in identity_emulator_profiles().values()}
        return {"data": {
            "profiles": [_public_identity_profile(profiles[str(row["profile_id"])]) for row in data["profiles"]],
            "plans": [_public_identity_plan(row, profile_by_record[str(row["profile_record_id"])], binding_by_record[str(row["binding_record_id"])]) for row in data["plans"]],
            "runs": [_public_identity_run(row, str(plan_by_record[str(row["plan_record_id"])] ["plan_id"])) for row in data["runs"]],
            "evaluations": data["evaluations"], "exceptions": data["exceptions"], "graphs": data["graphs"], "cleanups": data["cleanups"],
            "binding_options": [{
                "binding_id": row["binding_id"],
                "profile_id": profile_by_record[str(row["profile_record_id"])],
                "provider_tenant_id": row["provider_tenant_id"],
                "audience": row["audience"],
                "consent_mode": row["consent_mode"],
                "permission_digest": row["permission_digest"],
                "binding_state": row["binding_state"],
            } for row in data["binding_options"]],
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
