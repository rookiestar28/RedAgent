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
from redagent_platform.api.schemas.purple import (
    PurpleAbilityListResponse,
    PurpleCompileRequest,
    PurpleDashboardResponse,
    PurpleKillRequest,
    PurplePlanResponse,
    PurpleRunCreateRequest,
    PurpleRunResponse,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.purple_runtime.catalog import certified_abilities as certified_purple_abilities
from redagent_platform.purple_runtime.compiler import compile_ability_plan
from redagent_platform.purple_runtime.contracts import (
    AbilityApproval,
    AbilityAuthorization,
    LabBinding,
)
from redagent_platform.purple_runtime.repository import (
    PurpleRepositoryConflict,
    PurpleRuntimeRepository,
)
from sqlalchemy import select

def _public_purple_ability(ability) -> dict[str, object]:
    return {"ability_id": ability.ability_id, "attack_version": ability.attack_version,
        "attack_technique_id": ability.attack_technique_id, "phases": [item.value for item in ability.phases],
        "detection_strategy_id": ability.detection.strategy_id, "analytic_id": ability.detection.analytic_id,
        "event_schema": ability.detection.event_schema, "timeout_seconds": ability.timeout_seconds,
        "lab_only": True, "network_allowed": False, "subprocess_allowed": False,
        "external_content_allowed": False, "production_qualified": False}


def _public_purple_plan(row: dict[str, object], ability_id: str, lab_binding_id: str, approval_id: str) -> dict[str, object]:
    return {"plan_id": row["plan_id"], "ability_id": ability_id, "lab_binding_id": lab_binding_id,
        "approval_id": approval_id, "policy_decision_id": row["policy_decision_id"], "roe_revision": row["roe_revision"],
        "reservation_id": row["reservation_id"], "lease_id": row["lease_id"], "kill_switch_id": row["kill_switch_id"],
        "plan_sha256": row["plan_sha256"], "plan_state": row["plan_state"], "expires_at": row["expires_at"],
        "version": row["version"]}


def _public_purple_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {"run_id": row["run_id"], "plan_id": plan_id, "job_id": row["job_id"], "runner_id": row["runner_id"],
        "run_state": row["run_state"], "dispatch_blocked": row["dispatch_blocked"],
        "detection_observed": row["detection_observed"], "cleanup_complete": row["cleanup_complete"],
        "teardown_verified": row["teardown_verified"], "failure_code": row["failure_code"], "version": row["version"]}


def register_purple_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get("/api/v1/purple-lab/abilities", operation_id="list_purple_lab_abilities", response_model=PurpleAbilityListResponse)
    async def list_purple_lab_abilities(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        return {"data": [_public_purple_ability(ability) for ability in certified_purple_abilities().values()]}

    @app.post("/api/v1/purple-lab/plans", operation_id="compile_purple_lab_plan", response_model=PurplePlanResponse, status_code=status.HTTP_201_CREATED)
    async def create_purple_lab_plan(
        payload: PurpleCompileRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        now = _now(); _match_roe_reference(guard, payload.roe_version_id)
        ability = certified_purple_abilities()[payload.ability_id]
        try:
            async with session_scope(request) as session:
                abilities = metadata.tables["purple_abilities"]; labs = metadata.tables["purple_lab_bindings"]
                approvals = metadata.tables["purple_approvals"]
                ability_row = (await session.execute(select(abilities).where(abilities.c.tenant_id == guard.security.tenant_id,
                    abilities.c.ability_id == payload.ability_id, abilities.c.ability_state == "certified-local-lab"))).mappings().one_or_none()
                lab_row = (await session.execute(select(labs).where(labs.c.tenant_id == guard.security.tenant_id,
                    labs.c.binding_id == payload.lab_binding_id, labs.c.binding_state == "active-disposable-owned",
                    labs.c.disposable.is_(True), labs.c.production.is_(False), labs.c.egress_allowed.is_(False), labs.c.expires_at > now))).mappings().one_or_none()
                approval_row = (await session.execute(select(approvals).where(approvals.c.tenant_id == guard.security.tenant_id,
                    approvals.c.approval_id == payload.approval_id, approvals.c.approval_state == "approved-exact",
                    approvals.c.expires_at > now))).mappings().one_or_none()
                decisions = metadata.tables["policy_decisions"]
                decision = (await session.execute(select(decisions.c.id).where(decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id, decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "purple.plan.compile", decisions.c.resource_type == "purple_ability",
                    decisions.c.resource_id == payload.ability_id, decisions.c.allowed.is_(True), decisions.c.valid_until > now))).one_or_none()
                roes = metadata.tables["roe_versions"]
                roe = (await session.execute(select(roes.c.id).where(roes.c.tenant_id == guard.security.tenant_id,
                    roes.c.id == payload.roe_version_id, roes.c.status == "approved"))).one_or_none()
                reservations = metadata.tables["quota_reservations"]
                reservation = (await session.execute(select(reservations).where(reservations.c.tenant_id == guard.security.tenant_id,
                    reservations.c.reservation_id == payload.reservation_id,
                    reservations.c.reservation_state.in_(("reserved", "partially_consumed")), reservations.c.expires_at > now))).mappings().one_or_none()
                if ability_row is None or lab_row is None or approval_row is None:
                    raise ApiError(403, "purple_exact_foundation_required", "A certified ability, disposable owned lab, and exact active approval are required.")
                if approval_row["ability_record_id"] != ability_row["id"] or approval_row["lab_binding_record_id"] != lab_row["id"]:
                    raise ApiError(403, "purple_approval_binding_mismatch", "Approval must bind the exact ability and lab snapshot.")
                if decision is None or roe is None or reservation is None:
                    raise ApiError(403, "purple_authorization_required", "Current policy, approved ROE, and quota reservation are required.")
                approval = AbilityApproval(approval_id=str(approval_row["approval_id"]), ability_id=payload.ability_id,
                    ability_sha256=str(approval_row["ability_sha256"]), adapter_sha256=str(approval_row["adapter_sha256"]),
                    lab_binding_id=payload.lab_binding_id, lab_snapshot_sha256=str(approval_row["lab_snapshot_sha256"]),
                    requester_id=str(approval_row["requester_id"]), approver_id=str(approval_row["approver_id"]),
                    executor_id=str(approval_row["executor_id"]), approved_at=approval_row["approved_at"], expires_at=approval_row["expires_at"])
                lab = LabBinding(binding_id=payload.lab_binding_id, target_id=str(lab_row["target_id"]), runner_id=str(lab_row["runner_id"]),
                    snapshot_sha256=str(lab_row["snapshot_sha256"]), telemetry_collector_id=str(lab_row["telemetry_collector_id"]),
                    disposable=True, production=False, egress_allowed=False, expires_at=lab_row["expires_at"])
                expires_at = min(approval.expires_at, lab.expires_at, reservation["expires_at"], now + timedelta(minutes=10))
                authorization = AbilityAuthorization(authorization_id=f"authorization-{payload.plan_id}",
                    policy_decision_id=payload.policy_decision_id, policy_revision=payload.policy_revision,
                    roe_revision=payload.roe_version_id, reservation_id=payload.reservation_id, lease_id=payload.lease_id,
                    kill_switch_id=payload.kill_switch_id, quota_id=payload.quota_id,
                    ability_sha256=approval.ability_sha256, lab_snapshot_sha256=lab.snapshot_sha256,
                    approved_at=now, expires_at=expires_at)
                compiled = compile_ability_plan(ability=ability, approval=approval, lab=lab, authorization=authorization, now=now)
                row = await PurpleRuntimeRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).store_plan(
                    plan_id=payload.plan_id, compiled=compiled, approval=approval, authorization=authorization, occurred_at=now)
        except PurpleRepositoryConflict as exc:
            raise ApiError(409, "purple_plan_conflict", str(exc)) from exc
        return {"data": _public_purple_plan(row, payload.ability_id, payload.lab_binding_id, payload.approval_id)}

    @app.post("/api/v1/purple-lab/runs", operation_id="create_purple_lab_run", response_model=PurpleRunResponse, status_code=status.HTTP_202_ACCEPTED)
    async def create_purple_lab_run(
        payload: PurpleRunCreateRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await PurpleRuntimeRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).create_run(
                    run_id=payload.run_id, plan_id=payload.plan_id, job_id=payload.job_id,
                    runner_id=payload.runner_id, occurred_at=_now())
        except PurpleRepositoryConflict as exc:
            raise ApiError(409, "purple_run_conflict", str(exc)) from exc
        return {"data": _public_purple_run(row, payload.plan_id)}

    @app.post("/api/v1/purple-lab/runs/{run_id}/kill", operation_id="kill_purple_lab_run", response_model=PurpleRunResponse)
    async def kill_purple_lab_run(
        run_id: str, payload: PurpleKillRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = PurpleRuntimeRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id)
                row = await repository.request_kill(run_id=run_id, expected_version=payload.expected_version, occurred_at=_now())
                plans = metadata.tables["purple_execution_plans"]
                plan = (await session.execute(select(plans.c.plan_id).where(plans.c.tenant_id == guard.security.tenant_id,
                    plans.c.id == row["plan_record_id"]))).one()
        except PurpleRepositoryConflict as exc:
            raise ApiError(409, "purple_kill_conflict", str(exc)) from exc
        return {"data": _public_purple_run(row, str(plan.plan_id))}

    @app.get("/api/v1/purple-lab/dashboard", operation_id="get_purple_lab_dashboard", response_model=PurpleDashboardResponse)
    async def get_purple_lab_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await PurpleRuntimeRepository(session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).dashboard()
        ability_by_record = {str(row["id"]): str(row["ability_id"]) for row in data["abilities"]}
        lab_by_record = {str(row["id"]): str(row["binding_id"]) for row in data["labs"]}
        approval_by_record = {str(row["id"]): str(row["approval_id"]) for row in data["approvals"]}
        plan_by_record = {str(row["id"]): row for row in data["plans"]}; catalog = certified_purple_abilities()
        return {"data": {"abilities": [_public_purple_ability(catalog[str(row["ability_id"])]) for row in data["abilities"]],
            "labs": data["labs"], "approvals": data["approvals"],
            "plans": [_public_purple_plan(row, ability_by_record[str(row["ability_record_id"])],
                lab_by_record[str(row["lab_binding_record_id"])], approval_by_record[str(row["approval_record_id"])]) for row in data["plans"]],
            "runs": [_public_purple_run(row, str(plan_by_record[str(row["plan_record_id"])]["plan_id"])) for row in data["runs"]],
            "detections": data["detections"], "telemetry": data["telemetry"], "cleanups": data["cleanups"],
            "teardowns": data["teardowns"], "rehearsals": data["rehearsals"],
            "lab_options": [{key: row[key] for key in (
                "binding_id", "runner_id", "disposable", "production", "egress_allowed",
                "binding_state", "expires_at",
            )} for row in data["lab_options"]],
            "approval_options": [{
                "approval_id": row["approval_id"],
                "ability_id": ability_by_record[str(row["ability_record_id"])],
                "lab_binding_id": lab_by_record[str(row["lab_binding_record_id"])],
                "approval_state": row["approval_state"],
                "expires_at": row["expires_at"],
            } for row in data["approval_options"]],
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
            } for row in data["reservation_options"]]}}
