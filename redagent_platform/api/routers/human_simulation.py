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
from redagent_platform.api.schemas.human_simulation import (
    HumanSimulationCampaignListResponse,
    HumanSimulationCompileRequest,
    HumanSimulationDashboardResponse,
    HumanSimulationPlanResponse,
    HumanSimulationRunCreateRequest,
    HumanSimulationRunResponse,
    HumanSimulationStopRequest,
)
from redagent_platform.human_simulation.catalog import certified_campaign
from redagent_platform.human_simulation.compiler import compile_campaign_plan
from redagent_platform.human_simulation.contracts import (
    CampaignApproval,
    CampaignAuthorization,
)
from redagent_platform.human_simulation.repository import (
    HumanSimulationRepository,
    HumanSimulationRepositoryConflict,
)
from redagent_platform.persistence.models import metadata
from sqlalchemy import select

def _public_human_campaign(campaign) -> dict[str, object]:
    return {"campaign_id": campaign.campaign_id, "purpose": campaign.purpose,
        "recipient_class": "synthetic-invalid-owned", "sink_id": campaign.sink_id,
        "template_sha256": campaign.template_sha256, "canary_id": campaign.canary_id,
        "max_deliveries": 1, "rate_per_minute": 1, "retention_seconds": 300,
        "consent_required": True, "suppression_required": True, "privacy_review_required": True,
        "deletion_required": True, "human_delivery": False, "external_delivery": False,
        "raw_submission_retention": False, "production_qualified": False}


def _public_human_plan(row: dict[str, object], campaign_id: str, approval_id: str) -> dict[str, object]:
    return {"plan_id": row["plan_id"], "campaign_id": campaign_id, "approval_id": approval_id,
        "policy_decision_id": row["policy_decision_id"], "roe_revision": row["roe_revision"],
        "reservation_id": row["reservation_id"], "delivery_lease_id": row["delivery_lease_id"],
        "stop_switch_id": row["stop_switch_id"], "plan_sha256": row["plan_sha256"],
        "plan_state": row["plan_state"], "expires_at": row["expires_at"], "version": row["version"]}


def _public_human_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {"run_id": row["run_id"], "plan_id": plan_id, "job_id": row["job_id"], "runner_id": row["runner_id"],
        "run_state": row["run_state"], "new_delivery_blocked": row["new_delivery_blocked"],
        "human_delivery_count": row["human_delivery_count"], "external_delivery_count": row["external_delivery_count"],
        "deletion_verified": row["deletion_verified"], "failure_code": row["failure_code"], "version": row["version"]}


def register_human_simulation_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get("/api/v1/human-simulation/campaigns", operation_id="list_human_simulation_campaigns", response_model=HumanSimulationCampaignListResponse)
    async def list_human_simulation_campaigns(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        return {"data": [_public_human_campaign(certified_campaign())]}

    @app.post("/api/v1/human-simulation/plans", operation_id="compile_human_simulation_plan", response_model=HumanSimulationPlanResponse, status_code=status.HTTP_201_CREATED)
    async def create_human_simulation_plan(
        payload: HumanSimulationCompileRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        now = _now(); _match_roe_reference(guard, payload.roe_version_id); campaign = certified_campaign()
        try:
            async with session_scope(request) as session:
                manifests = metadata.tables["human_campaign_manifests"]; approvals = metadata.tables["human_campaign_approvals"]
                manifest = (await session.execute(select(manifests).where(manifests.c.tenant_id == guard.security.tenant_id,
                    manifests.c.campaign_id == payload.campaign_id, manifests.c.manifest_state == "certified-synthetic-sink",
                    manifests.c.human_delivery.is_(False), manifests.c.external_delivery.is_(False)))).mappings().one_or_none()
                approval_row = (await session.execute(select(approvals).where(approvals.c.tenant_id == guard.security.tenant_id,
                    approvals.c.approval_id == payload.approval_id, approvals.c.approval_state == "send-approved-exact",
                    approvals.c.expires_at > now))).mappings().one_or_none()
                decisions = metadata.tables["policy_decisions"]
                decision = (await session.execute(select(decisions.c.id).where(decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id, decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "human_simulation.plan.compile", decisions.c.resource_type == "human_campaign",
                    decisions.c.resource_id == payload.campaign_id, decisions.c.allowed.is_(True), decisions.c.valid_until > now))).one_or_none()
                roes = metadata.tables["roe_versions"]
                roe = (await session.execute(select(roes.c.id).where(roes.c.tenant_id == guard.security.tenant_id,
                    roes.c.id == payload.roe_version_id, roes.c.status == "approved"))).one_or_none()
                reservations = metadata.tables["quota_reservations"]
                reservation = (await session.execute(select(reservations).where(reservations.c.tenant_id == guard.security.tenant_id,
                    reservations.c.reservation_id == payload.reservation_id,
                    reservations.c.reservation_state.in_(("reserved", "partially_consumed")), reservations.c.expires_at > now))).mappings().one_or_none()
                if manifest is None or approval_row is None or approval_row["campaign_record_id"] != manifest["id"]:
                    raise ApiError(403, "human_exact_campaign_approval_required", "A certified synthetic sink campaign and exact active approval are required.")
                if decision is None or roe is None or reservation is None:
                    raise ApiError(403, "human_authorization_required", "Current policy, approved ROE, and quota reservation are required.")
                approval = CampaignApproval(approval_id=str(approval_row["approval_id"]), campaign_id=payload.campaign_id,
                    campaign_sha256=str(approval_row["campaign_sha256"]), rendered_sha256=str(approval_row["rendered_sha256"]),
                    test_delivery_sha256=str(approval_row["test_delivery_sha256"]), requester_id=str(approval_row["requester_id"]),
                    preview_reviewer_id=str(approval_row["preview_reviewer_id"]), send_approver_id=str(approval_row["send_approver_id"]),
                    approved_at=approval_row["approved_at"], expires_at=approval_row["expires_at"])
                authorization = CampaignAuthorization(authorization_id=f"authorization-{payload.plan_id}",
                    policy_decision_id=payload.policy_decision_id, policy_revision=payload.policy_revision,
                    roe_revision=payload.roe_version_id, reservation_id=payload.reservation_id,
                    delivery_lease_id=payload.delivery_lease_id, stop_switch_id=payload.stop_switch_id,
                    quota_id=payload.quota_id, campaign_sha256=approval.campaign_sha256, approved_at=now,
                    expires_at=min(approval.expires_at, reservation["expires_at"], now + timedelta(minutes=10)))
                compiled = compile_campaign_plan(campaign=campaign, approval=approval, authorization=authorization, now=now)
                row = await HumanSimulationRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).store_plan(
                    plan_id=payload.plan_id, compiled=compiled, approval=approval, authorization=authorization, occurred_at=now)
        except HumanSimulationRepositoryConflict as exc:
            raise ApiError(409, "human_plan_conflict", str(exc)) from exc
        return {"data": _public_human_plan(row, payload.campaign_id, payload.approval_id)}

    @app.post("/api/v1/human-simulation/runs", operation_id="create_human_simulation_run", response_model=HumanSimulationRunResponse, status_code=status.HTTP_202_ACCEPTED)
    async def create_human_simulation_run(
        payload: HumanSimulationRunCreateRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                row = await HumanSimulationRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).create_run(
                    run_id=payload.run_id, plan_id=payload.plan_id, job_id=payload.job_id,
                    runner_id=payload.runner_id, occurred_at=_now())
        except HumanSimulationRepositoryConflict as exc:
            raise ApiError(409, "human_run_conflict", str(exc)) from exc
        return {"data": _public_human_run(row, payload.plan_id)}

    @app.post("/api/v1/human-simulation/runs/{run_id}/stop", operation_id="stop_human_simulation_run", response_model=HumanSimulationRunResponse)
    async def stop_human_simulation_run(
        run_id: str, payload: HumanSimulationStopRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = HumanSimulationRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id)
                row = await repository.request_stop(run_id=run_id, expected_version=payload.expected_version, occurred_at=_now())
                plans = metadata.tables["human_campaign_plans"]
                plan = (await session.execute(select(plans.c.plan_id).where(plans.c.tenant_id == guard.security.tenant_id,
                    plans.c.id == row["plan_record_id"]))).one()
        except HumanSimulationRepositoryConflict as exc:
            raise ApiError(409, "human_stop_conflict", str(exc)) from exc
        return {"data": _public_human_run(row, str(plan.plan_id))}

    @app.get("/api/v1/human-simulation/dashboard", operation_id="get_human_simulation_dashboard", response_model=HumanSimulationDashboardResponse)
    async def get_human_simulation_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await HumanSimulationRepository(session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).dashboard()
        campaign_by_record = {str(row["id"]): str(row["campaign_id"]) for row in data["campaigns"]}
        approval_by_record = {str(row["id"]): str(row["approval_id"]) for row in data["approvals"]}
        plan_by_record = {str(row["id"]): row for row in data["plans"]}
        return {"data": {"campaigns": [_public_human_campaign(certified_campaign()) for _ in data["campaigns"]],
            "rosters": data["rosters"], "suppressions": data["suppressions"], "privacy_reviews": data["privacy_reviews"],
            "templates": data["templates"], "approvals": data["approvals"],
            "plans": [_public_human_plan(row, campaign_by_record[str(row["campaign_record_id"])],
                approval_by_record[str(row["approval_record_id"])]) for row in data["plans"]],
            "runs": [_public_human_run(row, str(plan_by_record[str(row["plan_record_id"])]["plan_id"])) for row in data["runs"]],
            "deliveries": data["deliveries"], "events": data["events"], "canaries": data["canaries"],
            "stops": data["stops"], "deletions": data["deletions"], "rehearsals": data["rehearsals"],
            "approval_options": [{
                "approval_id": row["approval_id"],
                "campaign_id": campaign_by_record[str(row["campaign_record_id"])],
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
