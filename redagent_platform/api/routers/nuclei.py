"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from datetime import (
    datetime,
    timedelta,
)
from fastapi import (
    Depends,
    Request,
    status,
)
from pathlib import Path
from redagent_platform.api.contracts import (
    ApiError,
    RequestGuard,
)
from redagent_platform.api.router_primitives import (
    _match_roe_reference,
    _now,
    _orchestration,
)
from redagent_platform.api.schemas.nuclei import (
    NucleiCancelRequest,
    NucleiCompileRequest,
    NucleiDashboardResponse,
    NucleiPlanResponse,
    NucleiProfileListResponse,
    NucleiRunCreateRequest,
    NucleiRunResponse,
)
from redagent_platform.nuclei_service.compiler import compile_nuclei_plan
from redagent_platform.nuclei_service.contracts import (
    NucleiAuthorization,
    NucleiProfileId,
    NucleiTargetBinding,
    certified_profiles as certified_nuclei_profiles,
)
from redagent_platform.nuclei_service.promotion import verify_current_nuclei_bundle_promotion
from redagent_platform.nuclei_service.repository import (
    NucleiRepository,
    NucleiRepositoryConflict,
    profile_values as nuclei_profile_values,
)
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    EmergencyStopSignal,
)
from redagent_platform.persistence.models import metadata
from sqlalchemy import select

# IMPORTANT: router modules are one level below api; promotion assets remain workspace-relative.
def _public_nuclei_profile(row: dict[str, object]) -> dict[str, object]:
    return {key: row[key] for key in (
        "profile_id", "profile_revision", "profile_sha256", "request_limit",
        "request_rate_per_second", "concurrency_limit", "timeout_seconds",
        "response_bytes_limit", "result_limit", "profile_state",
    )} | {
        **{key: row[key] for key in ("engine_version", "image_digest", "bundle_id", "bundle_revision")},
        "risk_class": "low", "allowed_protocols": ["http"],
        "allowed_methods": ["GET"], "allowed_paths": ["/nuclei/missing-header"],
    }


def _public_nuclei_plan(row: dict[str, object], profile_id: str, bundle_id: str) -> dict[str, object]:
    return {
        "plan_id": row["plan_id"], "profile_id": profile_id, "bundle_id": bundle_id,
        "policy_revision": row["compiled_plan"]["policy_revision"],
        **{key: row[key] for key in (
            "target_id", "policy_decision_id", "roe_version_id", "plan_sha256",
            "scope_sha256", "expires_at", "version",
        )},
    }


def _public_nuclei_run(row: dict[str, object], plan_id: str) -> dict[str, object]:
    return {
        "run_id": row["run_id"], "plan_id": plan_id,
        **{key: row[key] for key in (
            "job_id", "runner_id", "run_state", "progress_percent", "request_count",
            "response_bytes", "result_count", "reason_code", "version",
        )},
    }


def _load_nuclei_bundle(now: datetime):
    workspace = Path(__file__).resolve().parents[3]
    return verify_current_nuclei_bundle_promotion(
        manifest_bytes=(workspace / "bundles/r105-nuclei/bundle-manifest-v3.json").read_bytes(),
        signature_bundle_bytes=(
            workspace / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.sigstore.json"
        ).read_bytes(),
        public_key_bytes=(
            workspace / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.pub"
        ).read_bytes(),
        template_bytes=(workspace / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml").read_bytes(),
        certificate_bytes=(workspace / "config/trust/r105-nuclei-user.crt").read_bytes(),
        qualification_bytes=(
            workspace / "runtime-assets/attestations/261002-R105_NUCLEI_RUNTIME_QUALIFICATION_V3.json"
        ).read_bytes(),
        now=now,
    )


def _require_nuclei_bundle(now: datetime):
    try:
        return _load_nuclei_bundle(now)
    except (OSError, ValueError) as exc:
        raise ApiError(503, "nuclei_supply_chain_unavailable", "The signed Nuclei bundle is unavailable.") from exc


def register_nuclei_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/nuclei/profiles",
        operation_id="list_nuclei_profiles",
        response_model=NucleiProfileListResponse,
    )
    async def list_nuclei_profiles(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        _require_nuclei_bundle(_now())
        return {"data": [nuclei_profile_values(profile) for profile in certified_nuclei_profiles().values()]}

    @app.post(
        "/api/v1/nuclei/plans",
        operation_id="compile_nuclei_plan",
        response_model=NucleiPlanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_nuclei_plan(
        payload: NucleiCompileRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True, roe_required=True)),
    ) -> dict:
        now = _now()
        _match_roe_reference(guard, payload.roe_version_id)
        promoted = _require_nuclei_bundle(now)
        profile_id = NucleiProfileId(payload.profile_id)
        profile = certified_nuclei_profiles()[profile_id]
        target = NucleiTargetBinding(
            target_id=payload.target_id, attestation_sha256=payload.target_attestation_sha256,
            endpoint="http://redagent-r105-gateway:8080", allowed_paths=profile.allowed_paths,
            network_id="redagent-r105-gateway-target", non_production=True,
            issued_at=now, expires_at=now + timedelta(minutes=15),
        )
        authorization = NucleiAuthorization(
            tenant_id=guard.security.tenant_id, policy_decision_id=payload.policy_decision_id,
            policy_revision=payload.policy_revision, roe_version_id=payload.roe_version_id,
            approved_profile_ids=(profile_id,), approved_bundle_id=payload.bundle_id,
            approved_at=now, expires_at=now + timedelta(minutes=10),
        )
        compiled = compile_nuclei_plan(profile_id=profile_id, bundle=promoted, target=target,
                                       authorization=authorization, now=now)
        try:
            async with session_scope(request) as session:
                attestations = metadata.tables["nuclei_target_attestations"]
                attestation = (await session.execute(select(attestations.c.id).where(
                    attestations.c.tenant_id == guard.security.tenant_id,
                    attestations.c.target_id == payload.target_id,
                    attestations.c.attestation_sha256 == payload.target_attestation_sha256,
                    attestations.c.network_id == "redagent-r105-gateway-target",
                    attestations.c.non_production.is_(True),
                    attestations.c.attestation_state == "active",
                    attestations.c.issued_at <= now, attestations.c.expires_at > now,
                ))).one_or_none()
                decisions = metadata.tables["policy_decisions"]
                decision = (await session.execute(select(decisions.c.id).where(
                    decisions.c.tenant_id == guard.security.tenant_id,
                    decisions.c.opa_decision_id == payload.policy_decision_id,
                    decisions.c.bundle_revision == payload.policy_revision,
                    decisions.c.action == "nuclei.plan.compile",
                    decisions.c.resource_type == "nuclei_profile",
                    decisions.c.resource_id == payload.profile_id,
                    decisions.c.allowed.is_(True), decisions.c.valid_until > now,
                ))).one_or_none()
                roes = metadata.tables["roe_versions"]
                roe = (await session.execute(select(roes.c.id).where(
                    roes.c.tenant_id == guard.security.tenant_id,
                    roes.c.id == payload.roe_version_id, roes.c.status == "approved",
                ))).one_or_none()
                promotions = metadata.tables["nuclei_bundle_promotions"]
                promotion = (await session.execute(select(promotions.c.id).where(
                    promotions.c.tenant_id == guard.security.tenant_id,
                    promotions.c.promotion_id == f"r105-bundle-promotion-v{promoted.revision}",
                    # CRITICAL: a stored label alone cannot substitute the current signed bundle.
                    promotions.c.promotion_sha256 == promoted.bundle_sha256,
                    promotions.c.promotion_state == "active-local-lab",
                ))).one_or_none()
                if attestation is None:
                    raise ApiError(403, "nuclei_target_attestation_required", "An active owned-fixture attestation is required.")
                if decision is None:
                    raise ApiError(403, "nuclei_policy_decision_required", "A current profile-bound policy decision is required.")
                if roe is None:
                    raise ApiError(403, "nuclei_roe_approval_required", "An approved ROE version is required.")
                if promotion is None:
                    raise ApiError(403, "nuclei_bundle_promotion_required", "An active signed bundle promotion is required.")
                row = await NucleiRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                ).store_plan(plan_id=payload.plan_id, compiled=compiled, target=target,
                             authorization=authorization, occurred_at=now)
        except NucleiRepositoryConflict as exc:
            raise ApiError(409, "nuclei_plan_conflict", str(exc)) from exc
        return {"data": _public_nuclei_plan(row, payload.profile_id, payload.bundle_id)}

    @app.post(
        "/api/v1/nuclei/runs",
        operation_id="create_nuclei_run",
        response_model=NucleiRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def create_nuclei_run(
        payload: NucleiRunCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = NucleiRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                )
                row = await repository.create_run(
                    run_id=payload.run_id, plan_id=payload.plan_id,
                    job_id=payload.job_id, runner_id=payload.runner_id, occurred_at=_now(),
                )
        except NucleiRepositoryConflict as exc:
            raise ApiError(409, "nuclei_run_conflict", str(exc)) from exc
        return {"data": _public_nuclei_run(row, payload.plan_id)}

    @app.post(
        "/api/v1/nuclei/runs/{run_id}/cancel",
        operation_id="cancel_nuclei_run",
        response_model=NucleiRunResponse,
    )
    async def cancel_nuclei_run(
        run_id: str,
        payload: NucleiCancelRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = NucleiRepository(
                    session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
                )
                row = await repository.request_cancel(
                    run_id=run_id, expected_version=payload.expected_version,
                    reason_code="operator_cancel_requested", occurred_at=_now(),
                )
                plans = metadata.tables["nuclei_compiled_plans"]
                plan = (await session.execute(select(plans.c.plan_id).where(
                    plans.c.tenant_id == guard.security.tenant_id,
                    plans.c.id == row["plan_record_id"],
                ))).one()
                job = (await session.execute(select(metadata.tables["jobs"].c.workflow_id).where(
                    metadata.tables["jobs"].c.tenant_id == guard.security.tenant_id,
                    metadata.tables["jobs"].c.id == row["job_id"],
                ))).one_or_none()
            if job is None or not job.workflow_id:
                raise ApiError(503, "nuclei_workflow_missing", "The bound durable workflow is unavailable.")
            await _orchestration(request).stop_job(
                str(job.workflow_id),
                EmergencyStopSignal(
                    CONTRACT_SCHEMA_VERSION, f"nuclei-cancel-{run_id}"[:100],
                    guard.security.subject, guard.policy_reference, payload.reason,
                ),
            )
        except NucleiRepositoryConflict as exc:
            raise ApiError(409, "nuclei_cancel_conflict", str(exc)) from exc
        return {"data": _public_nuclei_run(row, str(plan.plan_id))}

    @app.get(
        "/api/v1/nuclei/dashboard",
        operation_id="get_nuclei_dashboard",
        response_model=NucleiDashboardResponse,
    )
    async def get_nuclei_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await NucleiRepository(
                session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
            ).dashboard()
        profiles = {row["id"]: row for row in data["profiles"]}
        plans = {row["id"]: row for row in data["plans"]}
        return {"data": {
            "profiles": [_public_nuclei_profile(row) for row in data["profiles"]],
            "plans": [_public_nuclei_plan(
                row, str(profiles[row["profile_record_id"]]["profile_id"]),
                str(row["compiled_plan"]["bundle_id"]),
            ) for row in data["plans"]],
            "runs": [_public_nuclei_run(row, str(plans[row["plan_record_id"]]["plan_id"])) for row in data["runs"]],
            "results": [{key: row[key] for key in (
                "result_id", "template_id", "matcher_name", "severity", "affected_resource",
                "fingerprint", "evidence_instance_id",
            )} for row in data["results"]],
            "cleanups": [{key: row[key] for key in (
                "receipt_id", "residual_resource_count", "cleanup_complete", "completed_at",
            )} for row in data["cleanups"]],
            "target_options": [{key: row[key] for key in (
                "target_id", "attestation_sha256", "attestation_state", "non_production", "expires_at",
            )} for row in data["target_options"]],
            "runner_options": [{key: row[key] for key in (
                "runner_id", "environment", "network_plane", "required_policy_revision",
                "registration_state", "expires_at",
            )} for row in data["runner_options"]],
            "job_options": [{"job_id": row["id"], **{key: row[key] for key in (
                "engagement_id", "roe_version_id", "status", "current_gate", "dispatch_blocked", "stop_requested",
            )}} for row in data["job_options"]],
        }}
