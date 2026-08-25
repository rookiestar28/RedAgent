"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiError,
    AsyncSession,
    Depends,
    PaginationQuery,
    PolicyAdministrationRepository,
    PolicyBundleListResponse,
    PolicyDecisionListResponse,
    PolicyPromotionRequest,
    PolicyPromotionResponse,
    PolicySimulationRequest,
    PolicySimulationResponse,
    PolicyStatusResponse,
    Request,
    RequestGuard,
    _idempotency,
    _list_response,
    _now,
    _probe_limit,
)

def _policy_administration(session: AsyncSession, guard: RequestGuard) -> PolicyAdministrationRepository:
    return PolicyAdministrationRepository(
        session,
        tenant_id=guard.security.tenant_id,
        actor_user_id=guard.security.subject,
        correlation_id=guard.correlation_id,
    )


def _public_policy_decision(row: dict[str, object]) -> dict[str, object]:
    return {
        "decision_id": row["opa_decision_id"], "bundle_revision": row["bundle_revision"],
        "input_hash": row["input_hash"], "boundary": row["boundary"], "action": row["action"],
        "subject_id": row["subject_id"], "resource_type": row["resource_type"],
        "resource_id": row["resource_id"], "allowed": row["allowed"],
        "reason_code": row["reason_code"], "obligations": row["obligations"],
        "issued_at": row["issued_at"], "valid_until": row["valid_until"],
        "correlation_id": row["correlation_id"],
    }


def _public_policy_bundle(row: dict[str, object]) -> dict[str, object]:
    return {
        "revision": row["revision_name"], "artifact_sha256": row["artifact_sha256"],
        "artifact_size": row["artifact_size"], "rego_version": row["rego_version"],
        "signing_key_id": row["signing_key_id"], "author_user_id": row["author_user_id"],
        "reviewer_user_id": row["reviewer_user_id"],
        "coverage_basis_points": row["coverage_basis_points"], "status": row["bundle_status"],
        "version": row["version"], "created_at": row["created_at"],
    }


def _public_policy_promotion(row: dict[str, object]) -> dict[str, object]:
    return {
        "revision": row["bundle_revision"], "previous_revision": row["previous_revision"],
        "state": row["promotion_state"], "required_agents": row["required_agents"],
        "acknowledged_agents": row["acknowledged_agents"], "promoted_at": row["promoted_at"],
        "version": row["version"],
    }


def register_policy_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/policy/status",
        operation_id="get_policy_status",
        response_model=PolicyStatusResponse,
    )
    async def get_policy_status(
        request: Request,
        guard: RequestGuard = Depends(require_guard("policy:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            data = await _policy_administration(session, guard).status(
                fallback_required_revision=(
                    request.app.state.policy_sdk.required_revision
                    if request.app.state.policy_sdk is not None else "not-configured"
                )
            )
        return {"data": data}

    @app.get(
        "/api/v1/policy/decisions",
        operation_id="list_policy_decisions",
        response_model=PolicyDecisionListResponse,
    )
    async def list_policy_decisions(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("policy:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            rows = await _policy_administration(session, guard).list_decisions(
                limit=_probe_limit(query), offset=query.offset,
            )
        return _list_response([_public_policy_decision(row) for row in rows], query)

    @app.get(
        "/api/v1/policy/bundles",
        operation_id="list_policy_bundles",
        response_model=PolicyBundleListResponse,
    )
    async def list_policy_bundles(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("policy:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            rows = await _policy_administration(session, guard).list_bundles(
                limit=_probe_limit(query), offset=query.offset,
            )
        return _list_response([_public_policy_bundle(row) for row in rows], query)

    @app.post(
        "/api/v1/policy/simulations",
        operation_id="simulate_policy_fixture",
        response_model=PolicySimulationResponse,
    )
    async def simulate_policy_fixture(
        payload: PolicySimulationRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("policy:simulate", mutation=True)),
    ) -> dict[str, object]:
        sdk = request.app.state.policy_sdk
        if sdk is None:
            raise ApiError(503, "policy_unavailable", "Policy enforcement is unavailable.")
        now = _now()
        if payload.fixture == "api-job-create":
            result = await sdk.enforce_api(
                tenant_id=guard.security.tenant_id, subject_id=guard.security.subject,
                roles=("policy-simulator",), permissions=("job:create",), action="job.create",
                resource_type="job", resource_id="fixture-job", resource_version=1,
                policy_reference=guard.policy_reference, roe_version_id="fixture-roe",
                correlation_id=guard.correlation_id, requested_at=now,
            )
        elif payload.fixture == "workflow-job-command":
            result = await sdk.enforce_workflow(
                tenant_id=guard.security.tenant_id, subject_id=guard.security.subject,
                action="job.command", job_id="fixture-job", job_status="pending",
                expected_version=1, dispatch_blocked=True,
                policy_reference=guard.policy_reference, roe_version_id="fixture-roe",
                roe_status="current", correlation_id=guard.correlation_id, requested_at=now,
            )
        elif payload.fixture == "evidence-write":
            result = await sdk.enforce_evidence(
                tenant_id=guard.security.tenant_id, subject_id=guard.security.subject,
                action="evidence.write", artifact_id="fixture-artifact", artifact_class="redacted",
                classification="restricted", legal_hold=False,
                policy_reference=guard.policy_reference, roe_version_id="fixture-roe",
                correlation_id=guard.correlation_id, requested_at=now,
            )
        else:
            result = await sdk.enforce_secret(
                tenant_id=guard.security.tenant_id, subject_id=guard.security.subject,
                action="secret.lease", lease_id="fixture-lease", reference_status="active",
                lease_state="pending", renewable=True, revoke_pending=False,
                permission_digest="0" * 64, permission_count=1, workload_client_status="active",
                policy_reference=guard.policy_reference, roe_version_id="fixture-roe",
                correlation_id=guard.correlation_id, requested_at=now,
            )
        return {"data": {
            "fixture": payload.fixture,
            "decision_id": result.decision_id,
            "receipt_id": result.receipt_id,
            "bundle_revision": result.bundle_revision,
            "input_hash": result.input_hash,
            "obligations": list(result.obligations),
        }}

    @app.post(
        "/api/v1/policy/promotions",
        operation_id="promote_policy_bundle",
        response_model=PolicyPromotionResponse,
    )
    async def promote_policy_bundle(
        payload: PolicyPromotionRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("policy:promote", mutation=True)),
    ) -> dict[str, object]:
        return await _promote_policy(request, guard, payload, rollback=False)

    @app.post(
        "/api/v1/policy/rollbacks",
        operation_id="rollback_policy_bundle",
        response_model=PolicyPromotionResponse,
    )
    async def rollback_policy_bundle(
        payload: PolicyPromotionRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("policy:rollback", mutation=True)),
    ) -> dict[str, object]:
        return await _promote_policy(request, guard, payload, rollback=True)

    async def _promote_policy(
        request: Request, guard: RequestGuard, payload: PolicyPromotionRequest, *, rollback: bool,
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            row = await _policy_administration(session, guard).promote(
                revision=payload.revision, expected_version=payload.expected_version,
                idempotency_key=_idempotency(guard), reason=payload.reason,
                rollback=rollback, occurred_at=_now(),
            )
        return {"data": _public_policy_promotion(row), "meta": {"replayed": False}}
