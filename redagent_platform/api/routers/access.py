"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ActivityListResponse,
    ApiError,
    AsyncSession,
    ContextResponse,
    Depends,
    EngagementCreateRequest,
    EngagementListResponse,
    EngagementMutationResponse,
    EngagementResponse,
    EngagementUpdateRequest,
    IdentityRepository,
    JitGrantApprovalRequest,
    JitGrantCreateRequest,
    JitGrantListResponse,
    JitGrantMutationResponse,
    JitGrantReviewRequest,
    JitGrantRevokeRequest,
    MembershipListResponse,
    PaginationQuery,
    Request,
    RequestGuard,
    RoeApprovalRequest,
    RoeVersionCreateRequest,
    RoeVersionListResponse,
    RoeVersionMutationResponse,
    SecurityContext,
    TargetCreateRequest,
    TargetListResponse,
    TargetMutationResponse,
    _idempotency,
    _list_response,
    _match_roe_reference,
    _mutation_response,
    _now,
    _probe_limit,
    _repository,
    status,
)

def _identity_repository(session: AsyncSession, guard: RequestGuard) -> IdentityRepository:
    return IdentityRepository(
        session,
        tenant_id=guard.security.tenant_id,
        actor_user_id=guard.security.subject,
        correlation_id=guard.correlation_id,
    )


def register_access_context_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    require_security_context = dependencies.require_security_context
    resolved_operator_shell_context = dependencies.resolved_operator_shell_context
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/engagements",
        operation_id="list_engagements",
        response_model=EngagementListResponse,
    )
    async def list_engagements(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("engagement:read")),
    ) -> dict:
        async with session_scope(request) as session:
            repo = _repository(session, guard)
            rows = await repo.list_engagements(
                limit=_probe_limit(query), offset=query.offset, name_prefix=query.query
            )
        return _list_response(rows, query)

    @app.get("/api/v1/context", operation_id="get_console_context", response_model=ContextResponse)
    async def get_console_context(
        request: Request,
        security: SecurityContext = Depends(require_security_context),
    ) -> dict[str, object]:
        resolved = getattr(request.state, "identity", None)
        roles = list(resolved.principal.roles) if resolved is not None else []
        return {
            "data": {
                "subject": security.subject,
                "tenant_id": security.tenant_id,
                "permissions": sorted(security.permissions),
                "roles": roles,
                # CRITICAL: shell safety identity is server-composed; never accept a client default.
                "operator_shell": resolved_operator_shell_context.model_dump(),
            }
        }

    @app.get(
        "/api/v1/identity/memberships",
        operation_id="list_identity_memberships",
        response_model=MembershipListResponse,
    )
    async def list_identity_memberships(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("membership:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            rows = await _identity_repository(session, guard).list_memberships(
                limit=_probe_limit(query), offset=query.offset
            )
        return _list_response(rows, query)


def register_access_management_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get(
        "/api/v1/jit-grants",
        operation_id="list_jit_grants",
        response_model=JitGrantListResponse,
    )
    async def list_jit_grants(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("jit:read")),
    ) -> dict[str, object]:
        include_all = bool(
            guard.security.permissions & {"jit:approve", "jit:review", "jit:revoke"}
        )
        async with session_scope(request) as session:
            rows = await _identity_repository(session, guard).list_jit_grants(
                requester_user_id=guard.security.subject,
                include_all=include_all,
                limit=_probe_limit(query),
                offset=query.offset,
            )
        return _list_response(rows, query)

    @app.post(
        "/api/v1/jit-grants",
        operation_id="request_jit_grant",
        status_code=status.HTTP_201_CREATED,
        response_model=JitGrantMutationResponse,
    )
    async def request_jit_grant(
        payload: JitGrantCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("jit:request", mutation=True)),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            repo = _identity_repository(session, guard)
            result = await repo.request_jit_grant(
                **payload.model_dump(),
                requester_user_id=guard.security.subject,
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)

    @app.post(
        "/api/v1/jit-grants/{grant_id}/approve",
        operation_id="approve_jit_grant",
        response_model=JitGrantMutationResponse,
    )
    async def approve_jit_grant(
        grant_id: str,
        payload: JitGrantApprovalRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("jit:approve", mutation=True)),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            repo = _identity_repository(session, guard)
            result = await repo.approve_jit_grant(
                grant_id=grant_id,
                approver_user_id=guard.security.subject,
                expected_version=payload.expected_version,
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)

    @app.post(
        "/api/v1/jit-grants/{grant_id}/revoke",
        operation_id="revoke_jit_grant",
        response_model=JitGrantMutationResponse,
    )
    async def revoke_jit_grant(
        grant_id: str,
        payload: JitGrantRevokeRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("jit:revoke", mutation=True)),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            repo = _identity_repository(session, guard)
            result = await repo.revoke_jit_grant(
                grant_id=grant_id,
                expected_version=payload.expected_version,
                reason=payload.reason,
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)

    @app.post(
        "/api/v1/jit-grants/{grant_id}/review",
        operation_id="review_break_glass_grant",
        response_model=JitGrantMutationResponse,
    )
    async def review_break_glass_grant(
        grant_id: str,
        payload: JitGrantReviewRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("jit:review", mutation=True)),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            repo = _identity_repository(session, guard)
            result = await repo.review_break_glass(
                grant_id=grant_id,
                reviewer_user_id=guard.security.subject,
                **payload.model_dump(),
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)

    @app.get(
        "/api/v1/activity",
        operation_id="list_console_activity",
        response_model=ActivityListResponse,
    )
    async def list_console_activity(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("audit:read")),
    ) -> dict[str, object]:
        async with session_scope(request) as session:
            rows = await _identity_repository(session, guard).list_activity(
                limit=_probe_limit(query), offset=query.offset
            )
        return _list_response(rows, query)

    @app.post(
        "/api/v1/engagements",
        status_code=status.HTTP_201_CREATED,
        operation_id="create_engagement",
        response_model=EngagementMutationResponse,
    )
    async def create_engagement(
        payload: EngagementCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("engagement:create", mutation=True)),
    ) -> dict:
        async with session_scope(request) as session:
            result = await _repository(session, guard).create_engagement(
                **payload.model_dump(),
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)

    @app.get(
        "/api/v1/engagements/{engagement_id}",
        operation_id="get_engagement",
        response_model=EngagementResponse,
    )
    async def get_engagement(
        engagement_id: str,
        request: Request,
        guard: RequestGuard = Depends(require_guard("engagement:read")),
    ) -> dict:
        async with session_scope(request) as session:
            resource = await _repository(session, guard).get_engagement(engagement_id)
        if resource is None:
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        return {"data": resource}

    @app.patch(
        "/api/v1/engagements/{engagement_id}",
        operation_id="update_engagement",
        response_model=EngagementMutationResponse,
    )
    async def update_engagement(
        engagement_id: str,
        payload: EngagementUpdateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("engagement:update", mutation=True)),
    ) -> dict:
        async with session_scope(request) as session:
            result = await _repository(session, guard).update_engagement(
                engagement_id=engagement_id,
                **payload.model_dump(),
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)

    @app.get(
        "/api/v1/engagements/{engagement_id}/targets",
        operation_id="list_targets",
        response_model=TargetListResponse,
    )
    async def list_targets(
        engagement_id: str,
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("target:read")),
    ) -> dict:
        async with session_scope(request) as session:
            rows = await _repository(session, guard).list_targets(
                engagement_id, limit=_probe_limit(query), offset=query.offset
            )
        return _list_response(rows, query)

    @app.post(
        "/api/v1/engagements/{engagement_id}/targets",
        status_code=status.HTTP_201_CREATED,
        operation_id="create_target",
        response_model=TargetMutationResponse,
    )
    async def create_target(
        engagement_id: str,
        payload: TargetCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("target:create", mutation=True)),
    ) -> dict:
        async with session_scope(request) as session:
            result = await _repository(session, guard).create_target(
                engagement_id=engagement_id,
                **payload.model_dump(),
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)

    @app.get(
        "/api/v1/engagements/{engagement_id}/roe-versions",
        operation_id="list_roe_versions",
        response_model=RoeVersionListResponse,
    )
    async def list_roe_versions(
        engagement_id: str,
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("roe:read")),
    ) -> dict:
        async with session_scope(request) as session:
            rows = await _repository(session, guard).list_roe_versions(
                engagement_id, limit=_probe_limit(query), offset=query.offset
            )
        return _list_response(rows, query)

    @app.post(
        "/api/v1/engagements/{engagement_id}/roe-versions",
        status_code=status.HTTP_201_CREATED,
        operation_id="create_roe_version",
        response_model=RoeVersionMutationResponse,
    )
    async def create_roe_version(
        engagement_id: str,
        payload: RoeVersionCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("roe:create", mutation=True)),
    ) -> dict:
        async with session_scope(request) as session:
            result = await _repository(session, guard).create_roe_version(
                engagement_id=engagement_id,
                **payload.model_dump(),
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)

    @app.post(
        "/api/v1/roe-versions/{roe_version_id}/approve",
        operation_id="approve_roe_version",
        response_model=RoeVersionMutationResponse,
    )
    async def approve_roe_version(
        roe_version_id: str,
        payload: RoeApprovalRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("roe:approve", mutation=True, roe_required=True)),
    ) -> dict:
        _match_roe_reference(guard, roe_version_id)
        async with session_scope(request) as session:
            result = await _repository(session, guard).approve_roe_version(
                roe_version_id=roe_version_id,
                **payload.model_dump(),
                idempotency_key=_idempotency(guard),
                occurred_at=_now(),
            )
        return _mutation_response(result)
