"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiError,
    AttestedFakeWorkload,
    Depends,
    LeaseIssueRequest,
    PaginationQuery,
    Request,
    RequestGuard,
    SecretLeaseBroker,
    SecretLeaseListResponse,
    SecretLeaseResponse,
    SecretReference,
    SecretReferenceKind,
    SecretReferenceListResponse,
    SecretReferenceStatus,
    SecretRevokeRequest,
    SecretSyntheticIssueRequest,
    TransactionalSecretLeaseStore,
    WorkloadClient,
    _idempotency,
    _list_response,
    _now,
    _probe_limit,
    hashlib,
    status,
    timedelta,
)

def _secret_store(request: Request) -> TransactionalSecretLeaseStore:
    factory = request.app.state.session_factory
    if factory is None:
        raise ApiError(503, "database_not_configured", "Control-plane database is not configured.")
    return TransactionalSecretLeaseStore(factory)


def _public_secret_reference(row: dict[str, object]) -> dict[str, object]:
    return {
        "reference_id": row["id"], "tenant_id": row["tenant_id"],
        "engagement_id": row["engagement_id"], "reference_kind": row["reference_kind"],
        "provider_alias": row["provider_alias"], "allowed_capabilities": row["allowed_capabilities"],
        "allowed_permissions": row["allowed_permissions"], "expires_at": row["expires_at"],
        "rotation_due_at": row["rotation_due_at"], "reference_status": row["reference_status"],
        "redaction_label": row["redaction_label"], "version": row["version"],
    }


def _public_secret_lease(row: dict[str, object]) -> dict[str, object]:
    return {
        "lease_id": row["id"], "tenant_id": row["tenant_id"], "reference_id": row["reference_id"],
        "engagement_id": row["engagement_id"], "job_id": row["job_id"],
        "workload_client_id": row["workload_client_id"], "capability": row["capability"],
        "permission_count": row["permission_count"], "issued_at": row["issued_at"],
        "expires_at": row["expires_at"], "renewed_at": row["renewed_at"], "revoked_at": row["revoked_at"],
        "renewable": row["renewable"], "renewal_count": row["renewal_count"],
        "lease_state": row["lease_state"], "policy_reference": row["policy_reference"],
        "roe_version_id": row["roe_version_id"], "failure_code": row["failure_code"], "version": row["version"],
    }


def register_secret_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard

    @app.get(
        "/api/v1/secret-references",
        operation_id="list_secret_references",
        response_model=SecretReferenceListResponse,
    )
    async def list_secret_references(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("secret:read")),
    ) -> dict:
        store = _secret_store(request)
        rows = await store.list_references(
            tenant_id=guard.security.tenant_id,
            limit=_probe_limit(query),
            offset=query.offset,
        )
        return _list_response([_public_secret_reference(row) for row in rows], query)

    @app.get(
        "/api/v1/secret-leases",
        operation_id="list_secret_leases",
        response_model=SecretLeaseListResponse,
    )
    async def list_secret_leases(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("secret:read")),
    ) -> dict:
        store = _secret_store(request)
        rows = await store.list_leases(
            tenant_id=guard.security.tenant_id,
            limit=_probe_limit(query),
            offset=query.offset,
        )
        return _list_response([_public_secret_lease(row) for row in rows], query)

    @app.post(
        "/api/v1/secret-leases/synthetic",
        operation_id="issue_synthetic_secret_lease",
        status_code=status.HTTP_201_CREATED,
        response_model=SecretLeaseResponse,
    )
    async def issue_synthetic_secret_lease(
        payload: SecretSyntheticIssueRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("secret:issue", mutation=True, roe_required=True)),
    ) -> dict:
        if not request.app.state.synthetic_secret_enabled:
            raise ApiError(404, "synthetic_secret_disabled", "Synthetic secret issuance is disabled.")
        provider = request.app.state.secret_provider
        if provider is None:
            raise ApiError(503, "secret_provider_not_configured", "Secret provider is not configured.")
        store = _secret_store(request)
        now = await store.issue_requested_at(
            tenant_id=guard.security.tenant_id, idempotency_key=_idempotency(guard)
        ) or _now()
        deadline = now + timedelta(seconds=payload.ttl_seconds)
        attestation = hashlib.sha256(
            f"{guard.security.tenant_id}:{payload.job_id}:{payload.workload_client_id}".encode()
        ).hexdigest()
        await store.register_reference(
            SecretReference(
                tenant_id=guard.security.tenant_id, reference_id=payload.reference_id,
                engagement_id=payload.engagement_id, owner_user_id=guard.security.subject,
                kind=SecretReferenceKind.DYNAMIC_DATABASE, provider_alias="synthetic-local",
                role_reference="role:database-readonly-v1", allowed_capabilities=("synthetic-noop",),
                allowed_permissions=("read",), created_at=now, expires_at=now + timedelta(hours=1),
                rotation_due_at=now + timedelta(minutes=30), status=SecretReferenceStatus.ACTIVE,
                redaction_label="synthetic-database-reference",
            ),
            actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
        )
        await store.register_workload(
            WorkloadClient(
                tenant_id=guard.security.tenant_id, client_id=payload.workload_client_id,
                job_id=payload.job_id, capability="synthetic-noop",
                attestation_fingerprint=attestation, expires_at=deadline, revoked_at=None,
            ),
            actor_user_id=guard.security.subject, correlation_id=guard.correlation_id, occurred_at=now,
        )
        result = await SecretLeaseBroker(
            store, provider,
            AttestedFakeWorkload(client_id=payload.workload_client_id, attestation_fingerprint=attestation),
            request.app.state.policy_sdk,
        ).issue(
            LeaseIssueRequest(
                tenant_id=guard.security.tenant_id, lease_id=payload.lease_id,
                reference_id=payload.reference_id, engagement_id=payload.engagement_id,
                job_id=payload.job_id, workload_client_id=payload.workload_client_id,
                capability="synthetic-noop", requested_permissions=("read",), requested_at=now,
                ttl_seconds=payload.ttl_seconds, job_deadline=deadline, policy_expires_at=deadline,
                roe_expires_at=deadline, policy_reference=guard.policy_reference,
                roe_version_id=str(guard.roe_version_id), idempotency_key=_idempotency(guard),
            ),
            actor_user_id=guard.security.subject, correlation_id=guard.correlation_id,
        )
        return {"data": _public_secret_lease(result.lease), "meta": {"replayed": result.replayed}}

    @app.post(
        "/api/v1/secret-leases/{lease_id}/revoke",
        operation_id="revoke_secret_lease",
        response_model=SecretLeaseResponse,
    )
    async def revoke_secret_lease(
        lease_id: str,
        payload: SecretRevokeRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("secret:revoke", mutation=True)),
    ) -> dict:
        provider = request.app.state.secret_provider
        if provider is None:
            raise ApiError(503, "secret_provider_not_configured", "Secret provider is not configured.")
        result = await SecretLeaseBroker(
            _secret_store(request), provider, None, request.app.state.policy_sdk,
        ).revoke(
            tenant_id=guard.security.tenant_id, lease_id=lease_id,
            expected_version=payload.expected_version, actor_user_id=guard.security.subject,
            correlation_id=guard.correlation_id, occurred_at=_now(),
        )
        return {"data": _public_secret_lease(result.lease), "meta": {"replayed": result.replayed}}
