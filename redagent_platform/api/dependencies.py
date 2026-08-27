"""Shared request-time dependencies for the control-plane API routers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from contextlib import asynccontextmanager
from datetime import (
    datetime,
    timezone,
)
from fastapi import (
    Depends,
    Header,
    Request,
)
import inspect
from redagent_platform.api.contracts import (
    ApiError,
    AuthorizationDecision,
    AuthorizationHook,
    RequestGuard,
    SecurityContext,
    _valid_context_value,
)
from redagent_platform.api.router_primitives import _now
from redagent_platform.api.schemas.access import OperatorShellContextData
from redagent_platform.evidence_service.service import EvidenceService
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from typing import AsyncIterator


@dataclass(frozen=True)
class ApiDependencies:
    require_security_context: Callable[..., Any]
    session_scope: Callable[..., Any]
    evidence_service: Callable[..., Any]
    enforce_workflow_boundary: Callable[..., Any]
    require_guard: Callable[..., Any]
    resolved_operator_shell_context: OperatorShellContextData
    test_issuer_enabled: bool


def build_api_dependencies(
    *,
    test_issuer_enabled: bool,
    authorization_hook: AuthorizationHook | None,
    identity_runtime: object | None,
    resolved_operator_shell_context: OperatorShellContextData,
) -> ApiDependencies:
    async def require_security_context(
        request: Request,
        subject: str | None = Header(default=None, alias="X-RedAgent-Test-Subject"),
        tenant: str | None = Header(default=None, alias="X-RedAgent-Test-Tenant"),
        permissions: str | None = Header(default=None, alias="X-RedAgent-Test-Permissions"),
    ) -> SecurityContext:
        if identity_runtime is not None and not test_issuer_enabled:
            resolved = await identity_runtime.resolve_request(request)
            if resolved is None:
                raise ApiError(401, "security_context_required", "Validated security context is required.")
            request.state.identity = resolved
            return SecurityContext(
                resolved.subject,
                resolved.tenant_id,
                resolved.permissions,
            )
        if not test_issuer_enabled:
            raise ApiError(401, "production_identity_not_configured", "Production identity is not configured.")
        if not subject or not tenant:
            raise ApiError(401, "security_context_required", "Validated security context is required.")
        if not _valid_context_value(subject, 64) or not _valid_context_value(tenant, 64):
            raise ApiError(401, "security_context_invalid", "Validated security context is invalid.")
        if permissions is not None and len(permissions) > 2000:
            raise ApiError(401, "security_context_invalid", "Validated security context is invalid.")
        parsed = frozenset(item.strip() for item in (permissions or "").split(",") if item.strip())
        if any(not _valid_context_value(item, 100) for item in parsed):
            raise ApiError(401, "security_context_invalid", "Validated security context is invalid.")
        return SecurityContext(subject, tenant, parsed)

    @asynccontextmanager
    async def session_scope(request: Request) -> AsyncIterator[AsyncSession]:
        factory = request.app.state.session_factory
        if factory is None:
            raise ApiError(503, "database_not_configured", "Control-plane database is not configured.")
        try:
            async with factory() as session:
                async with session.begin():
                    yield session
        except (SQLAlchemyError, OSError) as exc:
            raise ApiError(503, "database_unavailable", "The control-plane database is unavailable.") from exc

    def evidence_service(request: Request) -> EvidenceService:
        factory = request.app.state.session_factory
        backend = request.app.state.evidence_backend
        if factory is None:
            raise ApiError(503, "database_not_configured", "Control-plane database is not configured.")
        if backend is None:
            raise ApiError(503, "evidence_backend_not_configured", "Evidence storage is not configured.")
        return EvidenceService(factory, backend, request.app.state.policy_sdk)

    async def enforce_workflow_boundary(
        request: Request,
        guard: RequestGuard,
        *,
        job_id: str,
        action: str,
        job_status: str,
        expected_version: int,
        dispatch_blocked: bool,
        roe_version_id: str,
    ) -> None:
        policy_sdk = request.app.state.policy_sdk
        if policy_sdk is None:
            if request.app.state.policy_required:
                raise ApiError(503, "policy_unavailable", "Policy enforcement is unavailable.")
            return
        await policy_sdk.enforce_workflow(
            tenant_id=guard.security.tenant_id,
            subject_id=guard.security.subject,
            action=action,
            job_id=job_id,
            job_status=job_status,
            expected_version=expected_version,
            dispatch_blocked=dispatch_blocked,
            policy_reference=guard.policy_reference,
            roe_version_id=roe_version_id,
            roe_status="current",
            correlation_id=guard.correlation_id,
            requested_at=_now(),
        )

    async def default_authorize(context: SecurityContext, permission: str, object_id: str | None) -> bool:
        return permission in context.permissions

    authorize = authorization_hook or default_authorize

    def require_guard(
        permission: str,
        *,
        mutation: bool = False,
        roe_required: bool = False,
        safety_preserving: bool = False,
    ):
        async def dependency(
            request: Request,
            security: SecurityContext = Depends(require_security_context),
            policy_reference: str | None = Header(default=None, alias="X-RedAgent-Policy-Reference"),
            roe_header: str | None = Header(default=None, alias="X-RedAgent-ROE-Version"),
            idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        ) -> RequestGuard:
            object_id = next((str(value) for key, value in request.path_params.items() if key.endswith("_id")), None)
            allowed = authorize(security, permission, object_id)
            if inspect.isawaitable(allowed):
                allowed = await allowed
            decision = AuthorizationDecision(permission, object_id, bool(allowed))
            if not decision.allowed:
                raise ApiError(403, "permission_denied", "The security context does not permit this operation.")
            if (
                mutation
                and identity_runtime is not None
                and not test_issuer_enabled
                and request.state.identity.is_browser
            ):
                try:
                    identity_runtime.enforce_csrf(request, request.state.identity)
                except Exception as exc:
                    raise ApiError(403, "csrf_rejected", "The browser request failed CSRF validation.") from exc
            if mutation:
                if not policy_reference or not _valid_context_value(policy_reference, 200):
                    raise ApiError(400, "policy_reference_required", "A validated policy reference is required.")
            normalized_policy = policy_reference or "read-only"
            if roe_required and (not roe_header or not _valid_context_value(roe_header, 64)):
                raise ApiError(400, "roe_reference_required", "A validated ROE version reference is required.")
            if mutation:
                if not idempotency_key or not idempotency_key.strip():
                    raise ApiError(400, "idempotency_key_required", "Idempotency-Key is required for mutations.")
                if not _valid_context_value(idempotency_key, 200):
                    raise ApiError(400, "idempotency_key_invalid", "Idempotency-Key is invalid.")
            policy_sdk = request.app.state.policy_sdk
            if request.app.state.policy_required and policy_sdk is None and not safety_preserving:
                raise ApiError(503, "policy_unavailable", "Policy enforcement is unavailable.")
            if policy_sdk is not None and not safety_preserving:
                resolved = getattr(request.state, "identity", None)
                roles = tuple(resolved.principal.roles) if resolved is not None else ("test-operator",)
                resource_type = permission.partition(":")[0]
                await policy_sdk.enforce_api(
                    tenant_id=security.tenant_id,
                    subject_id=security.subject,
                    roles=roles or ("authenticated",),
                    permissions=tuple(sorted(security.permissions)),
                    action=permission,
                    resource_type=resource_type,
                    resource_id=object_id or f"{resource_type}-collection",
                    resource_version=None,
                    policy_reference=normalized_policy,
                    roe_version_id=roe_header,
                    correlation_id=request.state.correlation_id,
                    requested_at=datetime.now(timezone.utc),
                )
            return RequestGuard(
                security=security,
                decision=decision,
                policy_reference=normalized_policy,
                roe_version_id=roe_header,
                correlation_id=request.state.correlation_id,
                audit_intent=permission,
                idempotency_key=idempotency_key,
            )

        return dependency

    return ApiDependencies(
        require_security_context=require_security_context,
        session_scope=session_scope,
        evidence_service=evidence_service,
        enforce_workflow_boundary=enforce_workflow_boundary,
        require_guard=require_guard,
        resolved_operator_shell_context=resolved_operator_shell_context,
        test_issuer_enabled=test_issuer_enabled,
    )
