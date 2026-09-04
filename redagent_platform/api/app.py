"""FastAPI control-plane application assembly."""

from __future__ import annotations

from typing import TYPE_CHECKING, Awaitable, Callable

from contextlib import asynccontextmanager
from fastapi import (
    FastAPI,
    Request,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import inspect
from pathlib import Path
from redagent_platform.api.contracts import (
    ApiError,
    AuthorizationHook,
    R123ApiServiceFactory,
    _valid_context_value,
)
from redagent_platform.api.openapi_compatibility import install_legacy_component_name_compatibility
from redagent_platform.api.router_primitives import _list_response
from redagent_platform.api.schemas.access import OperatorShellContextData
from redagent_platform.api.static_assets import (
    _install_static_routes,
    _is_hashed_asset,
    _static_root,
)
from redagent_platform.api.workbench_fixtures import (
    _fixture_draft_binding,
    _matches_fixture_draft_binding,
    _matches_fixture_successor_plan,
)
from redagent_platform.campaign_service.api import build_campaign_router
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_service import (
    AutonomousCampaignApplicationService,
)
from redagent_platform.campaign_service.approval_api import register_autonomous_campaign_approval_routes
from redagent_platform.campaign_service.composition import CampaignApiRuntimeServices
from redagent_platform.campaign_service.qualification import (
    CampaignQualificationService,
    CampaignStatusService,
)
from redagent_platform.campaign_service.registry import StrategyLoopMode
from redagent_platform.campaign_service.status import CampaignStatusOwner
from redagent_platform.evidence_service.repository import (
    EvidenceIdempotencyConflict,
    EvidenceRecordConflict,
)
from redagent_platform.identity.repository import IdentityStateConflict
from redagent_platform.orchestration.config import TemporalSettings
from redagent_platform.orchestration.gateway import (
    OrchestrationUnavailable,
    TemporalOrchestrationGateway,
    connect_temporal,
)
from redagent_platform.persistence.database import (
    DatabaseSettings,
    async_engine_options,
)
from redagent_platform.persistence.repository import (
    ConcurrencyConflict,
    IdempotencyConflict,
    RecordConflict,
)
from redagent_platform.policy_service.boundaries import PolicyBoundarySDK
from redagent_platform.policy_service.enforcement import (
    PolicyBoundaryEnforcer,
    PolicyEnforcementError,
)
from redagent_platform.policy_service.repository import (
    PolicyDecisionConflict,
    TransactionalPolicyDecisionRecorder,
)
from redagent_platform.secret_service.repository import SecretLeaseConflict
from sqlalchemy.exc import (
    IntegrityError,
    SQLAlchemyError,
)
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)
from typing import AsyncIterator
from uuid import uuid4
from redagent_platform.api.dependencies import build_api_dependencies
from redagent_platform.api.routers import (
    register_foundation_routes,
    register_access_context_routes,
    register_policy_routes,
    register_access_management_routes,
    register_job_list_routes,
    register_runner_routes,
    register_job_mutation_routes,
    register_containment_routes,
    register_quota_routes,
    register_observability_dashboard_routes,
    register_lab_routes,
    register_zap_routes,
    register_api_differential_routes,
    register_network_routes,
    register_cloud_routes,
    register_identity_saas_routes,
    register_artifact_routes,
    register_purple_routes,
    register_human_simulation_routes,
    register_agent_tool_routes,
    register_workbench_routes,
    register_finding_operations_routes,
    register_agent_runtime_routes,
    register_nuclei_routes,
    register_observability_incident_routes,
    register_campaign_routes,
    register_evidence_routes,
    register_finding_routes,
    register_secret_routes,
)

if TYPE_CHECKING:
    from redagent_platform.identity.bff import IdentityRuntime


__all__ = (
    "create_app",
    "_list_response",
    "_fixture_draft_binding",
    "_matches_fixture_draft_binding",
    "_matches_fixture_successor_plan",
)


def create_app(
    *,
    test_issuer_enabled: bool = False,
    database_settings: DatabaseSettings | None = None,
    authorization_hook: AuthorizationHook | None = None,
    identity_runtime: "IdentityRuntime | None" = None,
    static_directory: Path | None = None,
    orchestration_gateway: TemporalOrchestrationGateway | None = None,
    temporal_settings: TemporalSettings | None = None,
    evidence_backend: object | None = None,
    evidence_kms_reference: str | None = None,
    synthetic_evidence_enabled: bool = False,
    secret_provider: object | None = None,
    synthetic_secret_enabled: bool = False,
    policy_provider: object | None = None,
    policy_required_revision: str | None = None,
    r123_qualification_service: CampaignQualificationService | None = None,
    r123_status_service: CampaignStatusService | None = None,
    r123_campaign_status_owner: CampaignStatusOwner | None = None,
    r123_service_factory: R123ApiServiceFactory | None = None,
    autonomous_campaign_service_factory: (
        Callable[
            [object],
            AutonomousCampaignApplicationService | Awaitable[AutonomousCampaignApplicationService],
        ]
        | None
    ) = None,
    autonomous_campaign_application_service: AutonomousCampaignApplicationService | None = None,
    r124_campaign_core_service: object | None = None,
    campaign_operations_owner: object | None = None,
    operator_shell_context: OperatorShellContextData | None = None,
) -> FastAPI:
    if r123_service_factory is not None and database_settings is None:
        raise ValueError("r123_api_factory_requires_database")
    if r123_service_factory is not None and any(
        service is not None
        for service in (
            r123_qualification_service,
            r123_status_service,
            r123_campaign_status_owner,
            r124_campaign_core_service,
            campaign_operations_owner,
        )
    ):
        raise ValueError("r123_api_runtime_services_ambiguous")
    if autonomous_campaign_service_factory is not None and database_settings is None:
        raise ValueError("autonomous_campaign_factory_requires_database")
    if autonomous_campaign_service_factory is not None and autonomous_campaign_application_service is not None:
        raise ValueError("autonomous_campaign_runtime_services_ambiguous")
    static_root = _static_root(static_directory)
    resolved_operator_shell_context = operator_shell_context or OperatorShellContextData()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        engine = None
        try:
            if temporal_settings is not None and orchestration_gateway is None:
                client = await connect_temporal(temporal_settings)
                application.state.orchestration_gateway = TemporalOrchestrationGateway(client, temporal_settings)
            if database_settings is not None:
                engine = create_async_engine(database_settings.url, **async_engine_options(database_settings))
                application.state.database_engine = engine
                application.state.session_factory = async_sessionmaker(engine, expire_on_commit=False)
                if policy_provider is not None and policy_required_revision is not None:
                    application.state.policy_sdk = PolicyBoundarySDK(
                        PolicyBoundaryEnforcer(
                            policy_provider,
                            TransactionalPolicyDecisionRecorder(application.state.session_factory),
                        ),
                        required_revision=policy_required_revision,
                    )
                if r123_service_factory is not None:
                    if getattr(
                        r123_service_factory,
                        "_redagent_temporal_readiness_factory",
                        False,
                    ):
                        services = r123_service_factory(
                            application.state.session_factory,
                            application.state.orchestration_gateway,
                        )
                    else:
                        services = r123_service_factory(application.state.session_factory)
                    if inspect.isawaitable(services):
                        services = await services
                    if (
                        not isinstance(services, CampaignApiRuntimeServices)
                        or not isinstance(services.qualification_service, CampaignQualificationService)
                        or not isinstance(services.status_service, CampaignStatusService)
                        or services.status_service.mode is not StrategyLoopMode.TWO_CAPABILITY
                        or not callable(getattr(services.campaign_status_owner, "read", None))
                        or not callable(getattr(services.campaign_core_service, "start_campaign", None))
                        or not callable(getattr(services.campaign_operations_owner, "read", None))
                    ):
                        raise RuntimeError("r123_api_factory_result_invalid")
                    application.state.r123_qualification_service = services.qualification_service
                    application.state.r123_status_service = services.status_service
                    application.state.r123_campaign_status_owner = services.campaign_status_owner
                    application.state.r124_campaign_core_service = services.campaign_core_service
                    application.state.campaign_operations_owner = services.campaign_operations_owner
                if autonomous_campaign_service_factory is not None:
                    application_service = autonomous_campaign_service_factory(application.state.session_factory)
                    if inspect.isawaitable(application_service):
                        application_service = await application_service
                    if (
                        not isinstance(application_service, AutonomousCampaignApplicationService)
                        or application_service.mode is not AutonomousCampaignMode.PLAN_ONLY
                    ):
                        raise RuntimeError("autonomous_campaign_factory_result_invalid")
                    application.state.autonomous_campaign_application_service = application_service
            yield
        finally:
            if r123_service_factory is not None:
                application.state.r123_qualification_service = None
                application.state.r123_campaign_status_owner = None
                application.state.r123_status_service = CampaignStatusService(
                    StrategyLoopMode.DISABLED,
                    None,
                )
                application.state.r124_campaign_core_service = r124_campaign_core_service
                application.state.campaign_operations_owner = campaign_operations_owner
            if autonomous_campaign_service_factory is not None:
                application.state.autonomous_campaign_application_service = autonomous_campaign_application_service
            application.state.session_factory = None
            if engine is not None:
                await engine.dispose()
            policy_client = getattr(policy_provider, "client", None)
            if policy_client is not None and hasattr(policy_client, "aclose"):
                await policy_client.aclose()

    app = FastAPI(
        title="RedAgent Control Plane API",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.state.session_factory = None
    app.state.expected_revision = database_settings.expected_revision if database_settings else None
    app.state.orchestration_gateway = orchestration_gateway
    app.state.temporal_required = temporal_settings is not None or orchestration_gateway is not None
    app.state.evidence_backend = evidence_backend
    app.state.evidence_kms_reference = evidence_kms_reference
    app.state.synthetic_evidence_enabled = synthetic_evidence_enabled
    app.state.secret_provider = secret_provider
    app.state.synthetic_secret_enabled = synthetic_secret_enabled
    app.state.policy_sdk = None
    app.state.policy_required = policy_provider is not None
    app.state.r123_qualification_service = r123_qualification_service
    app.state.r123_campaign_status_owner = r123_campaign_status_owner
    app.state.r123_status_service = r123_status_service or CampaignStatusService(
        StrategyLoopMode.DISABLED,
        None,
    )
    app.state.r124_campaign_core_service = r124_campaign_core_service
    app.state.campaign_operations_owner = campaign_operations_owner
    app.state.autonomous_campaign_application_service = autonomous_campaign_application_service

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        supplied = request.headers.get("X-Correlation-ID", "")
        correlation_id = supplied if _valid_context_value(supplied, 100) else str(uuid4())
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
            if static_root is None
            else (
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; "
                "form-action 'self'; frame-ancestors 'none'"
            )
        )
        response.headers["Cache-Control"] = (
            "public, max-age=31536000, immutable"
            if response.status_code == 200 and _is_hashed_asset(request.url.path)
            else "no-store"
        )
        return response

    def error_response(request: Request, status_code: int, code: str, message: str, **extra) -> JSONResponse:
        error = {
            "code": code,
            "message": message,
            "correlation_id": getattr(request.state, "correlation_id", str(uuid4())),
            **extra,
        }
        return JSONResponse(status_code=status_code, content={"error": error})

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(request, exc.status_code, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {
                "location": ".".join(str(part) for part in error.get("loc", ())),
                "type": str(error.get("type", "invalid")),
            }
            for error in exc.errors()
        ]
        return error_response(
            request,
            422,
            "validation_error",
            "Request validation failed.",
            details=details,
        )

    @app.exception_handler(ConcurrencyConflict)
    async def concurrency_error_handler(request: Request, exc: ConcurrencyConflict) -> JSONResponse:
        return error_response(request, 409, "version_conflict", "The resource version is stale.")

    @app.exception_handler(IdempotencyConflict)
    async def idempotency_error_handler(request: Request, exc: IdempotencyConflict) -> JSONResponse:
        return error_response(request, 409, "idempotency_conflict", "The idempotency key was used for another request.")

    @app.exception_handler(RecordConflict)
    async def record_error_handler(request: Request, exc: RecordConflict) -> JSONResponse:
        code = str(exc)
        status_code = 404 if code.endswith("not_found") else 409
        public_code = "resource_not_found" if status_code == 404 else "record_conflict"
        return error_response(request, status_code, public_code, "The requested operation cannot be applied.")

    @app.exception_handler(SecretLeaseConflict)
    async def secret_lease_error_handler(request: Request, exc: SecretLeaseConflict) -> JSONResponse:
        code = str(exc)
        status_code = 404 if code.endswith("not_found") else 409
        return error_response(request, status_code, "secret_lease_conflict", "The secret lease operation was denied.")

    @app.exception_handler(IdentityStateConflict)
    async def identity_state_error_handler(request: Request, exc: IdentityStateConflict) -> JSONResponse:
        code = str(exc)
        status_code = 409
        if code.endswith("not_found"):
            status_code = 404
        public_code = "version_conflict" if code.endswith("version_conflict") else "identity_state_conflict"
        return error_response(request, status_code, public_code, "The identity state transition cannot be applied.")

    @app.exception_handler(OrchestrationUnavailable)
    async def orchestration_error_handler(request: Request, exc: OrchestrationUnavailable) -> JSONResponse:
        return error_response(request, 503, "workflow_unavailable", "Durable workflow orchestration is unavailable.")

    @app.exception_handler(PolicyEnforcementError)
    async def policy_enforcement_error_handler(request: Request, exc: PolicyEnforcementError) -> JSONResponse:
        denied = str(exc).startswith("policy_boundary_denied:")
        return error_response(
            request,
            403 if denied else 503,
            "policy_denied" if denied else "policy_unavailable",
            "The current policy denied this operation." if denied else "Policy enforcement is unavailable.",
        )

    @app.exception_handler(PolicyDecisionConflict)
    async def policy_conflict_error_handler(request: Request, exc: PolicyDecisionConflict) -> JSONResponse:
        return error_response(
            request,
            409,
            str(exc),
            "The policy lifecycle transition cannot be applied.",
        )

    @app.exception_handler(EvidenceIdempotencyConflict)
    async def evidence_idempotency_error_handler(request: Request, exc: EvidenceIdempotencyConflict) -> JSONResponse:
        return error_response(
            request, 409, "evidence_idempotency_conflict", "The evidence operation conflicts with an existing request."
        )

    @app.exception_handler(EvidenceRecordConflict)
    async def evidence_record_error_handler(request: Request, exc: EvidenceRecordConflict) -> JSONResponse:
        code = str(exc)
        status_code = 404 if code.endswith("not_found") else 409
        return error_response(request, status_code, code, "The evidence operation cannot be applied.")

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(request: Request, exc: IntegrityError) -> JSONResponse:
        return error_response(request, 409, "record_conflict", "The resource conflicts with existing state.")

    @app.exception_handler(SQLAlchemyError)
    async def database_error_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        return error_response(request, 503, "database_unavailable", "The control-plane database is unavailable.")

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return error_response(request, 500, "internal_error", "The request could not be completed.")

    dependencies = build_api_dependencies(
        test_issuer_enabled=test_issuer_enabled,
        authorization_hook=authorization_hook,
        identity_runtime=identity_runtime,
        resolved_operator_shell_context=resolved_operator_shell_context,
    )

    # IMPORTANT: register on app.router so FastAPI 0.139 preserves path-bearing app.routes.
    build_campaign_router(
        require_guard=dependencies.require_guard,
        api_error=ApiError,
        router=app.router,
    )
    register_autonomous_campaign_approval_routes(
        app.router,
        require_guard=dependencies.require_guard,
        api_error=ApiError,
    )
    register_foundation_routes(app.router, dependencies)
    register_access_context_routes(app.router, dependencies)
    register_policy_routes(app.router, dependencies)
    register_access_management_routes(app.router, dependencies)
    register_job_list_routes(app.router, dependencies)
    register_runner_routes(app.router, dependencies)
    register_job_mutation_routes(app.router, dependencies)
    register_containment_routes(app.router, dependencies)
    register_quota_routes(app.router, dependencies)
    register_observability_dashboard_routes(app.router, dependencies)
    register_lab_routes(app.router, dependencies)
    register_zap_routes(app.router, dependencies)
    register_api_differential_routes(app.router, dependencies)
    register_network_routes(app.router, dependencies)
    register_cloud_routes(app.router, dependencies)
    register_identity_saas_routes(app.router, dependencies)
    register_artifact_routes(app.router, dependencies)
    register_purple_routes(app.router, dependencies)
    register_human_simulation_routes(app.router, dependencies)
    register_agent_tool_routes(app.router, dependencies)
    register_workbench_routes(app.router, dependencies)
    register_finding_operations_routes(app.router, dependencies)
    register_agent_runtime_routes(app.router, dependencies)
    register_nuclei_routes(app.router, dependencies)
    register_observability_incident_routes(app.router, dependencies)
    register_campaign_routes(app.router, dependencies)
    register_evidence_routes(app.router, dependencies)
    register_finding_routes(app.router, dependencies)
    register_secret_routes(app.router, dependencies)

    if identity_runtime is not None:
        identity_runtime.install(app)
    if static_root is not None:
        _install_static_routes(app, static_root)
    install_legacy_component_name_compatibility(app)
    return app
