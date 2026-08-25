"""compat_093 FastAPI control plane with fail-closed guards and relational transactions."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
from pathlib import Path
import re
from typing import TYPE_CHECKING, Awaitable, Callable, AsyncIterator
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redagent_platform.api.schemas import (
    ActivityListResponse,
    AgentCancelRequest,
    AgentDashboardResponse,
    AgentProposalApproveRequest,
    AgentProposalResponse,
    AgentRunCreateRequest,
    AgentRunResponse,
    AgentRunStartResponse,
    AgentToolListResponse,
    McpFreezeRequest,
    McpFreezeResponse,
    WorkbenchDashboardResponse,
    WorkbenchDraftCreateRequest,
    WorkbenchDraftMutationResponse,
    WorkbenchReviewResponse,
    WorkbenchReviewRequest,
    WorkbenchSuccessorRequest,
    ApiDifferentialCancelRequest,
    ApiDifferentialCompileRequest,
    ApiDifferentialDashboardResponse,
    ApiDifferentialPlanResponse,
    ApiDifferentialProfileListResponse,
    ApiDifferentialRunCreateRequest,
    ApiDifferentialRunResponse,
    ArtifactCancelRequest,
    ArtifactCompileRequest,
    ArtifactDashboardResponse,
    ArtifactPlanResponse,
    ArtifactProfileListResponse,
    ArtifactRunCreateRequest,
    ArtifactRunResponse,
    PurpleAbilityListResponse,
    PurpleCompileRequest,
    PurpleDashboardResponse,
    PurpleKillRequest,
    PurplePlanResponse,
    PurpleRunCreateRequest,
    PurpleRunResponse,
    HumanSimulationCampaignListResponse,
    HumanSimulationCompileRequest,
    HumanSimulationDashboardResponse,
    HumanSimulationPlanResponse,
    HumanSimulationRunCreateRequest,
    HumanSimulationRunResponse,
    HumanSimulationStopRequest,
    CampaignCreateRequest,
    CampaignListResponse,
    CampaignMutationResponse,
    CampaignResponse,
    CloudCancelRequest,
    CloudCompileRequest,
    CloudDashboardResponse,
    CloudPlanResponse,
    CloudProfileListResponse,
    CloudRunCreateRequest,
    CloudRunResponse,
    ContainmentApprovalRequest,
    ContainmentControlListResponse,
    ContainmentControlResponse,
    ContainmentRecoveryRequest,
    ContainmentStopRequest,
    ContextResponse,
    EngagementCreateRequest,
    EngagementListResponse,
    EngagementMutationResponse,
    EngagementResponse,
    EngagementUpdateRequest,
    EvidenceArtifactDetailResponse,
    EvidenceArtifactListResponse,
    EvidenceArtifactMutationResponse,
    EvidenceArtifactResponse,
    EvidenceDeriveRequest,
    EvidenceLegalHoldRequest,
    EvidenceSyntheticRegisterRequest,
    EvidenceVerificationResponse,
    FindingIngestRequest,
    FindingOperationsDashboardResponse,
    FindingOperationsDeliveryRequest,
    FindingOperationsDeliveryResponse,
    FindingOperationsImportRequest,
    FindingOperationsImportResponse,
    FindingOperationsIssueResponse,
    FindingOperationsPublicationResponse,
    FindingOperationsPublishRequest,
    FindingOperationsReportRequest,
    FindingOperationsReportResponse,
    FindingOperationsReviewRequest,
    JitGrantApprovalRequest,
    JitGrantCreateRequest,
    JitGrantListResponse,
    JitGrantMutationResponse,
    JitGrantResponse,
    JitGrantReviewRequest,
    JitGrantRevokeRequest,
    LabDashboardResponse,
    JobCreateRequest,
    JobCommandResponse,
    JobContainmentResponse,
    JobEmergencyStopRequest,
    JobLifecycleCommandRequest,
    JobListResponse,
    JobMutationResponse,
    JobResponse,
    JobStopResponse,
    MembershipListResponse,
    NetworkCancelRequest,
    NetworkCompileRequest,
    NetworkDashboardResponse,
    NetworkPlanResponse,
    NetworkProfileListResponse,
    NetworkRunCreateRequest,
    NetworkRunResponse,
    NucleiCancelRequest,
    NucleiCompileRequest,
    NucleiDashboardResponse,
    NucleiPlanResponse,
    NucleiProfileListResponse,
    NucleiRunCreateRequest,
    NucleiRunResponse,
    OperatorShellContextData,
    IncidentActionRequest,
    IncidentListResponse,
    IncidentResponse,
    IncidentRunbookListResponse,
    IncidentTimelineResponse,
    IdentitySaasCancelRequest,
    IdentitySaasCompileRequest,
    IdentitySaasDashboardResponse,
    IdentitySaasPlanResponse,
    IdentitySaasProfileListResponse,
    IdentitySaasRunCreateRequest,
    IdentitySaasRunResponse,
    ObservabilityDashboardResponse,
    CorrelationEventListResponse,
    PaginationQuery,
    PolicyBundleListResponse,
    PolicyDecisionListResponse,
    PolicyPromotionRequest,
    PolicyPromotionResponse,
    PolicySimulationRequest,
    PolicySimulationResponse,
    PolicyStatusResponse,
    QuotaStatusResponse,
    RoeApprovalRequest,
    RoeVersionListResponse,
    RoeVersionMutationResponse,
    RoeVersionCreateRequest,
    RunnerExecutionListResponse,
    RunnerManifestListResponse,
    RunnerRegistrationListResponse,
    RunnerStatusResponse,
    SecretLeaseListResponse,
    SecretLeaseResponse,
    SecretReferenceListResponse,
    SecretRevokeRequest,
    SecretSyntheticIssueRequest,
    TargetCreateRequest,
    TargetListResponse,
    TargetMutationResponse,
    ZapCancelRequest,
    ZapCompileRequest,
    ZapDashboardResponse,
    ZapPlanResponse,
    ZapProfileListResponse,
    ZapRunCreateRequest,
    ZapRunResponse,
)
from redagent_platform.campaign_service.api import build_r123_router
from redagent_platform.campaign_service.composition import R123ApiRuntimeServices
from redagent_platform.campaign_service.qualification import (
    R123QualificationService,
    R123StatusService,
)
from redagent_platform.campaign_service.registry import StrategyLoopMode
from redagent_platform.campaign_service.status import R123CampaignStatusOwner
from redagent_platform.identity.repository import IdentityRepository, IdentityStateConflict
from redagent_platform.evidence_service.contracts import (
    ArtifactClass,
    ArtifactWriteRequest,
    DataClassification,
    EvidenceDerivativeRequest,
    EvidencePurpose,
    RetentionMode,
)
from redagent_platform.evidence_service.repository import EvidenceIdempotencyConflict, EvidenceRecordConflict
from redagent_platform.evidence_service.service import EvidenceService
from redagent_platform.secret_service.broker import SecretLeaseBroker
from redagent_platform.secret_service.contracts import (
    LeaseIssueRequest,
    SecretReference,
    SecretReferenceKind,
    SecretReferenceStatus,
    WorkloadClient,
)
from redagent_platform.secret_service.fakes import AttestedFakeWorkload
from redagent_platform.secret_service.repository import SecretLeaseConflict, TransactionalSecretLeaseStore
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CampaignWorkflowInput,
    CommandAction,
    EmergencyStopSignal,
    JobWorkflowInput,
    OperatorCommand,
    deterministic_campaign_workflow_id,
    deterministic_job_workflow_id,
)
from redagent_platform.orchestration.gateway import OrchestrationUnavailable, TemporalOrchestrationGateway
from redagent_platform.orchestration.config import TemporalSettings
from redagent_platform.orchestration.gateway import connect_temporal
from redagent_platform.persistence.database import DatabaseSettings, async_engine_options
from redagent_platform.persistence.repository import (
    ConcurrencyConflict,
    ControlPlaneRepository,
    IdempotencyConflict,
    MutationResult,
    RecordConflict,
)
from redagent_platform.policy_service.boundaries import PolicyBoundarySDK
from redagent_platform.policy_service.enforcement import PolicyBoundaryEnforcer, PolicyEnforcementError
from redagent_platform.policy_service.repository import (
    PolicyAdministrationRepository,
    PolicyDecisionConflict,
    TransactionalPolicyDecisionRecorder,
)
from redagent_platform.runner_service.repository import RunnerRepository
from redagent_platform.containment_service.contracts import (
    ControlScope,
    ControlScopeKind,
    StopApproval,
    StopRequest,
)
from redagent_platform.containment_service.repository import ContainmentRepository, ContainmentRepositoryConflict
from redagent_platform.telemetry_service.incidents import IncidentAction
from redagent_platform.telemetry_service.catalog import foundation_runbooks
from redagent_platform.telemetry_service.operations import (
    IncidentRepository, ObservabilityRepositoryConflict, SloRepository,
)
from redagent_platform.telemetry_service.repository import TelemetryRepository, TelemetryRepositoryConflict
from redagent_platform.lab_service.repository import LabRepository
from redagent_platform.zap_service.compiler import compile_zap_plan
from redagent_platform.zap_service.contracts import (
    CertifiedProfileId,
    ZapAuthorization,
    ZapTargetBinding,
    certified_profiles,
)
from redagent_platform.zap_service.repository import (
    ZapRepository,
    ZapRepositoryConflict,
    profile_values,
)
from redagent_platform.nuclei_service.compiler import compile_nuclei_plan
from redagent_platform.nuclei_service.contracts import (
    NucleiAuthorization,
    NucleiProfileId,
    NucleiTargetBinding,
    certified_profiles as certified_nuclei_profiles,
)
from redagent_platform.nuclei_service.promotion import (
    verify_current_nuclei_bundle_promotion,
)
from redagent_platform.nuclei_service.repository import (
    NucleiRepository,
    NucleiRepositoryConflict,
    profile_values as nuclei_profile_values,
)
from redagent_platform.api_differential_service.artifact import EXPECTED_WHEEL_SHA256
from redagent_platform.api_differential_service.compiler import compile_differential_plan
from redagent_platform.api_differential_service.contracts import (
    ApiDifferentialAuthorization,
    ApiDifferentialProfileId,
    ApiDifferentialTargetBinding,
    IdentityState,
    certified_profiles as certified_api_differential_profiles,
)
from redagent_platform.api_differential_service.promotion import verify_api_differential_promotion
from redagent_platform.api_differential_service.repository import (
    ApiDifferentialRepository,
    ApiDifferentialRepositoryConflict,
)
from redagent_platform.network_service.compiler import compile_network_plan
from redagent_platform.network_service.contracts import (
    NetworkAuthorization,
    NetworkProfileId,
    NetworkProtocol,
    NetworkTargetBinding,
    certified_profiles as certified_network_profiles,
)
from redagent_platform.network_service.repository import NetworkRepository, NetworkRepositoryConflict
from redagent_platform.cloud_connectors.compiler import compile_collection_plan
from redagent_platform.cloud_connectors.contracts import CollectionAuthorization, ProviderKind
from redagent_platform.cloud_connectors.profiles import emulator_profiles
from redagent_platform.cloud_connectors.repository import CloudRepository, CloudRepositoryConflict
from redagent_platform.identity_saas.compiler import compile_identity_plan
from redagent_platform.identity_saas.contracts import IdentityAuthorization
from redagent_platform.identity_saas.profiles import emulator_profiles as identity_emulator_profiles
from redagent_platform.identity_saas.repository import IdentitySaasRepository, IdentityRepositoryConflict
from redagent_platform.artifact_pipeline.compiler import compile_artifact_plan
from redagent_platform.artifact_pipeline.contracts import ArtifactAuthorization, ArtifactKind
from redagent_platform.artifact_pipeline.profiles import certified_profiles as certified_artifact_profiles
from redagent_platform.artifact_pipeline.repository import ArtifactPipelineRepository, ArtifactRepositoryConflict
from redagent_platform.purple_runtime.catalog import certified_abilities as certified_purple_abilities
from redagent_platform.purple_runtime.compiler import compile_ability_plan
from redagent_platform.purple_runtime.contracts import AbilityApproval, AbilityAuthorization, LabBinding
from redagent_platform.purple_runtime.repository import PurpleRuntimeRepository, PurpleRepositoryConflict
from redagent_platform.human_simulation.catalog import certified_campaign
from redagent_platform.human_simulation.compiler import compile_campaign_plan
from redagent_platform.human_simulation.contracts import CampaignApproval, CampaignAuthorization
from redagent_platform.human_simulation.repository import HumanSimulationRepository, HumanSimulationRepositoryConflict
from redagent_platform.agent_kernel.approvals import ProposalContext
from redagent_platform.agent_kernel.promotion import verify_agent_kernel_promotion
from redagent_platform.agent_kernel.qualification import build_projection_catalog, certified_capability_catalog, qualify_agent_kernel
from redagent_platform.agent_kernel.repository import AgentKernelRepository
from redagent_platform.persistence.models import metadata

SAFE_CONTEXT_VALUE = re.compile(r"^[A-Za-z0-9._:/-]+$")


@dataclass(frozen=True)
class SecurityContext:
    subject: str
    tenant_id: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class AuthorizationDecision:
    permission: str
    object_id: str | None
    allowed: bool


@dataclass(frozen=True)
class RequestGuard:
    security: SecurityContext
    decision: AuthorizationDecision
    policy_reference: str
    roe_version_id: str | None
    correlation_id: str
    audit_intent: str
    idempotency_key: str | None


AuthorizationHook = Callable[[SecurityContext, str, str | None], bool | Awaitable[bool]]
R123ApiServiceFactory = Callable[..., object | Awaitable[object]]


class ApiError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message

def _valid_context_value(value: str, maximum: int) -> bool:
    return bool(value and len(value) <= maximum and SAFE_CONTEXT_VALUE.fullmatch(value))


def _repository(session: AsyncSession, guard: RequestGuard) -> ControlPlaneRepository:
    return ControlPlaneRepository(
        session,
        tenant_id=guard.security.tenant_id,
        actor_user_id=guard.security.subject,
        correlation_id=guard.correlation_id,
    )


























































































def _r114_fixture_draft_binding() -> dict[str, object]:
    return {
        "binding_id": "binding-r114-fixture",
        "campaign_id": "campaign-r114",
        "campaign_label": "R114 synthetic campaign",
        "plan_id": "plan-r114-stored",
        "plan_label": "Stored fixture plan",
        "successor_plan_id": "plan-r114-successor",
        "successor_plan_label": "Revised fixture plan",
        "target_id": "target-r114-owned",
        "target_label": "Owned synthetic target",
        "tool_fqn": "redagent.r114-mcp-fixture.propose.v1",
        "binding_state": "available",
        "fixture_only": True,
        "egress_class": "none",
    }


def _r114_matches_fixture_draft_binding(*, campaign_id: str, plan_id: str,
                                        target_id: str, tool_fqn: str) -> bool:
    binding = _r114_fixture_draft_binding()
    return (campaign_id, plan_id, target_id, tool_fqn) == (
        binding["campaign_id"], binding["plan_id"], binding["target_id"], binding["tool_fqn"],
    )


def _r114_matches_fixture_successor_plan(plan_id: str) -> bool:
    return plan_id == _r114_fixture_draft_binding()["successor_plan_id"]














































def _orchestration(request: Request) -> TemporalOrchestrationGateway:
    gateway = request.app.state.orchestration_gateway
    if gateway is None:
        raise ApiError(503, "workflow_not_configured", "Durable workflow orchestration is not configured.")
    return gateway




def _idempotency(guard: RequestGuard) -> str:
    if guard.idempotency_key is None:
        raise ApiError(400, "idempotency_key_required", "Idempotency-Key is required for mutations.")
    return guard.idempotency_key


def _match_roe_reference(guard: RequestGuard, expected: str) -> None:
    if guard.roe_version_id != expected:
        raise ApiError(403, "roe_reference_mismatch", "The validated ROE reference does not match the resource.")


def _mutation_response(result: MutationResult) -> dict[str, object]:
    return {
        "data": result.resource,
        "meta": {
            "replayed": result.replayed,
            "audit_id": result.audit_id,
            "outbox_id": result.outbox_id,
        },
    }


def _list_response(rows: list[dict[str, object]], query: PaginationQuery) -> dict[str, object]:
    page_rows = rows[:query.limit]
    has_more = len(rows) > query.limit
    return {
        "data": page_rows,
        "page": {
            "limit": query.limit,
            "offset": query.offset,
            "returned": len(page_rows),
            "next_offset": query.offset + len(page_rows) if has_more else None,
        },
    }


def _probe_limit(query: PaginationQuery) -> int:
    # IMPORTANT: one extra row is an internal bounded continuation probe; never expose it.
    return query.limit + 1


def _static_root(configured: Path | None) -> Path | None:
    if configured is None:
        return None
    root = configured.resolve()
    if not root.is_dir() or not (root / "index.html").is_file():
        raise ValueError("static_index_required")
    return root


def _install_static_routes(app: FastAPI, root: Path) -> None:
    async def serve_frontend(spa_path: str) -> FileResponse:
        normalized = spa_path.lstrip("/")
        if normalized == "api" or normalized.startswith("api/") or normalized == "auth" or normalized.startswith("auth/"):
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        candidate = (root / normalized).resolve()
        if not candidate.is_relative_to(root):
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        if candidate.is_file():
            return FileResponse(candidate)
        # IMPORTANT: missing assets and extension-bearing paths must never receive the SPA document.
        if normalized.startswith("assets/") or Path(normalized).suffix:
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        return FileResponse(root / "index.html", media_type="text/html")

    app.add_api_route(
        "/{spa_path:path}",
        serve_frontend,
        methods=["GET", "HEAD"],
        include_in_schema=False,
        name="serve_operational_console",
    )


def _is_hashed_asset(path: str) -> bool:
    return bool(re.fullmatch(r"/assets/.+-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+", path))


def _now() -> datetime:
    return datetime.now(timezone.utc)


__all__ = (
    "AbilityApproval",
    "AbilityAuthorization",
    "ActivityListResponse",
    "AgentCancelRequest",
    "AgentDashboardResponse",
    "AgentKernelRepository",
    "AgentProposalApproveRequest",
    "AgentProposalResponse",
    "AgentRunCreateRequest",
    "AgentRunResponse",
    "AgentRunStartResponse",
    "AgentToolListResponse",
    "ApiDifferentialAuthorization",
    "ApiDifferentialCancelRequest",
    "ApiDifferentialCompileRequest",
    "ApiDifferentialDashboardResponse",
    "ApiDifferentialPlanResponse",
    "ApiDifferentialProfileId",
    "ApiDifferentialProfileListResponse",
    "ApiDifferentialRepository",
    "ApiDifferentialRepositoryConflict",
    "ApiDifferentialRunCreateRequest",
    "ApiDifferentialRunResponse",
    "ApiDifferentialTargetBinding",
    "ApiError",
    "ArtifactAuthorization",
    "ArtifactCancelRequest",
    "ArtifactClass",
    "ArtifactCompileRequest",
    "ArtifactDashboardResponse",
    "ArtifactKind",
    "ArtifactPipelineRepository",
    "ArtifactPlanResponse",
    "ArtifactProfileListResponse",
    "ArtifactRepositoryConflict",
    "ArtifactRunCreateRequest",
    "ArtifactRunResponse",
    "ArtifactWriteRequest",
    "AsyncIterator",
    "AsyncSession",
    "AttestedFakeWorkload",
    "AuthorizationDecision",
    "AuthorizationHook",
    "Awaitable",
    "CONTRACT_SCHEMA_VERSION",
    "Callable",
    "CampaignApproval",
    "CampaignAuthorization",
    "CampaignCreateRequest",
    "CampaignListResponse",
    "CampaignMutationResponse",
    "CampaignResponse",
    "CampaignWorkflowInput",
    "CertifiedProfileId",
    "CloudCancelRequest",
    "CloudCompileRequest",
    "CloudDashboardResponse",
    "CloudPlanResponse",
    "CloudProfileListResponse",
    "CloudRepository",
    "CloudRepositoryConflict",
    "CloudRunCreateRequest",
    "CloudRunResponse",
    "CollectionAuthorization",
    "CommandAction",
    "ConcurrencyConflict",
    "ContainmentApprovalRequest",
    "ContainmentControlListResponse",
    "ContainmentControlResponse",
    "ContainmentRecoveryRequest",
    "ContainmentRepository",
    "ContainmentRepositoryConflict",
    "ContainmentStopRequest",
    "ContextResponse",
    "ControlPlaneRepository",
    "ControlScope",
    "ControlScopeKind",
    "CorrelationEventListResponse",
    "DataClassification",
    "DatabaseSettings",
    "Depends",
    "EXPECTED_WHEEL_SHA256",
    "EmergencyStopSignal",
    "EngagementCreateRequest",
    "EngagementListResponse",
    "EngagementMutationResponse",
    "EngagementResponse",
    "EngagementUpdateRequest",
    "EvidenceArtifactDetailResponse",
    "EvidenceArtifactListResponse",
    "EvidenceArtifactMutationResponse",
    "EvidenceArtifactResponse",
    "EvidenceDerivativeRequest",
    "EvidenceDeriveRequest",
    "EvidenceIdempotencyConflict",
    "EvidenceLegalHoldRequest",
    "EvidencePurpose",
    "EvidenceRecordConflict",
    "EvidenceService",
    "EvidenceSyntheticRegisterRequest",
    "EvidenceVerificationResponse",
    "FastAPI",
    "FileResponse",
    "FindingIngestRequest",
    "FindingOperationsDashboardResponse",
    "FindingOperationsDeliveryRequest",
    "FindingOperationsDeliveryResponse",
    "FindingOperationsImportRequest",
    "FindingOperationsImportResponse",
    "FindingOperationsIssueResponse",
    "FindingOperationsPublicationResponse",
    "FindingOperationsPublishRequest",
    "FindingOperationsReportRequest",
    "FindingOperationsReportResponse",
    "FindingOperationsReviewRequest",
    "Header",
    "HumanSimulationCampaignListResponse",
    "HumanSimulationCompileRequest",
    "HumanSimulationDashboardResponse",
    "HumanSimulationPlanResponse",
    "HumanSimulationRepository",
    "HumanSimulationRepositoryConflict",
    "HumanSimulationRunCreateRequest",
    "HumanSimulationRunResponse",
    "HumanSimulationStopRequest",
    "IdempotencyConflict",
    "IdentityAuthorization",
    "IdentityRepository",
    "IdentityRepositoryConflict",
    "IdentitySaasCancelRequest",
    "IdentitySaasCompileRequest",
    "IdentitySaasDashboardResponse",
    "IdentitySaasPlanResponse",
    "IdentitySaasProfileListResponse",
    "IdentitySaasRepository",
    "IdentitySaasRunCreateRequest",
    "IdentitySaasRunResponse",
    "IdentityState",
    "IdentityStateConflict",
    "IncidentAction",
    "IncidentActionRequest",
    "IncidentListResponse",
    "IncidentRepository",
    "IncidentResponse",
    "IncidentRunbookListResponse",
    "IncidentTimelineResponse",
    "IntegrityError",
    "JSONResponse",
    "JitGrantApprovalRequest",
    "JitGrantCreateRequest",
    "JitGrantListResponse",
    "JitGrantMutationResponse",
    "JitGrantResponse",
    "JitGrantReviewRequest",
    "JitGrantRevokeRequest",
    "JobCommandResponse",
    "JobContainmentResponse",
    "JobCreateRequest",
    "JobEmergencyStopRequest",
    "JobLifecycleCommandRequest",
    "JobListResponse",
    "JobMutationResponse",
    "JobResponse",
    "JobStopResponse",
    "JobWorkflowInput",
    "LabBinding",
    "LabDashboardResponse",
    "LabRepository",
    "LeaseIssueRequest",
    "McpFreezeRequest",
    "McpFreezeResponse",
    "MembershipListResponse",
    "MutationResult",
    "NetworkAuthorization",
    "NetworkCancelRequest",
    "NetworkCompileRequest",
    "NetworkDashboardResponse",
    "NetworkPlanResponse",
    "NetworkProfileId",
    "NetworkProfileListResponse",
    "NetworkProtocol",
    "NetworkRepository",
    "NetworkRepositoryConflict",
    "NetworkRunCreateRequest",
    "NetworkRunResponse",
    "NetworkTargetBinding",
    "NucleiAuthorization",
    "NucleiCancelRequest",
    "NucleiCompileRequest",
    "NucleiDashboardResponse",
    "NucleiPlanResponse",
    "NucleiProfileId",
    "NucleiProfileListResponse",
    "NucleiRepository",
    "NucleiRepositoryConflict",
    "NucleiRunCreateRequest",
    "NucleiRunResponse",
    "NucleiTargetBinding",
    "ObservabilityDashboardResponse",
    "ObservabilityRepositoryConflict",
    "OperatorCommand",
    "OperatorShellContextData",
    "OrchestrationUnavailable",
    "PaginationQuery",
    "Path",
    "PolicyAdministrationRepository",
    "PolicyBoundaryEnforcer",
    "PolicyBoundarySDK",
    "PolicyBundleListResponse",
    "PolicyDecisionConflict",
    "PolicyDecisionListResponse",
    "PolicyEnforcementError",
    "PolicyPromotionRequest",
    "PolicyPromotionResponse",
    "PolicySimulationRequest",
    "PolicySimulationResponse",
    "PolicyStatusResponse",
    "ProposalContext",
    "ProviderKind",
    "PurpleAbilityListResponse",
    "PurpleCompileRequest",
    "PurpleDashboardResponse",
    "PurpleKillRequest",
    "PurplePlanResponse",
    "PurpleRepositoryConflict",
    "PurpleRunCreateRequest",
    "PurpleRunResponse",
    "PurpleRuntimeRepository",
    "QuotaStatusResponse",
    "R123ApiRuntimeServices",
    "R123ApiServiceFactory",
    "R123CampaignStatusOwner",
    "R123QualificationService",
    "R123StatusService",
    "RecordConflict",
    "Request",
    "RequestGuard",
    "RequestValidationError",
    "Response",
    "RetentionMode",
    "RoeApprovalRequest",
    "RoeVersionCreateRequest",
    "RoeVersionListResponse",
    "RoeVersionMutationResponse",
    "RunnerExecutionListResponse",
    "RunnerManifestListResponse",
    "RunnerRegistrationListResponse",
    "RunnerRepository",
    "RunnerStatusResponse",
    "SAFE_CONTEXT_VALUE",
    "SQLAlchemyError",
    "SecretLeaseBroker",
    "SecretLeaseConflict",
    "SecretLeaseListResponse",
    "SecretLeaseResponse",
    "SecretReference",
    "SecretReferenceKind",
    "SecretReferenceListResponse",
    "SecretReferenceStatus",
    "SecretRevokeRequest",
    "SecretSyntheticIssueRequest",
    "SecurityContext",
    "SloRepository",
    "StopApproval",
    "StopRequest",
    "StrategyLoopMode",
    "TYPE_CHECKING",
    "TargetCreateRequest",
    "TargetListResponse",
    "TargetMutationResponse",
    "TelemetryRepository",
    "TelemetryRepositoryConflict",
    "TemporalOrchestrationGateway",
    "TemporalSettings",
    "TransactionalPolicyDecisionRecorder",
    "TransactionalSecretLeaseStore",
    "WorkbenchDashboardResponse",
    "WorkbenchDraftCreateRequest",
    "WorkbenchDraftMutationResponse",
    "WorkbenchReviewRequest",
    "WorkbenchReviewResponse",
    "WorkbenchSuccessorRequest",
    "WorkloadClient",
    "ZapAuthorization",
    "ZapCancelRequest",
    "ZapCompileRequest",
    "ZapDashboardResponse",
    "ZapPlanResponse",
    "ZapProfileListResponse",
    "ZapRepository",
    "ZapRepositoryConflict",
    "ZapRunCreateRequest",
    "ZapRunResponse",
    "ZapTargetBinding",
    "_idempotency",
    "_install_static_routes",
    "_is_hashed_asset",
    "_list_response",
    "_match_roe_reference",
    "_mutation_response",
    "_now",
    "_orchestration",
    "_probe_limit",
    "_r114_fixture_draft_binding",
    "_r114_matches_fixture_draft_binding",
    "_r114_matches_fixture_successor_plan",
    "_repository",
    "_static_root",
    "_valid_context_value",
    "async_engine_options",
    "async_sessionmaker",
    "asynccontextmanager",
    "build_projection_catalog",
    "build_r123_router",
    "certified_api_differential_profiles",
    "certified_artifact_profiles",
    "certified_campaign",
    "certified_capability_catalog",
    "certified_network_profiles",
    "certified_nuclei_profiles",
    "certified_profiles",
    "certified_purple_abilities",
    "compile_ability_plan",
    "compile_artifact_plan",
    "compile_campaign_plan",
    "compile_collection_plan",
    "compile_differential_plan",
    "compile_identity_plan",
    "compile_network_plan",
    "compile_nuclei_plan",
    "compile_zap_plan",
    "connect_temporal",
    "create_async_engine",
    "dataclass",
    "datetime",
    "deterministic_campaign_workflow_id",
    "deterministic_job_workflow_id",
    "emulator_profiles",
    "foundation_runbooks",
    "hashlib",
    "identity_emulator_profiles",
    "inspect",
    "metadata",
    "nuclei_profile_values",
    "profile_values",
    "qualify_agent_kernel",
    "re",
    "select",
    "status",
    "text",
    "timedelta",
    "timezone",
    "uuid4",
    "verify_agent_kernel_promotion",
    "verify_api_differential_promotion",
    "verify_current_nuclei_bundle_promotion",
)
