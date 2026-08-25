"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiError,
    ArtifactClass,
    ArtifactWriteRequest,
    DataClassification,
    Depends,
    EvidenceArtifactDetailResponse,
    EvidenceArtifactListResponse,
    EvidenceArtifactMutationResponse,
    EvidenceArtifactResponse,
    EvidenceDerivativeRequest,
    EvidenceDeriveRequest,
    EvidenceLegalHoldRequest,
    EvidencePurpose,
    EvidenceSyntheticRegisterRequest,
    EvidenceVerificationResponse,
    PaginationQuery,
    Request,
    RequestGuard,
    RetentionMode,
    _idempotency,
    _list_response,
    _now,
    _probe_limit,
    status,
    timedelta,
)

def register_evidence_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    evidence_service = dependencies.evidence_service
    require_guard = dependencies.require_guard

    @app.get(
        "/api/v1/evidence/artifacts",
        operation_id="list_evidence_artifacts",
        response_model=EvidenceArtifactListResponse,
    )
    async def list_evidence_artifacts(
        request: Request,
        query: PaginationQuery = Depends(),
        guard: RequestGuard = Depends(require_guard("evidence:read")),
    ) -> dict:
        rows = await evidence_service(request).list_artifacts(
            tenant_id=guard.security.tenant_id,
            actor_user_id=guard.security.subject,
            correlation_id=guard.correlation_id,
            limit=_probe_limit(query),
            offset=query.offset,
        )
        return _list_response(rows, query)

    @app.get(
        "/api/v1/evidence/artifacts/{artifact_id}",
        operation_id="get_evidence_artifact",
        response_model=EvidenceArtifactDetailResponse,
    )
    async def get_evidence_artifact(
        artifact_id: str,
        request: Request,
        guard: RequestGuard = Depends(require_guard("evidence:read")),
    ) -> dict:
        artifact = await evidence_service(request).get_artifact_detail(
            tenant_id=guard.security.tenant_id,
            artifact_id=artifact_id,
            actor_user_id=guard.security.subject,
            correlation_id=guard.correlation_id,
        )
        if artifact is None:
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        return {"data": artifact}

    @app.get(
        "/api/v1/evidence/artifacts/{artifact_id}/selection",
        operation_id="select_evidence_for_purpose",
        response_model=EvidenceArtifactResponse,
    )
    async def select_evidence_for_purpose(
        artifact_id: str,
        purpose: EvidencePurpose,
        request: Request,
        guard: RequestGuard = Depends(require_guard("evidence:read")),
    ) -> dict:
        selected = await evidence_service(request).select_for_purpose(
            tenant_id=guard.security.tenant_id,
            source_artifact_id=artifact_id,
            purpose=purpose,
            actor_user_id=guard.security.subject,
            correlation_id=guard.correlation_id,
        )
        if selected is None:
            raise ApiError(404, "safe_evidence_derivative_not_found", "No approved evidence derivative satisfies the requested purpose.")
        return {"data": selected}

    @app.post(
        "/api/v1/evidence/synthetic",
        operation_id="register_synthetic_evidence",
        status_code=status.HTTP_201_CREATED,
        response_model=EvidenceArtifactMutationResponse,
    )
    async def register_synthetic_evidence(
        payload: EvidenceSyntheticRegisterRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("evidence:write", mutation=True)),
    ) -> dict:
        if not request.app.state.synthetic_evidence_enabled:
            raise ApiError(404, "synthetic_evidence_disabled", "Synthetic evidence registration is disabled.")
        kms_reference = request.app.state.evidence_kms_reference
        if not isinstance(kms_reference, str) or not kms_reference:
            raise ApiError(503, "evidence_kms_not_configured", "Evidence encryption is not configured.")
        content = {
            "sanitized-log": b"synthetic sanitized evidence log\n",
            "sanitized-json": b'{"fixture":"synthetic","sanitized":true}\n',
        }[payload.fixture_kind]
        result = await evidence_service(request).ingest(
            ArtifactWriteRequest(
                tenant_id=guard.security.tenant_id,
                artifact_id=payload.artifact_id,
                engagement_id=payload.engagement_id,
                job_id=payload.job_id,
                producer_id=guard.security.subject,
                content=content,
                content_type="application/json" if payload.fixture_kind == "sanitized-json" else "text/plain",
                artifact_class=ArtifactClass.REDACTED,
                classification=DataClassification.CONFIDENTIAL,
                redaction_state=ArtifactClass.REDACTED.value,
                retention_mode=RetentionMode.GOVERNANCE,
                retain_until=_now() + timedelta(days=payload.retention_days),
                legal_hold=False,
                kms_reference=kms_reference,
                policy_reference=guard.policy_reference,
                idempotency_key=_idempotency(guard),
            ),
            actor_user_id=guard.security.subject,
            correlation_id=guard.correlation_id,
            occurred_at=_now(),
        )
        return {"data": result.artifact, "meta": {"replayed": result.replayed}}

    @app.post(
        "/api/v1/evidence/artifacts/{artifact_id}/derive",
        operation_id="derive_evidence_artifact",
        status_code=status.HTTP_201_CREATED,
        response_model=EvidenceArtifactMutationResponse,
    )
    async def derive_evidence_artifact(
        artifact_id: str,
        payload: EvidenceDeriveRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("evidence:derive", mutation=True)),
    ) -> dict:
        result = await evidence_service(request).derive(
            tenant_id=guard.security.tenant_id,
            request=EvidenceDerivativeRequest(
                source_artifact_id=artifact_id,
                artifact_id=payload.artifact_id,
                artifact_class=ArtifactClass(payload.artifact_class),
                transform_name=payload.transform_name,
                transform_version=payload.transform_version,
                quality_approved=payload.quality_approved,
                idempotency_key=_idempotency(guard),
            ),
            actor_user_id=guard.security.subject,
            correlation_id=guard.correlation_id,
            occurred_at=_now(),
        )
        return {"data": result.artifact, "meta": {"replayed": result.replayed}}

    @app.post(
        "/api/v1/evidence/artifacts/{artifact_id}/verify",
        operation_id="verify_evidence_artifact",
        response_model=EvidenceVerificationResponse,
    )
    async def verify_evidence_artifact(
        artifact_id: str,
        request: Request,
        guard: RequestGuard = Depends(require_guard("evidence:verify", mutation=True)),
    ) -> dict:
        verification = await evidence_service(request).verify(
            tenant_id=guard.security.tenant_id,
            artifact_id=artifact_id,
            actor_user_id=guard.security.subject,
            correlation_id=guard.correlation_id,
            idempotency_key=_idempotency(guard),
            occurred_at=_now(),
        )
        return {"data": {
            "artifact_id": artifact_id,
            "object_version_id": verification.version_id,
            "verified": verification.ok,
            "reason": verification.reason,
        }}

    @app.post(
        "/api/v1/evidence/artifacts/{artifact_id}/legal-hold",
        operation_id="place_evidence_legal_hold",
        response_model=EvidenceArtifactResponse,
    )
    async def place_evidence_legal_hold(
        artifact_id: str,
        payload: EvidenceLegalHoldRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("evidence:retention-admin", mutation=True)),
    ) -> dict:
        artifact = await evidence_service(request).place_legal_hold(
            tenant_id=guard.security.tenant_id,
            artifact_id=artifact_id,
            expected_version=payload.expected_version,
            actor_user_id=guard.security.subject,
            correlation_id=guard.correlation_id,
            idempotency_key=_idempotency(guard),
            occurred_at=_now(),
        )
        return {"data": artifact}
