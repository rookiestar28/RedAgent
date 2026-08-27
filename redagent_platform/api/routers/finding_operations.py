"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from datetime import datetime
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
    _idempotency,
    _now,
)
from redagent_platform.api.schemas.finding_operations import (
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
)

# IMPORTANT: router modules are one level below api; promotion assets remain workspace-relative.
def _public_finding_issue(row: dict[str, object]) -> dict[str, object]:
    return {key: row[key] for key in ("issue_id", "issue_fingerprint", "title", "severity", "confidence",
        "disposition", "disposition_revision", "owner_id", "sla_due_at", "first_seen_at", "last_seen_at",
        "issue_state", "version")}


def _public_finding_occurrence(row: dict[str, object], issue_id: str,
                               evidence: dict[str, object]) -> dict[str, object]:
    return {"issue_id": issue_id, "evidence_id": evidence["evidence_id"],
        "evidence_sha256": evidence["evidence_sha256"], "redaction_state": evidence["redaction_state"]} | {
        key: row[key] for key in ("occurrence_id", "tool_id", "tool_version",
        "rule_id", "rule_version", "database_version", "coverage_state", "occurrence_state", "observed_at",
        "version")}


def _public_finding_report(row: dict[str, object]) -> dict[str, object]:
    return {key: row[key] for key in ("report_id", "audience", "reviewed_snapshot_sha256", "policy_revision",
        "roe_version_id", "coverage_state", "report_sha256", "generation_profile", "report_state", "generated_by",
        "generated_at", "version")}


def _public_finding_publication(row: dict[str, object], report_id: str) -> dict[str, object]:
    return {"report_id": report_id} | {key: row[key] for key in ("publication_id", "report_sha256",
        "reviewer_id", "publisher_id", "publication_state", "published_at", "version")}


def _public_finding_delivery(row: dict[str, object], profile_id: str, report_id: str) -> dict[str, object]:
    return {"profile_id": profile_id, "report_id": report_id,
        "network_contact_count": int(row.get("network_contact_count", 0))} | {
        key: row[key] for key in ("delivery_id", "snapshot_sha256", "delivery_state", "attempt_count",
            "next_attempt_at", "version")}


def _require_finding_operations_promotion(now: datetime):
    from redagent_platform.finding_operations.promotion import verify_finding_operations_promotion

    try:
        return verify_finding_operations_promotion(Path(__file__).resolve().parents[3], now=now)
    except (OSError, ValueError) as exc:
        raise ApiError(
            503, "finding_operations_promotion_unavailable",
            "The signed fixture-only finding operations promotion is unavailable.",
        ) from exc


def register_finding_operations_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get("/api/v1/finding-operations/dashboard", operation_id="get_finding_operations_dashboard",
             response_model=FindingOperationsDashboardResponse)
    async def get_finding_operations_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("finding:read", safety_preserving=True)),
    ) -> dict:
        from redagent_platform.finding_operations.repository import FindingOperationsRepository

        _require_finding_operations_promotion(_now())
        async with session_scope(request) as session:
            data = await FindingOperationsRepository(
                session, tenant_id=guard.security.tenant_id, actor_user_id=guard.security.subject,
                correlation_id=guard.correlation_id,
            ).dashboard()
        issue_by_record = {str(row["id"]): str(row["issue_id"]) for row in data["issues"]}
        evidence_by_occurrence = {str(row["occurrence_record_id"]): row for row in data["evidence_links"]}
        report_by_record = {str(row["id"]): str(row["report_id"]) for row in data["reports"]}
        profile_by_record = {str(row["id"]): str(row["profile_id"]) for row in data["profiles"]}
        return {"data": {
            "issues": [_public_finding_issue(row) for row in data["issues"]],
            "occurrences": [_public_finding_occurrence(
                row, issue_by_record[str(row["issue_record_id"])], evidence_by_occurrence[str(row["id"])],
            ) for row in data["occurrences"]],
            "reports": [_public_finding_report(row) for row in data["reports"]],
            "publications": [_public_finding_publication(
                row, report_by_record[str(row["report_record_id"])],
            ) for row in data["publications"]],
            "deliveries": [_public_finding_delivery(
                row, profile_by_record[str(row["profile_record_id"])],
                report_by_record[str(row["report_record_id"])],
            ) for row in data["deliveries"]],
        }}

    @app.post("/api/v1/finding-operations/imports", operation_id="import_finding_operations_fixture",
              response_model=FindingOperationsImportResponse, status_code=status.HTTP_202_ACCEPTED)
    async def import_finding_operations_fixture(
        payload: FindingOperationsImportRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("finding:ingest", mutation=True)),
    ) -> dict:
        from redagent_platform.finding_operations.contracts import CoverageState, FindingOccurrenceInput, ImportBatch
        from redagent_platform.finding_operations.repository import FindingOperationsRepository

        now = _now()
        _require_finding_operations_promotion(now)
        record = FindingOccurrenceInput(
            source_record_id=payload.source_record_id, tool="r115-fixture", tool_version="1.0.0",
            rule_id="fixture-missing-hsts", rule_version="r115-closed-v1",
            database_version="fixture-db-1", title="Missing HSTS",
            resource_identity=payload.resource_id, location="approved-resource-root",
            severity="medium", confidence="confirmed", taxonomy_ids=("CWE-319",),
            control_ids=("ASVS-V14.4.5",), evidence_id=payload.evidence_id,
            evidence_sha256=payload.evidence_sha256, redaction_state="report_safe", observed_at=now,
        )
        batch = ImportBatch(
            import_id=payload.import_id, tenant_id=guard.security.tenant_id, adapter_id="r115-fixture",
            run_id=payload.run_id, coverage_state=CoverageState(payload.coverage_state),
            comparable_baseline_run_id=payload.baseline_run_id, records=(record,), imported_at=now,
        )
        try:
            async with session_scope(request) as session:
                result = await FindingOperationsRepository(
                    session, tenant_id=guard.security.tenant_id, actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                ).import_batch(batch)
        except ValueError as exc:
            raise ApiError(409, "finding_import_conflict", str(exc)) from exc
        return {"data": result}

    @app.post("/api/v1/finding-operations/issues/{issue_id}/review",
              operation_id="review_finding_operations_issue", response_model=FindingOperationsIssueResponse)
    async def review_finding_operations_issue(
        issue_id: str, payload: FindingOperationsReviewRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("finding:review", mutation=True)),
    ) -> dict:
        from redagent_platform.finding_operations.repository import FindingOperationsRepository

        _require_finding_operations_promotion(_now())
        try:
            async with session_scope(request) as session:
                row = await FindingOperationsRepository(
                    session, tenant_id=guard.security.tenant_id, actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                ).review_issue(
                    issue_id=issue_id, operation_id=payload.operation_id,
                    disposition=payload.disposition, rationale=payload.reason_code, occurred_at=_now(),
                )
        except ValueError as exc:
            raise ApiError(409, "finding_review_conflict", str(exc)) from exc
        return {"data": _public_finding_issue(row)}

    @app.post("/api/v1/finding-operations/reports", operation_id="create_finding_operations_report",
              response_model=FindingOperationsReportResponse, status_code=status.HTTP_201_CREATED)
    async def create_finding_operations_report(
        payload: FindingOperationsReportRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("report:create", mutation=True)),
    ) -> dict:
        from redagent_platform.finding_operations.reporting import ReportClaimInput, ReportSnapshotInput
        from redagent_platform.finding_operations.repository import FindingOperationsRepository

        now = _now()
        _require_finding_operations_promotion(now)
        try:
            async with session_scope(request) as session:
                row = await FindingOperationsRepository(
                    session, tenant_id=guard.security.tenant_id, actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                ).store_report(ReportSnapshotInput(
                    report_id=payload.report_id, tenant_id=guard.security.tenant_id, audience=payload.audience,
                    policy_revision="r099-v1", roe_version_id="roe-r115-reviewed",
                    reviewed_snapshot_sha256=payload.reviewed_snapshot_sha256,
                    coverage_state=payload.coverage_state,
                    partial_coverage_disclosed=payload.partial_coverage_disclosed,
                    independently_reviewed=True, evidence_redaction_state="report_safe", generated_at=now,
                    claims=(ReportClaimInput(
                        claim_id=f"claim-{payload.report_id}", text="Reviewed fixture observation.",
                        evidence_sha256s=(payload.evidence_sha256,), reviewer_adopted=True, ai_drafted=False,
                    ),),
                ))
        except ValueError as exc:
            raise ApiError(409, "finding_report_conflict", str(exc)) from exc
        return {"data": _public_finding_report(row)}

    @app.post("/api/v1/finding-operations/deliveries", operation_id="queue_finding_operations_delivery",
              response_model=FindingOperationsDeliveryResponse, status_code=status.HTTP_202_ACCEPTED)
    async def queue_finding_operations_delivery(
        payload: FindingOperationsDeliveryRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("connector:deliver", mutation=True)),
    ) -> dict:
        from redagent_platform.finding_operations.repository import FindingOperationsRepository

        now = _now()
        _require_finding_operations_promotion(now)
        try:
            async with session_scope(request) as session:
                repository = FindingOperationsRepository(
                    session, tenant_id=guard.security.tenant_id, actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                )
                await repository.ensure_fixture_profile(profile_id=payload.profile_id, occurred_at=now)
                row = await repository.queue_fixture_delivery(
                    delivery_id=payload.delivery_id, profile_id=payload.profile_id,
                    report_id=payload.report_id, snapshot_sha256=payload.report_sha256,
                    destination_key=f"fixture-project:{payload.destination_object_id}",
                    fields=("issue_id", "severity", "snapshot_sha256"),
                    idempotency_key=_idempotency(guard), occurred_at=now,
                )
        except ValueError as exc:
            raise ApiError(409, "finding_delivery_conflict", str(exc)) from exc
        return {"data": _public_finding_delivery(row, payload.profile_id, payload.report_id)}

    @app.post("/api/v1/finding-operations/reports/{report_id}/publish",
              operation_id="publish_finding_operations_report",
              response_model=FindingOperationsPublicationResponse)
    async def publish_finding_operations_report(
        report_id: str, payload: FindingOperationsPublishRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("report:publish", mutation=True)),
    ) -> dict:
        from redagent_platform.finding_operations.repository import FindingOperationsRepository

        _require_finding_operations_promotion(_now())
        try:
            async with session_scope(request) as session:
                row = await FindingOperationsRepository(
                    session, tenant_id=guard.security.tenant_id, actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                ).publish_report(
                    report_id=report_id, report_sha256=payload.report_sha256,
                    publication_id=payload.publication_id, occurred_at=_now(),
                )
        except ValueError as exc:
            raise ApiError(409, "finding_publication_conflict", str(exc)) from exc
        return {"data": _public_finding_publication(row, report_id)}
