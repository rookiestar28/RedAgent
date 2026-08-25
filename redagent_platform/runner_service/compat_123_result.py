"""Canonical evidence and compat_115 import writer for bounded compat_123 adapter results."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import re
from typing import Protocol

from sqlalchemy import and_, select

from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.evidence_service.contracts import (
    ArtifactClass,
    ArtifactWriteRequest,
    DataClassification,
    RetentionMode,
)
from redagent_platform.finding_operations.contracts import (
    CoverageState,
    FindingOccurrenceInput,
    ImportBatch,
)
from redagent_platform.finding_operations.repository import FindingOperationsRepository
from redagent_platform.persistence.models import metadata
from redagent_platform.runner_service.compat_123_dispatch import (
    AdapterTerminalReceipt,
    R123AdapterRequest,
)


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
_OWNER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


@dataclass(frozen=True, slots=True, kw_only=True)
class NormalizedAdapterFindingV1:
    source_record_id: str
    tool: str
    tool_version: str
    rule_id: str
    rule_version: str
    database_version: str
    title: str
    resource_identity: str
    location: str
    severity: str
    confidence: str
    taxonomy_ids: tuple[str, ...]
    control_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in (
            "source_record_id",
            "tool",
            "tool_version",
            "rule_id",
            "rule_version",
            "database_version",
        ):
            if not _ID.fullmatch(getattr(self, name)):
                raise ValueError(f"r123_normalized_{name}_invalid")
        for name, maximum in (
            ("title", 200),
            ("resource_identity", 500),
            ("location", 500),
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > maximum:
                raise ValueError(f"r123_normalized_{name}_invalid")
        if self.severity not in {"informational", "low", "medium", "high", "critical"}:
            raise ValueError("r123_normalized_severity_invalid")
        if self.confidence not in {"low", "medium", "high", "confirmed"}:
            raise ValueError("r123_normalized_confidence_invalid")
        for name in ("taxonomy_ids", "control_ids"):
            values = getattr(self, name)
            if (
                not isinstance(values, tuple)
                or len(values) > 32
                or len(set(values)) != len(values)
                or any(not _ID.fullmatch(value) for value in values)
            ):
                raise ValueError(f"r123_normalized_{name}_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class AdapterResultMaterialV1:
    request: R123AdapterRequest
    report_safe_content: bytes
    findings: tuple[NormalizedAdapterFindingV1, ...]
    coverage_state: CoverageState
    cleanup_receipt_id: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.request, R123AdapterRequest):
            raise ValueError("r123_result_request_invalid")
        if not isinstance(self.report_safe_content, bytes) or not 1 <= len(
            self.report_safe_content
        ) <= 1_048_576:
            raise ValueError("r123_result_content_invalid")
        if (
            not isinstance(self.findings, tuple)
            or len(self.findings) > 100
            or not all(isinstance(item, NormalizedAdapterFindingV1) for item in self.findings)
        ):
            raise ValueError("r123_result_findings_invalid")
        if self.coverage_state not in {
            CoverageState.COMPLETE,
            CoverageState.PARTIAL,
            CoverageState.UNKNOWN,
        }:
            raise ValueError("r123_result_coverage_invalid")
        if not _ID.fullmatch(self.cleanup_receipt_id):
            raise ValueError("r123_result_cleanup_receipt_invalid")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("r123_result_observed_at_invalid")


class AdapterResultWriter(Protocol):
    async def persist(
        self, material: AdapterResultMaterialV1
    ) -> AdapterTerminalReceipt: ...

    async def lookup(
        self,
        request: R123AdapterRequest,
        *,
        cleanup_receipt_id: str,
    ) -> AdapterTerminalReceipt | None: ...


class PostgresAdapterResultWriter:
    """Write report-safe evidence and accepted complete compat_115 coverage before runner success."""

    def __init__(
        self,
        sessions: object,
        evidence_service: object,
        *,
        actor_user_id: str,
        kms_reference: str,
        retention_days: int = 30,
    ) -> None:
        if not _OWNER_ID.fullmatch(actor_user_id) or not isinstance(kms_reference, str) or not kms_reference:
            raise ValueError("r123_result_writer_config_invalid")
        if isinstance(retention_days, bool) or not 1 <= retention_days <= 3650:
            raise ValueError("r123_result_writer_config_invalid")
        self._sessions = sessions
        self._evidence_service = evidence_service
        self._actor_user_id = actor_user_id
        self._kms_reference = kms_reference
        self._retention_days = retention_days

    async def persist(
        self,
        material: AdapterResultMaterialV1,
    ) -> AdapterTerminalReceipt:
        request = material.request
        binding = closed_execution_registry().get(request.capability_key)
        if binding is None or (binding.adapter_id, binding.adapter_version) != (
            request.adapter_id,
            request.adapter_version,
        ):
            raise ValueError("r123_result_binding_invalid")
        async with self._sessions() as session, session.begin():
            context = await _result_context(session, request)
        stable = hashlib.sha256(
            f"{request.tenant_id}\0{request.effect_id}".encode("utf-8")
        ).hexdigest()[:24]
        evidence_id = f"evidence-r123-{stable}"
        execution_id = f"execution-r123-{stable}"
        import_id = f"import-r123-{stable}"
        evidence = await self._evidence_service.ingest(
            ArtifactWriteRequest(
                tenant_id=request.tenant_id,
                artifact_id=evidence_id,
                engagement_id=str(context["engagement_id"]),
                job_id=str(context["job_id"]),
                producer_id=self._actor_user_id,
                content=material.report_safe_content,
                content_type="application/json",
                artifact_class=ArtifactClass.REPORT_SAFE,
                classification=DataClassification.INTERNAL,
                redaction_state="report_safe",
                retention_mode=RetentionMode.GOVERNANCE,
                retain_until=material.observed_at + timedelta(days=self._retention_days),
                legal_hold=False,
                kms_reference=self._kms_reference,
                policy_reference=str(context["policy_reference"]),
                idempotency_key=f"r123-evidence-{stable}",
            ),
            actor_user_id=self._actor_user_id,
            correlation_id=f"r123-result-evidence-{stable}",
            occurred_at=material.observed_at,
        )
        content_sha256 = str(evidence.artifact["content_sha256"])
        records = tuple(
            FindingOccurrenceInput(
                source_record_id=item.source_record_id,
                tool=item.tool,
                tool_version=item.tool_version,
                rule_id=item.rule_id,
                rule_version=item.rule_version,
                database_version=item.database_version,
                title=item.title,
                resource_identity=item.resource_identity,
                location=item.location,
                severity=item.severity,
                confidence=item.confidence,
                taxonomy_ids=item.taxonomy_ids,
                control_ids=item.control_ids,
                evidence_id=evidence_id,
                evidence_sha256=content_sha256,
                redaction_state="report_safe",
                observed_at=material.observed_at,
            )
            for item in material.findings
        )
        async with self._sessions() as session, session.begin():
            finding_repository = FindingOperationsRepository(
                session,
                tenant_id=request.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=f"r123-result-import-{stable}",
            )
            imported = await finding_repository.import_batch(
                ImportBatch(
                    import_id=import_id,
                    tenant_id=request.tenant_id,
                    adapter_id=request.adapter_id,
                    run_id=execution_id,
                    coverage_state=material.coverage_state,
                    comparable_baseline_run_id=None,
                    records=records,
                    imported_at=material.observed_at,
                )
            )
            await _advance_retests(
                session,
                finding_repository,
                request=request,
                campaign_id=str(context["campaign_id"]),
                execution_id=execution_id,
                issue_ids=tuple(imported["issue_ids"]),
                occurred_at=material.observed_at,
            )
        return AdapterTerminalReceipt(
            invocation_id=request.invocation_id,
            effect_id=request.effect_id,
            state="confirmed",
            external_receipt_id=execution_id,
            evidence_ids=(evidence_id,),
            cleanup_receipt_id=material.cleanup_receipt_id,
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )

    async def lookup(
        self,
        request: R123AdapterRequest,
        *,
        cleanup_receipt_id: str,
    ) -> AdapterTerminalReceipt | None:
        """Read exact canonical result ownership without creating or repairing records."""
        stable = hashlib.sha256(
            f"{request.tenant_id}\0{request.effect_id}".encode("utf-8")
        ).hexdigest()[:24]
        evidence_id = f"evidence-r123-{stable}"
        execution_id = f"execution-r123-{stable}"
        import_id = f"import-r123-{stable}"
        async with self._sessions() as session, session.begin():
            await _result_context(session, request)
            artifacts = metadata.tables["evidence_artifacts"]
            receipts = metadata.tables["runner_execution_receipts"]
            imports = metadata.tables["finding_import_sessions"]
            row = (
                await session.execute(
                    select(
                        artifacts.c.id,
                        artifacts.c.artifact_class,
                        artifacts.c.redaction_state,
                        artifacts.c.quarantine_reason,
                        artifacts.c.finalized_at,
                        receipts.c.outcome,
                        receipts.c.cleanup_completed,
                        receipts.c.residual_risk,
                        imports.c.adapter_id,
                        imports.c.coverage_state,
                        imports.c.import_state,
                    )
                    .join(
                        receipts,
                        and_(
                            receipts.c.tenant_id == artifacts.c.tenant_id,
                            receipts.c.evidence_artifact_id == artifacts.c.id,
                        ),
                    )
                    .join(
                        imports,
                        and_(
                            imports.c.tenant_id == artifacts.c.tenant_id,
                            imports.c.run_id == receipts.c.execution_id,
                        ),
                    )
                    .where(
                        artifacts.c.tenant_id == request.tenant_id,
                        artifacts.c.id == evidence_id,
                        receipts.c.execution_id == execution_id,
                        imports.c.import_id == import_id,
                    )
                )
            ).mappings().one_or_none()
        if row is None:
            return None
        if (
            row["artifact_class"] not in {"report_safe", "export_safe"}
            or row["redaction_state"] != row["artifact_class"]
            or row["quarantine_reason"] is not None
            or row["finalized_at"] is None
            or row["outcome"] != "succeeded"
            or row["cleanup_completed"] is not True
            or row["residual_risk"] is not None
            or row["adapter_id"] != request.adapter_id
            or row["coverage_state"] not in {"complete", "partial", "unknown"}
            or row["import_state"] != "accepted"
        ):
            return None
        return AdapterTerminalReceipt(
            invocation_id=request.invocation_id,
            effect_id=request.effect_id,
            state="confirmed",
            external_receipt_id=execution_id,
            evidence_ids=(evidence_id,),
            cleanup_receipt_id=cleanup_receipt_id,
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )


async def _result_context(session: object, request: R123AdapterRequest):
    manifests = metadata.tables["runner_job_manifests"]
    jobs = metadata.tables["jobs"]
    row = (
        await session.execute(
            select(
                jobs.c.id.label("job_id"),
                jobs.c.campaign_id,
                jobs.c.engagement_id,
                jobs.c.policy_reference,
                jobs.c.request,
            )
            .join(
                manifests,
                and_(
                    manifests.c.tenant_id == jobs.c.tenant_id,
                    manifests.c.job_id == jobs.c.id,
                ),
            )
            .where(
                jobs.c.tenant_id == request.tenant_id,
                manifests.c.manifest_sha256 == request.manifest_v2_sha256,
                manifests.c.capability_id == request.capability_id,
                manifests.c.capability_revision == request.capability_revision,
            )
        )
    ).mappings().one_or_none()
    if row is None or row["request"].get("effect_id") != request.effect_id:
        raise ValueError("r123_result_manifest_job_mismatch")
    return row


async def _advance_retests(
    session: object,
    repository: FindingOperationsRepository,
    *,
    request: R123AdapterRequest,
    campaign_id: str,
    execution_id: str,
    issue_ids: tuple[str, ...],
    occurred_at: datetime,
) -> None:
    effects = metadata.tables["campaign_effects"]
    rows = (
        await session.execute(
            select(effects.c.effect_id, effects.c.external_receipt_id)
            .where(
                effects.c.tenant_id == request.tenant_id,
                effects.c.campaign_id == campaign_id,
            )
            .order_by(effects.c.outbox_sequence)
        )
    ).mappings().all()
    index = next(
        (position for position, row in enumerate(rows) if row["effect_id"] == request.effect_id),
        None,
    )
    if index is None or index > 1:
        raise ValueError("r123_result_effect_inventory_invalid")
    # CRITICAL: a different capability's successor observation is not an compat_115
    # remediation retest of the primary issue and must never auto-pass it.
    if index == 1:
        return
    retests = metadata.tables["finding_retests"]
    issues = metadata.tables["managed_issues"]
    for issue_id in issue_ids:
        retest_id = "retest-r123-" + hashlib.sha256(
            f"{request.tenant_id}\0{issue_id}\0{execution_id}".encode("utf-8")
        ).hexdigest()[:24]
        existing = await session.scalar(
            select(retests.c.id)
            .join(issues, issues.c.id == retests.c.issue_record_id)
            .where(
                retests.c.tenant_id == request.tenant_id,
                retests.c.retest_id == retest_id,
                issues.c.issue_id == issue_id,
            )
        )
        if existing is None:
            await repository.request_retest(
                issue_id=issue_id,
                retest_id=retest_id,
                baseline_run_id=execution_id,
                occurred_at=occurred_at,
            )
