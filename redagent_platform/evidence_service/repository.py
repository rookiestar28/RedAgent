"""Transactional PostgreSQL repository for compat_097 evidence truth."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import insert, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.evidence_service.contracts import (
    ArtifactClass,
    ArtifactWriteRequest,
    EvidenceDerivativeRequest,
    EvidencePurpose,
    ObjectVerification,
    OperationState,
    StoredObjectVersion,
)
from redagent_platform.persistence.models import metadata


_FINALIZE_WRITES = text(
    """
    WITH tenant_context AS MATERIALIZED (
        SELECT set_config('redagent.tenant_id', CAST(:tenant_id AS text), true)
    ), operation_write AS (
        UPDATE evidence_operations
        SET operation_state = 'finalized',
            object_version_id = CAST(:object_version_id AS varchar(255)),
            version = version + CAST(:operation_version_increment AS integer),
            updated_at = CAST(:occurred_at AS timestamptz)
        FROM tenant_context
        WHERE tenant_id = CAST(:tenant_id AS varchar(64))
            AND id = CAST(:operation_id AS varchar(64))
            AND operation_state = CAST(:expected_operation_state AS varchar(32))
            AND artifact_id = CAST(:artifact_id AS varchar(64))
            AND object_key = CAST(:object_key AS varchar(1000))
            AND (
                object_version_id IS NULL
                OR object_version_id = CAST(:object_version_id AS varchar(255))
            )
        RETURNING id
    ), artifact_write AS (
        INSERT INTO evidence_artifacts (
            id, engagement_id, job_id, producer_id, object_key, object_version_id,
            content_sha256, provider_checksum, size_bytes, content_type, artifact_class,
            classification, redaction_state, retention_mode, retain_until, legal_hold,
            kms_reference, attestation_hash, policy_reference, quarantine_reason,
            finalized_at, tenant_id, version, created_at, updated_at
        ) SELECT
            :artifact_id, :engagement_id, :job_id, :producer_id, :object_key,
            :object_version_id, :content_sha256, :provider_checksum, :size_bytes,
            :content_type, :artifact_class, :classification, :redaction_state,
            :retention_mode, :retain_until, :legal_hold, :kms_reference,
            :attestation_hash, :policy_reference, NULL, :occurred_at, :tenant_id,
            1, :occurred_at, :occurred_at
        FROM operation_write
        RETURNING id
    ), verification_write AS (
        INSERT INTO evidence_verifications (
            id, artifact_id, object_key, object_version_id, content_sha256,
            provider_checksum, size_bytes, verified, quarantine_reason, verified_at,
            tenant_id, version, created_at, updated_at
        )
        SELECT :verification_id, artifact_write.id, :object_key, :object_version_id,
            :content_sha256, :provider_checksum, :size_bytes, TRUE, NULL,
            :occurred_at, :tenant_id, 1, :occurred_at, :occurred_at
        FROM artifact_write
        RETURNING id
    ), custody_write AS (
        INSERT INTO evidence_custody_events (
            id, artifact_id, event_type, actor_id, attestation_hash, details,
            occurred_at, tenant_id, version, created_at, updated_at
        )
        SELECT events.event_id, artifact_write.id, events.event_type,
            :actor_user_id, :attestation_hash, CAST(:custody_details AS jsonb),
            :occurred_at, :tenant_id, 1, :occurred_at, :occurred_at
        FROM artifact_write
        CROSS JOIN (VALUES
            (:custody_collected_id, 'collected'),
            (:custody_stored_id, 'stored'),
            (:custody_verified_id, 'verified')
        ) AS events(event_id, event_type)
        RETURNING id
    ), audit_write AS (
        INSERT INTO audit_events (
            id, actor_user_id, action, subject_type, subject_id, correlation_id,
            details, tenant_id, version, created_at, updated_at
        )
        SELECT :audit_id, :actor_user_id, 'evidence.artifact.finalized',
            'evidence_artifact', artifact_write.id, :correlation_id,
            CAST(:event_details AS jsonb), :tenant_id, 1, :occurred_at, :occurred_at
        FROM artifact_write
        RETURNING id
    ), outbox_write AS (
        INSERT INTO outbox_events (
            id, event_type, aggregate_id, payload, published, tenant_id,
            version, created_at, updated_at
        )
        SELECT :outbox_id, 'evidence.artifact.finalized', artifact_write.id,
            CAST(:outbox_payload AS jsonb), FALSE, :tenant_id, 1,
            :occurred_at, :occurred_at
        FROM artifact_write
        RETURNING id
    )
    SELECT
        (SELECT count(*) FROM artifact_write) AS artifact_count,
        (SELECT count(*) FROM verification_write) AS verification_count,
        (SELECT count(*) FROM custody_write) AS custody_count,
        (SELECT count(*) FROM audit_write) AS audit_count,
        (SELECT count(*) FROM outbox_write) AS outbox_count,
        (SELECT count(*) FROM operation_write) AS operation_count
    """
)

_RESERVE_FAST = text(
    """
    WITH tenant_context AS MATERIALIZED (
        SELECT set_config('redagent.tenant_id', CAST(:tenant_id AS text), true)
    )
    INSERT INTO evidence_operations (
        id, artifact_id, idempotency_key, request_hash, operation_state,
        object_key, object_version_id, quarantine_reason, provider_error_code,
        tenant_id, version, created_at, updated_at
    )
    SELECT CAST(:operation_id AS varchar(64)), CAST(:artifact_id AS varchar(64)),
        CAST(:idempotency_key AS varchar(200)), CAST(:request_hash AS varchar(64)),
        'reserved', CAST(:object_key AS varchar(1000)), NULL, NULL, NULL,
        CAST(:tenant_id AS varchar(64)), 1,
        CAST(:occurred_at AS timestamptz), CAST(:occurred_at AS timestamptz)
    FROM jobs CROSS JOIN tenant_context
    WHERE tenant_id = CAST(:tenant_id AS varchar(64))
        AND id = CAST(:job_id AS varchar(64))
        AND engagement_id = CAST(:engagement_id AS varchar(64))
        AND policy_reference = CAST(:policy_reference AS varchar(200))
    ON CONFLICT DO NOTHING
    RETURNING id
    """
)


class EvidenceIdempotencyConflict(RuntimeError):
    """An evidence idempotency key or artifact ID was reused inconsistently."""


class EvidenceRecordConflict(RuntimeError):
    """Evidence state cannot be reconciled with the requested operation."""


class EvidenceOperationPending(EvidenceRecordConflict):
    """A known operation is still legitimately waiting for its first object version."""


@dataclass(frozen=True, slots=True)
class EvidenceReservation:
    operation_id: str
    object_key: str
    replayed: bool
    operation_state: str
    artifact: dict[str, object] | None


def evidence_request_hash(request: ArtifactWriteRequest) -> str:
    payload = {
        name: value.value if hasattr(value, "value") else value.isoformat() if isinstance(value, datetime) else value
        for name, value in asdict(request).items()
        if name != "content"
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EvidenceRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.actor_user_id = actor_user_id
        self.correlation_id = correlation_id
        self._tenant_context_transaction: object | None = None

    async def current_policy_facts(self, request: ArtifactWriteRequest) -> dict[str, object]:
        await self._tenant_context()
        jobs = metadata.tables["jobs"]
        job = (
            await self.session.execute(select(jobs).where(
                jobs.c.tenant_id == self.tenant_id,
                jobs.c.id == request.job_id,
                jobs.c.engagement_id == request.engagement_id,
            ))
        ).mappings().one_or_none()
        if job is None:
            raise EvidenceRecordConflict("evidence_policy_job_scope_invalid")
        if request.tenant_id != self.tenant_id:
            raise EvidenceRecordConflict("evidence_policy_tenant_scope_invalid")
        if request.producer_id != self.actor_user_id:
            raise EvidenceRecordConflict("evidence_policy_producer_scope_invalid")
        if job["policy_reference"] != request.policy_reference:
            raise EvidenceRecordConflict("evidence_policy_reference_scope_invalid")
        roe = metadata.tables["roe_versions"]
        roe_status = await self.session.scalar(select(roe.c.status).where(
            roe.c.tenant_id == self.tenant_id,
            roe.c.id == job["roe_version_id"],
        ))
        return {
            "roe_version_id": str(job["roe_version_id"]),
            "roe_status": "current" if roe_status == "approved" else str(roe_status or "missing"),
            "job_status": str(job["status"]),
        }

    async def reserve(
        self,
        request: ArtifactWriteRequest,
        *,
        object_key: str,
        occurred_at: datetime,
    ) -> EvidenceReservation:
        request_hash = evidence_request_hash(request)
        operations = metadata.tables["evidence_operations"]
        if request.tenant_id != self.tenant_id or request.producer_id != self.actor_user_id:
            raise EvidenceRecordConflict("evidence_actor_or_tenant_mismatch")
        operation_id = f"evidence-operation-{uuid4().hex}"
        inserted = (
            await self.session.execute(
                _RESERVE_FAST,
                {
                    "operation_id": operation_id,
                    "artifact_id": request.artifact_id,
                    "idempotency_key": request.idempotency_key,
                    "request_hash": request_hash,
                    "object_key": object_key,
                    "tenant_id": self.tenant_id,
                    "occurred_at": occurred_at,
                    "job_id": request.job_id,
                    "engagement_id": request.engagement_id,
                    "policy_reference": request.policy_reference,
                },
            )
        ).scalar_one_or_none()
        if inserted is not None:
            return EvidenceReservation(operation_id, object_key, False, OperationState.RESERVED.value, None)
        await self._tenant_context()
        existing = (
            await self.session.execute(
                select(operations).where(
                    operations.c.tenant_id == self.tenant_id,
                    or_(
                        operations.c.idempotency_key == request.idempotency_key,
                        operations.c.artifact_id == request.artifact_id,
                    ),
                )
            )
        ).mappings().one_or_none()
        if existing is not None:
            if (
                existing["idempotency_key"] != request.idempotency_key
                or existing["request_hash"] != request_hash
                or existing["artifact_id"] != request.artifact_id
            ):
                raise EvidenceIdempotencyConflict("evidence_idempotency_mismatch")
            return EvidenceReservation(
                operation_id=str(existing["id"]),
                object_key=str(existing["object_key"]),
                replayed=True,
                operation_state=str(existing["operation_state"]),
                artifact=await self.get_artifact(request.artifact_id),
            )
        jobs = metadata.tables["jobs"]
        job = (
            await self.session.execute(
                select(jobs.c.policy_reference).where(
                    jobs.c.tenant_id == self.tenant_id,
                    jobs.c.id == request.job_id,
                    jobs.c.engagement_id == request.engagement_id,
                )
            )
        ).scalar_one_or_none()
        if job is None:
            raise EvidenceRecordConflict("evidence_job_scope_not_found")
        raise EvidenceRecordConflict("evidence_policy_reference_mismatch")

    async def mutation_replay(
        self,
        operation: str,
        idempotency_key: str,
        request: dict[str, object],
    ) -> dict[str, object] | None:
        await self._tenant_context()
        request_hash = _canonical_hash(request)
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"evidence-mutation:{self.tenant_id}:{operation}:{idempotency_key}"},
        )
        table = metadata.tables["idempotency_records"]
        row = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.operation == operation,
                    table.c.idempotency_key == idempotency_key,
                )
            )
        ).mappings().one_or_none()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise EvidenceIdempotencyConflict("evidence_idempotency_mismatch")
        return dict(row["response_body"]["resource"])

    async def record_mutation_response(
        self,
        operation: str,
        idempotency_key: str,
        request: dict[str, object],
        resource: dict[str, object],
        *,
        occurred_at: datetime,
    ) -> None:
        table = metadata.tables["idempotency_records"]
        await self.session.execute(
            insert(table).values(
                id=f"evidence-idempotency-{uuid4().hex}",
                tenant_id=self.tenant_id,
                operation=operation,
                idempotency_key=idempotency_key,
                request_hash=_canonical_hash(request),
                response_status=200,
                response_body={"resource": _json_safe(resource)},
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )

    async def mark_uploaded(self, operation_id: str, stored: StoredObjectVersion, *, occurred_at: datetime) -> None:
        await self._tenant_context()
        operations = metadata.tables["evidence_operations"]
        row = (
            await self.session.execute(
                update(operations)
                .where(
                    operations.c.tenant_id == self.tenant_id,
                    operations.c.id == operation_id,
                    operations.c.object_key == stored.object_key,
                    operations.c.operation_state == OperationState.RESERVED.value,
                )
                .values(
                    operation_state=OperationState.UPLOADED.value,
                    object_version_id=stored.version_id,
                    version=operations.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(operations.c.id)
            )
        ).scalar_one_or_none()
        if row is None:
            existing = (
                await self.session.execute(
                    select(operations).where(
                        operations.c.tenant_id == self.tenant_id,
                        operations.c.id == operation_id,
                    )
                )
            ).mappings().one_or_none()
            if (
                existing is not None
                and existing["object_key"] == stored.object_key
                and existing["object_version_id"] == stored.version_id
                and existing["operation_state"] in {OperationState.UPLOADED.value, OperationState.FINALIZED.value}
            ):
                return
            raise EvidenceRecordConflict("evidence_operation_upload_conflict")

    async def quarantine_operation(
        self,
        operation_id: str,
        *,
        reason: str,
        occurred_at: datetime,
    ) -> None:
        await self._tenant_context()
        operations = metadata.tables["evidence_operations"]
        row = (
            await self.session.execute(
                update(operations)
                .where(
                    operations.c.tenant_id == self.tenant_id,
                    operations.c.id == operation_id,
                    operations.c.operation_state.in_((OperationState.RESERVED.value, OperationState.UPLOADED.value)),
                )
                .values(
                    operation_state=OperationState.QUARANTINED.value,
                    quarantine_reason=reason,
                    version=operations.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(operations.c.artifact_id)
            )
        ).scalar_one_or_none()
        if row is None:
            return
        await self._audit_outbox(
            operation_id,
            "evidence.operation.quarantined",
            {"artifact_id": str(row), "reason": reason},
            occurred_at,
            subject_type="evidence_operation",
        )

    async def finalize(
        self,
        operation_id: str,
        request: ArtifactWriteRequest,
        stored: StoredObjectVersion,
        verification: ObjectVerification,
        *,
        occurred_at: datetime,
        operation_prevalidated: bool = False,
    ) -> dict[str, object]:
        if not verification.ok:
            raise EvidenceRecordConflict("unverified_evidence_cannot_finalize")
        operations = metadata.tables["evidence_operations"]
        if not operation_prevalidated:
            await self._tenant_context()
            await self.session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"evidence-finalize:{self.tenant_id}:{request.artifact_id}"},
            )
            operation = (
                await self.session.execute(
                    select(operations).where(
                        operations.c.tenant_id == self.tenant_id,
                        operations.c.id == operation_id,
                        operations.c.artifact_id == request.artifact_id,
                        operations.c.object_key == stored.object_key,
                        operations.c.object_version_id == stored.version_id,
                        operations.c.operation_state == OperationState.UPLOADED.value,
                    )
                )
            ).mappings().one_or_none()
            if operation is None:
                existing = await self.get_artifact(request.artifact_id)
                if (
                    existing is not None
                    and existing["object_key"] == stored.object_key
                    and existing["object_version_id"] == stored.version_id
                    and existing["content_sha256"] == stored.content_sha256
                ):
                    return existing
                raise EvidenceRecordConflict("evidence_operation_finalize_conflict")
        artifacts = metadata.tables["evidence_artifacts"]
        attestation_hash = _attestation_hash(request, stored)
        resource = {
            "artifact_id": request.artifact_id,
            "tenant_id": self.tenant_id,
            "engagement_id": request.engagement_id,
            "job_id": request.job_id,
            "producer_id": request.producer_id,
            "object_key": stored.object_key,
            "object_version_id": stored.version_id,
            "content_sha256": stored.content_sha256,
            "provider_checksum": stored.provider_checksum,
            "size_bytes": stored.size_bytes,
            "content_type": stored.content_type,
            "artifact_class": request.artifact_class.value,
            "classification": request.classification.value,
            "redaction_state": request.redaction_state,
            "retention_mode": request.retention_mode.value,
            "retain_until": request.retain_until,
            "legal_hold": request.legal_hold,
            "kms_reference": request.kms_reference,
            "attestation_hash": attestation_hash,
            "policy_reference": request.policy_reference,
            "quarantine_reason": None,
            "version": 1,
        }
        receipt = (
            await self.session.execute(
                _FINALIZE_WRITES,
                {
                    "artifact_id": request.artifact_id,
                    "tenant_id": self.tenant_id,
                    "engagement_id": request.engagement_id,
                    "job_id": request.job_id,
                    "producer_id": request.producer_id,
                    "object_key": stored.object_key,
                    "object_version_id": stored.version_id,
                    "content_sha256": stored.content_sha256,
                    "provider_checksum": stored.provider_checksum,
                    "size_bytes": stored.size_bytes,
                    "content_type": stored.content_type,
                    "artifact_class": request.artifact_class.value,
                    "classification": request.classification.value,
                    "redaction_state": request.redaction_state,
                    "retention_mode": request.retention_mode.value,
                    "retain_until": request.retain_until,
                    "legal_hold": request.legal_hold,
                    "kms_reference": request.kms_reference,
                    "attestation_hash": attestation_hash,
                    "policy_reference": request.policy_reference,
                    "occurred_at": occurred_at,
                    "verification_id": f"evidence-verification-{uuid4().hex}",
                    "custody_collected_id": f"evidence-custody-{uuid4().hex}",
                    "custody_stored_id": f"evidence-custody-{uuid4().hex}",
                    "custody_verified_id": f"evidence-custody-{uuid4().hex}",
                    "custody_details": json.dumps({"correlation_id": self.correlation_id}),
                    "audit_id": f"audit-{uuid4().hex}",
                    "outbox_id": f"outbox-{uuid4().hex}",
                    "event_details": json.dumps(
                        {
                            "content_sha256": stored.content_sha256,
                            "object_version_id": stored.version_id,
                        }
                    ),
                    "outbox_payload": json.dumps(
                        {
                            "subject_type": "evidence_artifact",
                            "subject_id": request.artifact_id,
                            "content_sha256": stored.content_sha256,
                            "object_version_id": stored.version_id,
                        }
                    ),
                    "actor_user_id": self.actor_user_id,
                    "correlation_id": self.correlation_id,
                    "operation_id": operation_id,
                    "expected_operation_state": (
                        OperationState.RESERVED.value if operation_prevalidated else OperationState.UPLOADED.value
                    ),
                    "operation_version_increment": 2 if operation_prevalidated else 1,
                },
            )
        ).mappings().one()
        if tuple(int(receipt[name]) for name in receipt) != (1, 1, 3, 1, 1, 1):
            raise EvidenceRecordConflict("evidence_finalize_write_incomplete")
        return resource

    async def get_artifact(self, artifact_id: str) -> dict[str, object] | None:
        await self._tenant_context()
        table = metadata.tables["evidence_artifacts"]
        row = (
            await self.session.execute(
                select(table).where(table.c.tenant_id == self.tenant_id, table.c.id == artifact_id)
            )
        ).mappings().one_or_none()
        return _public_artifact(row) if row is not None else None

    async def list_artifacts(self, *, limit: int, offset: int) -> tuple[dict[str, object], ...]:
        await self._tenant_context()
        table = metadata.tables["evidence_artifacts"]
        rows = (
            await self.session.execute(
                select(table)
                .where(table.c.tenant_id == self.tenant_id)
                .order_by(table.c.created_at.desc(), table.c.id)
                .limit(limit)
                .offset(offset)
            )
        ).mappings().all()
        return tuple(_public_artifact(row) for row in rows)

    async def get_artifact_detail(self, artifact_id: str) -> dict[str, object] | None:
        artifact = await self.get_artifact(artifact_id)
        if artifact is None:
            return None
        derivatives = metadata.tables["evidence_derivatives"]
        custody = metadata.tables["evidence_custody_events"]
        verifications = metadata.tables["evidence_verifications"]
        lineage = (
            await self.session.execute(
                select(derivatives).where(
                    derivatives.c.tenant_id == self.tenant_id,
                    derivatives.c.artifact_id == artifact_id,
                )
            )
        ).mappings().one_or_none()
        custody_count = await self.session.scalar(
            select(text("count(*)")).select_from(custody).where(
                custody.c.tenant_id == self.tenant_id,
                custody.c.artifact_id == artifact_id,
            )
        )
        verification_rows = (
            await self.session.execute(
                select(verifications.c.verified, verifications.c.quarantine_reason, verifications.c.verified_at)
                .where(
                    verifications.c.tenant_id == self.tenant_id,
                    verifications.c.artifact_id == artifact_id,
                )
                .order_by(verifications.c.verified_at.desc())
            )
        ).mappings().all()
        return {
            **artifact,
            "source_artifact_id": str(lineage["source_artifact_id"]) if lineage else None,
            "transform_name": str(lineage["transform_name"]) if lineage else None,
            "transform_version": str(lineage["transform_version"]) if lineage else None,
            "transform_config_hash": str(lineage["transform_config_hash"]) if lineage else None,
            "custody_event_count": int(custody_count or 0),
            "verification_count": len(verification_rows),
            "last_verified": bool(verification_rows[0]["verified"]) if verification_rows else None,
            "last_verified_at": verification_rows[0]["verified_at"] if verification_rows else None,
        }

    async def register_derivative(
        self,
        request: EvidenceDerivativeRequest,
        *,
        occurred_at: datetime,
    ) -> None:
        await self._tenant_context()
        source = await self.get_artifact(request.source_artifact_id)
        derivative = await self.get_artifact(request.artifact_id)
        if source is None or derivative is None:
            raise EvidenceRecordConflict("evidence_derivative_artifact_not_found")
        if source["quarantine_reason"] is not None or derivative["quarantine_reason"] is not None:
            raise EvidenceRecordConflict("quarantined_evidence_derivative_forbidden")
        if source["engagement_id"] != derivative["engagement_id"] or source["job_id"] != derivative["job_id"]:
            raise EvidenceRecordConflict("evidence_derivative_scope_mismatch")
        if str(derivative["artifact_class"]) != request.artifact_class.value:
            raise EvidenceRecordConflict("evidence_derivative_class_mismatch")
        ranks = {item.value: rank for rank, item in enumerate(ArtifactClass)}
        if ranks[str(derivative["artifact_class"])] <= ranks[str(source["artifact_class"])]:
            raise EvidenceRecordConflict("evidence_derivative_sensitivity_not_reduced")
        table = metadata.tables["evidence_derivatives"]
        existing = (
            await self.session.execute(
                select(table).where(table.c.tenant_id == self.tenant_id, table.c.artifact_id == request.artifact_id)
            )
        ).mappings().one_or_none()
        expected = {
            "source_artifact_id": request.source_artifact_id,
            "source_object_version_id": str(source["object_version_id"]),
            "transform_name": request.transform_name,
            "transform_version": request.transform_version,
            "transform_config_hash": request.transform_config_hash,
        }
        if existing is not None:
            if any(str(existing[key]) != value for key, value in expected.items()):
                raise EvidenceRecordConflict("evidence_derivative_lineage_conflict")
            return
        await self.session.execute(
            insert(table).values(
                id=f"evidence-derivative-{uuid4().hex}",
                tenant_id=self.tenant_id,
                artifact_id=request.artifact_id,
                **expected,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self._record_custody(
            request.artifact_id,
            "transformed",
            str(derivative["attestation_hash"]),
            occurred_at,
        )
        await self._audit_outbox(
            request.artifact_id,
            "evidence.artifact.transformed",
            {
                "source_artifact_id": request.source_artifact_id,
                "transform_config_hash": request.transform_config_hash,
            },
            occurred_at,
        )

    async def select_for_purpose(
        self,
        source_artifact_id: str,
        purpose: EvidencePurpose,
    ) -> dict[str, object] | None:
        await self._tenant_context()
        artifacts = metadata.tables["evidence_artifacts"]
        derivatives = metadata.tables["evidence_derivatives"]
        rows = (
            await self.session.execute(
                select(artifacts)
                .outerjoin(
                    derivatives,
                    (derivatives.c.tenant_id == artifacts.c.tenant_id)
                    & (derivatives.c.artifact_id == artifacts.c.id),
                )
                .where(
                    artifacts.c.tenant_id == self.tenant_id,
                    artifacts.c.quarantine_reason.is_(None),
                    (artifacts.c.id == source_artifact_id)
                    | (derivatives.c.source_artifact_id == source_artifact_id),
                )
            )
        ).mappings().all()
        allowed = {
            EvidencePurpose.REVIEW: {ArtifactClass.REDACTED.value, ArtifactClass.REPORT_SAFE.value, ArtifactClass.EXPORT_SAFE.value},
            EvidencePurpose.REPORT: {ArtifactClass.REPORT_SAFE.value, ArtifactClass.EXPORT_SAFE.value},
            EvidencePurpose.EXPORT: {ArtifactClass.EXPORT_SAFE.value},
        }[purpose]
        candidates = [row for row in rows if str(row["artifact_class"]) in allowed]
        if not candidates:
            return None
        ranks = {item.value: rank for rank, item in enumerate(ArtifactClass)}
        selected = max(candidates, key=lambda row: ranks[str(row["artifact_class"])])
        return _public_artifact(selected)

    async def place_legal_hold(
        self,
        artifact_id: str,
        *,
        expected_version: int,
        occurred_at: datetime,
    ) -> dict[str, object]:
        await self._tenant_context()
        table = metadata.tables["evidence_artifacts"]
        row = (
            await self.session.execute(
                update(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == artifact_id,
                    table.c.version == expected_version,
                    table.c.legal_hold.is_(False),
                )
                .values(
                    legal_hold=True,
                    version=table.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(table)
            )
        ).mappings().one_or_none()
        if row is None:
            raise EvidenceRecordConflict("evidence_artifact_version_conflict")
        public = _public_artifact(row)
        await self._record_custody(
            artifact_id,
            "legal_hold_placed",
            str(public["attestation_hash"]),
            occurred_at,
        )
        await self._audit_outbox(
            artifact_id,
            "evidence.artifact.legal_hold_placed",
            {"object_version_id": public["object_version_id"]},
            occurred_at,
        )
        return public

    async def record_verification(
        self,
        artifact: dict[str, object],
        stored: StoredObjectVersion,
        verification: ObjectVerification,
        *,
        occurred_at: datetime,
    ) -> None:
        await self._tenant_context()
        artifact_id = str(artifact["artifact_id"])
        await self._record_verification_row(artifact_id, stored, verification, occurred_at)
        await self._record_custody(artifact_id, "verified" if verification.ok else "quarantined", str(artifact["attestation_hash"]), occurred_at)
        if not verification.ok:
            artifacts = metadata.tables["evidence_artifacts"]
            await self.session.execute(
                update(artifacts)
                .where(artifacts.c.tenant_id == self.tenant_id, artifacts.c.id == artifact_id)
                .values(
                    quarantine_reason=verification.reason,
                    version=artifacts.c.version + 1,
                    updated_at=occurred_at,
                )
            )
        await self._audit_outbox(
            artifact_id,
            "evidence.artifact.verified" if verification.ok else "evidence.artifact.quarantined",
            {"verified": verification.ok, "reason": verification.reason},
            occurred_at,
        )

    async def _record_verification_row(
        self,
        artifact_id: str,
        stored: StoredObjectVersion,
        verification: ObjectVerification,
        occurred_at: datetime,
    ) -> None:
        table = metadata.tables["evidence_verifications"]
        await self.session.execute(
            insert(table).values(
                id=f"evidence-verification-{uuid4().hex}",
                tenant_id=self.tenant_id,
                artifact_id=artifact_id,
                object_key=stored.object_key,
                object_version_id=stored.version_id,
                content_sha256=stored.content_sha256,
                provider_checksum=stored.provider_checksum,
                size_bytes=stored.size_bytes,
                verified=verification.ok,
                quarantine_reason=None if verification.ok else verification.reason,
                verified_at=occurred_at,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )

    async def _record_custody(self, artifact_id: str, event_type: str, attestation_hash: str, occurred_at: datetime) -> None:
        table = metadata.tables["evidence_custody_events"]
        await self.session.execute(
            insert(table).values(
                id=f"evidence-custody-{uuid4().hex}",
                tenant_id=self.tenant_id,
                artifact_id=artifact_id,
                event_type=event_type,
                actor_id=self.actor_user_id,
                attestation_hash=attestation_hash,
                details={"correlation_id": self.correlation_id},
                occurred_at=occurred_at,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )

    async def _audit_outbox(
        self,
        subject_id: str,
        event_type: str,
        details: dict[str, object],
        occurred_at: datetime,
        *,
        subject_type: str = "evidence_artifact",
    ) -> None:
        audit_id = f"audit-{uuid4().hex}"
        outbox_id = f"outbox-{uuid4().hex}"
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=audit_id,
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=event_type,
                subject_type=subject_type,
                subject_id=subject_id,
                correlation_id=self.correlation_id,
                details=details,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self.session.execute(
            insert(metadata.tables["outbox_events"]).values(
                id=outbox_id,
                tenant_id=self.tenant_id,
                event_type=event_type,
                aggregate_id=subject_id,
                payload={"subject_type": subject_type, "subject_id": subject_id, **details},
                published=False,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )

    async def _tenant_context(self) -> None:
        transaction = self.session.get_transaction()
        if transaction is not None and transaction is self._tenant_context_transaction:
            return
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )
        self._tenant_context_transaction = self.session.get_transaction()


def _attestation_hash(request: ArtifactWriteRequest, stored: StoredObjectVersion) -> str:
    canonical = json.dumps(
        {
            "artifact_id": request.artifact_id,
            "content_sha256": stored.content_sha256,
            "object_key": stored.object_key,
            "object_version_id": stored.version_id,
            "retention_mode": stored.retention_mode,
            "retain_until": stored.retain_until,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_hash(value: dict[str, object]) -> str:
    canonical = json.dumps(_json_safe(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _json_safe(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _public_artifact(row) -> dict[str, object]:
    return {
        "artifact_id": str(row["id"]),
        **{
            key: row[key]
            for key in (
                "tenant_id", "engagement_id", "job_id", "producer_id", "object_key", "object_version_id",
                "content_sha256", "provider_checksum", "size_bytes", "content_type", "artifact_class",
                "classification", "redaction_state", "retention_mode", "retain_until", "legal_hold",
                "kms_reference", "attestation_hash", "policy_reference", "quarantine_reason", "version",
            )
        },
    }
