from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.contracts import (
    ArtifactClass,
    ArtifactWriteRequest,
    DataClassification,
    EvidenceDerivativeRequest,
    EvidencePurpose,
    ObjectPutRequest,
    RetentionMode,
    deterministic_object_key,
)
from redagent_platform.evidence_service.repository import (
    EvidenceIdempotencyConflict,
    EvidenceOperationPending,
    EvidenceRecordConflict,
    EvidenceRepository,
)
from redagent_platform.evidence_service.service import EvidenceService
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.policy_service.boundaries import PolicyBoundarySDK
from redagent_platform.policy_service.enforcement import PolicyBoundaryEnforcer
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from redagent_platform.policy_service.repository import TransactionalPolicyDecisionRecorder


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 16, 0, tzinfo=timezone.utc)


def test_reserve_upload_verify_finalize_replay_tamper_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex
    tenant = f"tenant-evidence-{suffix}"
    other_tenant = f"tenant-evidence-other-{suffix}"
    actor = f"producer-{suffix}"
    engagement = f"eng-evidence-{suffix}"
    roe = f"roe-evidence-{suffix}"
    job = f"job-evidence-{suffix}"
    artifact = f"artifact-{suffix}"
    tmp_path = ROOT / ".tmp" / "r097-evidence-integration" / suffix
    backend = LocalAppendOnlyBackend(tmp_path, profile="synthetic-local")
    try:
        await _bootstrap(sessions, tenant, actor, engagement, roe, job, suffix)
        policy = PolicyBoundarySDK(
            PolicyBoundaryEnforcer(
                DeterministicFakePolicyProvider(revision="synthetic-r099-v1"),
                TransactionalPolicyDecisionRecorder(sessions),
            ),
            required_revision="synthetic-r099-v1",
        )
        service = EvidenceService(sessions, backend, policy)
        request = ArtifactWriteRequest(
            tenant_id=tenant,
            artifact_id=artifact,
            engagement_id=engagement,
            job_id=job,
            producer_id=actor,
            content=b"synthetic sanitized persistent evidence\n",
            content_type="text/plain",
            artifact_class=ArtifactClass.REDACTED,
            classification=DataClassification.CONFIDENTIAL,
            redaction_state="redacted",
            retention_mode=RetentionMode.GOVERNANCE,
            retain_until=NOW + timedelta(days=30),
            legal_hold=False,
            kms_reference="kms:local:fixture",
            policy_reference="policy:compat_097:1",
            idempotency_key=f"idempotency-{suffix}",
        )
        first = await service.ingest(request, actor_user_id=actor, correlation_id=f"corr-{suffix}", occurred_at=NOW)
        replay = await service.ingest(request, actor_user_id=actor, correlation_id=f"corr-replay-{suffix}", occurred_at=NOW)
        assert first.artifact == replay.artifact and first.replayed is False and replay.replayed is True
        assert first.artifact["object_version_id"]
        assert first.artifact["content_sha256"] == request.content_hash
        assert first.artifact["quarantine_reason"] is None

        batch_service = EvidenceService(sessions, backend)
        batch_requests = tuple(
            ArtifactWriteRequest(**{
                **{name: getattr(request, name) for name in request.__slots__ if name != "content_hash"},
                "artifact_id": f"artifact-batch-{index}-{suffix}",
                "idempotency_key": f"idempotency-batch-{index}-{suffix}",
                "content": f"synthetic batch evidence {index}\n".encode(),
            })
            for index in range(3)
        )
        batch_results = await batch_service.ingest_batch(
            batch_requests,
            actor_user_id=actor,
            correlation_prefix=f"corr-batch-{suffix}",
            occurred_at=NOW,
        )
        assert tuple(result.artifact["artifact_id"] for result in batch_results) == tuple(
            item.artifact_id for item in batch_requests
        )
        assert all(not result.replayed for result in batch_results)
        batch_replay = await batch_service.ingest_batch(
            batch_requests,
            actor_user_id=actor,
            correlation_prefix=f"corr-batch-replay-{suffix}",
            occurred_at=NOW,
        )
        assert all(result.replayed for result in batch_replay)
        mismatched = ArtifactWriteRequest(**{
            **{name: getattr(batch_requests[0], name) for name in batch_requests[0].__slots__ if name != "content_hash"},
            "tenant_id": other_tenant,
            "artifact_id": f"artifact-batch-other-{suffix}",
            "idempotency_key": f"idempotency-batch-other-{suffix}",
        })
        with pytest.raises(EvidenceRecordConflict, match="evidence_batch_tenant_mismatch"):
            await batch_service.ingest_batch(
                (batch_requests[0], mismatched),
                actor_user_id=actor,
                correlation_prefix=f"corr-batch-mismatch-{suffix}",
                occurred_at=NOW,
            )

        pending = ArtifactWriteRequest(**{
            **{name: getattr(request, name) for name in request.__slots__ if name != "content_hash"},
            "artifact_id": f"artifact-pending-{suffix}",
            "idempotency_key": f"idempotency-pending-{suffix}",
            "content": b"synthetic uploaded-before-database-finalize\n",
        })
        pending_key = deterministic_object_key(pending)
        async with sessions() as session, session.begin():
            reservation = await EvidenceRepository(
                session,
                tenant_id=tenant,
                actor_user_id=actor,
                correlation_id=f"corr-pending-reserve-{suffix}",
            ).reserve(pending, object_key=pending_key, occurred_at=NOW)
        with pytest.raises(EvidenceOperationPending, match="evidence_operation_pending_no_object"):
            await service.ingest(
                pending,
                actor_user_id=actor,
                correlation_id=f"corr-pending-before-object-{suffix}",
                occurred_at=NOW,
            )
        async with sessions() as session, session.begin():
            operations = metadata.tables["evidence_operations"]
            still_reserved = (
                await session.execute(select(operations).where(operations.c.id == reservation.operation_id))
            ).mappings().one()
            assert still_reserved["operation_state"] == "reserved"
            assert still_reserved["quarantine_reason"] is None
        backend.put(
            ObjectPutRequest(
                object_key=pending_key,
                content=pending.content,
                content_type=pending.content_type,
                content_sha256=pending.content_hash,
                retention_mode=pending.retention_mode.value,
                retain_until=pending.retain_until.isoformat(),
                legal_hold=pending.legal_hold,
                kms_reference=pending.kms_reference,
                operation_id=reservation.operation_id,
            )
        )
        resumed, concurrent_replay = await asyncio.gather(
            service.ingest(
                pending,
                actor_user_id=actor,
                correlation_id=f"corr-pending-resume-a-{suffix}",
                occurred_at=NOW + timedelta(milliseconds=1),
            ),
            service.ingest(
                pending,
                actor_user_id=actor,
                correlation_id=f"corr-pending-resume-b-{suffix}",
                occurred_at=NOW + timedelta(milliseconds=1),
            ),
        )
        assert resumed.replayed is True
        assert concurrent_replay.replayed is True
        assert resumed.artifact == concurrent_replay.artifact
        assert resumed.artifact["artifact_id"] == pending.artifact_id
        assert resumed.artifact["content_sha256"] == pending.content_hash

        failed = ArtifactWriteRequest(**{
            **{name: getattr(request, name) for name in request.__slots__ if name != "content_hash"},
            "artifact_id": f"artifact-failed-{suffix}",
            "idempotency_key": f"idempotency-failed-{suffix}",
            "content": b"synthetic tampered-before-finalize\n",
        })
        failed_key = deterministic_object_key(failed)
        async with sessions() as session, session.begin():
            failed_reservation = await EvidenceRepository(
                session,
                tenant_id=tenant,
                actor_user_id=actor,
                correlation_id=f"corr-failed-reserve-{suffix}",
            ).reserve(failed, object_key=failed_key, occurred_at=NOW)
        failed_stored = backend.put(ObjectPutRequest(
            object_key=failed_key,
            content=failed.content,
            content_type=failed.content_type,
            content_sha256=failed.content_hash,
            retention_mode=failed.retention_mode.value,
            retain_until=failed.retain_until.isoformat(),
            legal_hold=failed.legal_hold,
            kms_reference=failed.kms_reference,
            operation_id=failed_reservation.operation_id,
        ))
        (tmp_path / "objects" / failed_stored.storage_name).write_bytes(b"tampered-before-finalize")
        with pytest.raises(EvidenceRecordConflict, match="evidence_upload_verification_failed"):
            await service.ingest(
                failed,
                actor_user_id=actor,
                correlation_id=f"corr-failed-reconcile-{suffix}",
                occurred_at=NOW + timedelta(milliseconds=2),
            )
        async with sessions() as session, session.begin():
            operations = metadata.tables["evidence_operations"]
            failed_operation = (
                await session.execute(select(operations).where(operations.c.id == failed_reservation.operation_id))
            ).mappings().one()
            assert failed_operation["operation_state"] == "quarantined"
            assert failed_operation["quarantine_reason"] == "content_hash_mismatch"
            quarantine_audit = (
                await session.execute(select(metadata.tables["audit_events"]).where(
                    metadata.tables["audit_events"].c.subject_type == "evidence_operation",
                    metadata.tables["audit_events"].c.subject_id == failed_reservation.operation_id,
                ))
            ).mappings().one()
            assert quarantine_audit["action"] == "evidence.operation.quarantined"
            quarantine_outbox = (
                await session.execute(select(metadata.tables["outbox_events"]).where(
                    metadata.tables["outbox_events"].c.aggregate_id == failed_reservation.operation_id,
                ))
            ).mappings().one()
            assert quarantine_outbox["payload"]["artifact_id"] == failed.artifact_id

        raw_canary = f"canary-{suffix}"
        raw_request = ArtifactWriteRequest(**{
            **{name: getattr(request, name) for name in request.__slots__ if name != "content_hash"},
            "artifact_id": f"artifact-raw-{suffix}",
            "idempotency_key": f"idempotency-raw-{suffix}",
            "content": f"Authorization: Bearer {raw_canary}\n".encode("utf-8"),
            "artifact_class": ArtifactClass.RAW,
            "classification": DataClassification.RESTRICTED,
            "redaction_state": "raw",
        })
        await service.ingest(
            raw_request,
            actor_user_id=actor,
            correlation_id=f"corr-raw-{suffix}",
            occurred_at=NOW + timedelta(milliseconds=2),
        )
        redacted_raw = await service.derive(
            tenant_id=tenant,
            request=EvidenceDerivativeRequest(
                source_artifact_id=raw_request.artifact_id,
                artifact_id=f"artifact-redacted-{suffix}",
                artifact_class=ArtifactClass.REDACTED,
                transform_name="central-redaction",
                transform_version="1",
                quality_approved=True,
                idempotency_key=f"derive-redacted-{suffix}",
            ),
            actor_user_id=actor,
            correlation_id=f"corr-redact-raw-{suffix}",
            occurred_at=NOW + timedelta(milliseconds=3),
        )
        redacted_bytes = backend.get_exact(
            redacted_raw.stored_version.object_key,
            redacted_raw.stored_version.version_id,
        )
        assert redacted_bytes == b"Authorization: [redacted]\n"
        assert raw_canary.encode("utf-8") not in redacted_bytes

        report = await service.derive(
            tenant_id=tenant,
            request=EvidenceDerivativeRequest(
                source_artifact_id=artifact,
                artifact_id=f"artifact-report-{suffix}",
                artifact_class=ArtifactClass.REPORT_SAFE,
                transform_name="central-redaction",
                transform_version="1",
                quality_approved=True,
                idempotency_key=f"derive-report-{suffix}",
            ),
            actor_user_id=actor,
            correlation_id=f"corr-derive-report-{suffix}",
            occurred_at=NOW + timedelta(milliseconds=2),
        )
        exported = await service.derive(
            tenant_id=tenant,
            request=EvidenceDerivativeRequest(
                source_artifact_id=artifact,
                artifact_id=f"artifact-export-{suffix}",
                artifact_class=ArtifactClass.EXPORT_SAFE,
                transform_name="central-redaction",
                transform_version="1",
                quality_approved=True,
                idempotency_key=f"derive-export-{suffix}",
            ),
            actor_user_id=actor,
            correlation_id=f"corr-derive-export-{suffix}",
            occurred_at=NOW + timedelta(milliseconds=3),
        )
        assert report.artifact["artifact_class"] == "report_safe"
        assert exported.artifact["artifact_class"] == "export_safe"
        report_replay = await service.derive(
            tenant_id=tenant,
            request=EvidenceDerivativeRequest(
                source_artifact_id=artifact,
                artifact_id=f"artifact-report-{suffix}",
                artifact_class=ArtifactClass.REPORT_SAFE,
                transform_name="central-redaction",
                transform_version="1",
                quality_approved=True,
                idempotency_key=f"derive-report-{suffix}",
            ),
            actor_user_id=actor,
            correlation_id=f"corr-derive-report-replay-{suffix}",
            occurred_at=NOW + timedelta(milliseconds=4),
        )
        assert report_replay.replayed is True and report_replay.artifact == report.artifact
        selected = await service.select_for_purpose(
            tenant_id=tenant,
            source_artifact_id=artifact,
            purpose=EvidencePurpose.REPORT,
            actor_user_id=actor,
            correlation_id=f"corr-select-{suffix}",
        )
        assert selected is not None and selected["artifact_id"] == exported.artifact["artifact_id"]

        held = await service.place_legal_hold(
            tenant_id=tenant,
            artifact_id=artifact,
            expected_version=int(first.artifact["version"]),
            actor_user_id=actor,
            correlation_id=f"corr-hold-{suffix}",
            idempotency_key=f"hold-{suffix}",
            occurred_at=NOW + timedelta(milliseconds=4),
        )
        assert held["legal_hold"] is True and held["version"] == int(first.artifact["version"]) + 1
        held_replay = await service.place_legal_hold(
            tenant_id=tenant,
            artifact_id=artifact,
            expected_version=int(first.artifact["version"]),
            actor_user_id=actor,
            correlation_id=f"corr-hold-replay-{suffix}",
            idempotency_key=f"hold-{suffix}",
            occurred_at=NOW + timedelta(milliseconds=5),
        )
        assert held_replay == held
        with pytest.raises(EvidenceRecordConflict, match="evidence_artifact_version_conflict"):
            await service.place_legal_hold(
                tenant_id=tenant,
                artifact_id=artifact,
                expected_version=int(first.artifact["version"]),
                actor_user_id=actor,
                correlation_id=f"corr-hold-stale-{suffix}",
                idempotency_key=f"hold-stale-{suffix}",
                occurred_at=NOW + timedelta(milliseconds=5),
            )

        async with sessions() as session, session.begin():
            derivatives = metadata.tables["evidence_derivatives"]
            rows = (
                await session.execute(select(derivatives).where(derivatives.c.source_artifact_id == artifact))
            ).mappings().all()
            assert len(rows) == 2
            assert {row["transform_config_hash"] for row in rows} == {
                EvidenceDerivativeRequest(
                    source_artifact_id=artifact,
                    artifact_id=f"artifact-{kind}-{suffix}",
                    artifact_class=artifact_class,
                    transform_name="central-redaction",
                    transform_version="1",
                    quality_approved=True,
                    idempotency_key=f"derive-{kind}-{suffix}",
                ).transform_config_hash
                for kind, artifact_class in (("report", ArtifactClass.REPORT_SAFE), ("export", ArtifactClass.EXPORT_SAFE))
            }

        changed = ArtifactWriteRequest(**{
            **{name: getattr(request, name) for name in request.__slots__ if name != "content_hash"},
            "content": b"different bounded evidence",
        })
        with pytest.raises(EvidenceIdempotencyConflict, match="evidence_idempotency_mismatch"):
            await service.ingest(changed, actor_user_id=actor, correlation_id=f"corr-mismatch-{suffix}", occurred_at=NOW)

        stored = first.stored_version
        (tmp_path / "objects" / stored.storage_name).write_bytes(b"tampered")
        verification = await service.verify(
            tenant_id=tenant,
            artifact_id=artifact,
            actor_user_id=actor,
            correlation_id=f"corr-verify-{suffix}",
            idempotency_key=f"verify-{suffix}",
            occurred_at=NOW + timedelta(seconds=1),
        )
        assert verification.ok is False and verification.reason == "content_hash_mismatch"
        verification_replay = await service.verify(
            tenant_id=tenant,
            artifact_id=artifact,
            actor_user_id=actor,
            correlation_id=f"corr-verify-replay-{suffix}",
            idempotency_key=f"verify-{suffix}",
            occurred_at=NOW + timedelta(seconds=2),
        )
        assert verification_replay == verification

        async with sessions() as session, session.begin():
            artifacts = metadata.tables["evidence_artifacts"]
            custody = metadata.tables["evidence_custody_events"]
            audits = metadata.tables["audit_events"]
            outbox = metadata.tables["outbox_events"]
            verifications = metadata.tables["evidence_verifications"]
            artifact_row = (await session.execute(select(artifacts).where(artifacts.c.id == artifact))).mappings().one()
            assert artifact_row["quarantine_reason"] == "content_hash_mismatch"
            assert await session.scalar(select(func.count()).select_from(custody).where(custody.c.artifact_id == artifact)) >= 3
            assert await session.scalar(select(func.count()).select_from(audits).where(audits.c.subject_id == artifact)) >= 2
            assert await session.scalar(select(func.count()).select_from(outbox).where(outbox.c.aggregate_id == artifact)) >= 2
            assert await session.scalar(select(func.count()).select_from(verifications).where(verifications.c.artifact_id == artifact)) == 2

        other = await service.get_artifact(
            tenant_id=other_tenant,
            artifact_id=artifact,
            actor_user_id="other-user",
            correlation_id=f"corr-other-{suffix}",
        )
        assert other is None
    finally:
        await engine.dispose()


async def _bootstrap(sessions, tenant: str, actor: str, engagement: str, roe: str, job: str, suffix: str) -> None:
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}")
        await repo.bootstrap_tenant(name="Evidence Tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
        await repo.create_engagement(
            engagement_id=engagement, name="Evidence synthetic", owner_user_id=actor,
            idempotency_key=f"eng-{suffix}", occurred_at=NOW,
        )
        created_roe = await repo.create_roe_version(
            roe_version_id=roe, engagement_id=engagement, revision=1,
            document={"active_testing": False}, policy_reference_id=f"policy-{suffix}",
            policy_name="r097-policy", policy_version="1", idempotency_key=f"roe-{suffix}", occurred_at=NOW,
        )
        await repo.approve_roe_version(
            roe_version_id=roe, approval_id=f"approval-{suffix}",
            expected_version=int(created_roe.resource["version"]), idempotency_key=f"approve-{suffix}", occurred_at=NOW,
        )
        await repo.create_job(
            job_id=job, engagement_id=engagement, roe_version_id=roe,
            request={
                "capability": "synthetic-noop", "approval_timeout_seconds": 3600,
                "max_activity_attempts": 3, "budget_reference": "budget:compat_097:fixture",
            },
            workflow_id=f"workflow-{suffix}", policy_reference="policy:compat_097:1", campaign_id=None,
            idempotency_key=f"job-{suffix}", occurred_at=NOW,
        )
