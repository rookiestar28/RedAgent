"""compat_097 reserve/upload/verify/finalize evidence service."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

from redagent_platform.evidence_service.contracts import (
    ArtifactClass,
    ArtifactWriteRequest,
    DataClassification,
    EvidenceDerivativeRequest,
    EvidencePurpose,
    ObjectPutRequest,
    ObjectVerification,
    StoredObjectVersion,
    RetentionMode,
    deterministic_object_key,
)
from redagent_platform.evidence_service.backends import CapabilityError, ObjectConflict
from redagent_platform.evidence_service.repository import (
    EvidenceOperationPending,
    EvidenceRecordConflict,
    EvidenceRepository,
)
from redagent_platform.redaction import RedactionArtifactClass, sanitize_bytes


@dataclass(frozen=True, slots=True)
class EvidenceIngestResult:
    artifact: dict[str, object]
    stored_version: StoredObjectVersion
    replayed: bool


class EvidenceService:
    def __init__(self, session_factory: Any, backend: Any, policy_sdk: Any | None = None) -> None:
        self.session_factory = session_factory
        self.backend = backend
        self.policy_sdk = policy_sdk

    async def ingest(
        self,
        request: ArtifactWriteRequest,
        *,
        actor_user_id: str,
        correlation_id: str,
        occurred_at: datetime,
    ) -> EvidenceIngestResult:
        if self.policy_sdk is not None:
            async with self.session_factory() as session, session.begin():
                facts = await EvidenceRepository(
                    session, tenant_id=request.tenant_id,
                    actor_user_id=actor_user_id, correlation_id=correlation_id,
                ).current_policy_facts(request)
            await self.policy_sdk.enforce_evidence(
                tenant_id=request.tenant_id,
                subject_id=actor_user_id,
                action="evidence.write",
                artifact_id=request.artifact_id,
                artifact_class=request.artifact_class.value,
                classification=request.classification.value,
                legal_hold=request.legal_hold,
                policy_reference=request.policy_reference,
                roe_version_id=str(facts["roe_version_id"]),
                correlation_id=correlation_id,
                requested_at=occurred_at,
            )
        object_key = deterministic_object_key(request)
        async with self.session_factory() as session, session.begin():
            reservation = await EvidenceRepository(
                session,
                tenant_id=request.tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            ).reserve(request, object_key=object_key, occurred_at=occurred_at)
        if reservation.artifact is not None:
            stored = _stored_from_artifact(reservation.artifact)
            return EvidenceIngestResult(reservation.artifact, stored, True)
        if reservation.operation_state in {"quarantined", "failed"}:
            raise EvidenceRecordConflict("evidence_operation_quarantined")
        try:
            if reservation.replayed:
                stored = reconcile_pending_version(
                    self.backend.find_versions(object_key),
                    expected_content_hash=request.content_hash,
                )
            else:
                stored = self.backend.put(
                    ObjectPutRequest(
                        object_key=object_key,
                        content=request.content,
                        content_type=request.content_type,
                        content_sha256=request.content_hash,
                        retention_mode=request.retention_mode.value,
                        retain_until=request.retain_until.isoformat(),
                        legal_hold=request.legal_hold,
                        kms_reference=request.kms_reference,
                        operation_id=reservation.operation_id,
                    )
                )
        except EvidenceOperationPending:
            raise
        except (CapabilityError, ObjectConflict, EvidenceRecordConflict) as exc:
            await self._quarantine_operation(
                request,
                reservation.operation_id,
                reason=_stable_quarantine_reason(exc),
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                occurred_at=occurred_at,
            )
            raise
        verification = self.backend.verify_exact(stored)
        if not verification.ok:
            await self._quarantine_operation(
                request,
                reservation.operation_id,
                reason=_stable_quarantine_reason(verification.reason),
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                occurred_at=occurred_at,
            )
            raise EvidenceRecordConflict(f"evidence_upload_verification_failed:{verification.reason}")
        # IMPORTANT: exact object verification happens before database finalization;
        # the uploaded transition and immutable metadata then commit atomically in one statement.
        async with self.session_factory() as session, session.begin():
            repository = EvidenceRepository(
                session,
                tenant_id=request.tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            )
            artifact = await repository.finalize(
                reservation.operation_id,
                request,
                stored,
                verification,
                occurred_at=occurred_at,
                operation_prevalidated=reservation.operation_state == "reserved",
            )
        return EvidenceIngestResult(artifact, stored, reservation.replayed)

    async def ingest_batch(
        self,
        requests: Sequence[ArtifactWriteRequest],
        *,
        actor_user_id: str,
        correlation_prefix: str,
        occurred_at: datetime,
    ) -> tuple[EvidenceIngestResult, ...]:
        """Durably ingest a bounded same-tenant batch without per-item commits."""
        batch = tuple(requests)
        if not batch:
            return ()
        if len(batch) > 100:
            raise ValueError("evidence_ingest_batch_too_large")
        tenant_id = batch[0].tenant_id
        if any(request.tenant_id != tenant_id for request in batch):
            raise EvidenceRecordConflict("evidence_batch_tenant_mismatch")
        if self.policy_sdk is not None:
            # Policy enforcement remains item-specific; the ordinary path preserves its
            # exact facts and decision receipts until a policy batch contract exists.
            results = []
            for index, request in enumerate(batch):
                results.append(
                    await self.ingest(
                        request,
                        actor_user_id=actor_user_id,
                        correlation_id=f"{correlation_prefix}-{index}",
                        occurred_at=occurred_at,
                    )
                )
            return tuple(results)

        reservations = []
        async with self.session_factory() as session, session.begin():
            for index, request in enumerate(batch):
                reservations.append(
                    await EvidenceRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id=actor_user_id,
                        correlation_id=f"{correlation_prefix}-{index}",
                    ).reserve(
                        request,
                        object_key=deterministic_object_key(request),
                        occurred_at=occurred_at,
                    )
                )

        pending: list[tuple[int, ArtifactWriteRequest, Any, StoredObjectVersion, ObjectVerification]] = []
        results: list[EvidenceIngestResult | None] = [None] * len(batch)
        for index, (request, reservation) in enumerate(zip(batch, reservations, strict=True)):
            if reservation.artifact is not None:
                stored = _stored_from_artifact(reservation.artifact)
                results[index] = EvidenceIngestResult(reservation.artifact, stored, True)
                continue
            if reservation.operation_state in {"quarantined", "failed"}:
                raise EvidenceRecordConflict("evidence_operation_quarantined")
            try:
                if reservation.replayed:
                    stored = reconcile_pending_version(
                        self.backend.find_versions(reservation.object_key),
                        expected_content_hash=request.content_hash,
                    )
                else:
                    stored = self.backend.put(
                        ObjectPutRequest(
                            object_key=reservation.object_key,
                            content=request.content,
                            content_type=request.content_type,
                            content_sha256=request.content_hash,
                            retention_mode=request.retention_mode.value,
                            retain_until=request.retain_until.isoformat(),
                            legal_hold=request.legal_hold,
                            kms_reference=request.kms_reference,
                            operation_id=reservation.operation_id,
                        )
                    )
                verification = self.backend.verify_exact(stored)
                if not verification.ok:
                    raise EvidenceRecordConflict(
                        f"evidence_upload_verification_failed:{verification.reason}"
                    )
            except (CapabilityError, ObjectConflict, EvidenceRecordConflict) as exc:
                await self._quarantine_operation(
                    request,
                    reservation.operation_id,
                    reason=_stable_quarantine_reason(exc),
                    actor_user_id=actor_user_id,
                    correlation_id=f"{correlation_prefix}-{index}",
                    occurred_at=occurred_at,
                )
                raise
            pending.append((index, request, reservation, stored, verification))

        async with self.session_factory() as session, session.begin():
            for index, request, reservation, stored, verification in pending:
                artifact = await EvidenceRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id=actor_user_id,
                    correlation_id=f"{correlation_prefix}-{index}",
                ).finalize(
                    reservation.operation_id,
                    request,
                    stored,
                    verification,
                    occurred_at=occurred_at,
                    operation_prevalidated=reservation.operation_state == "reserved",
                )
                results[index] = EvidenceIngestResult(artifact, stored, reservation.replayed)
        if any(result is None for result in results):
            raise EvidenceRecordConflict("evidence_batch_finalize_incomplete")
        return tuple(result for result in results if result is not None)

    async def _quarantine_operation(
        self,
        request: ArtifactWriteRequest,
        operation_id: str,
        *,
        reason: str,
        actor_user_id: str,
        correlation_id: str,
        occurred_at: datetime,
    ) -> None:
        async with self.session_factory() as session, session.begin():
            await EvidenceRepository(
                session,
                tenant_id=request.tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            ).quarantine_operation(operation_id, reason=reason, occurred_at=occurred_at)

    async def get_artifact(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, object] | None:
        async with self.session_factory() as session, session.begin():
            return await EvidenceRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            ).get_artifact(artifact_id)

    async def list_artifacts(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
        limit: int,
        offset: int,
    ) -> tuple[dict[str, object], ...]:
        async with self.session_factory() as session, session.begin():
            return await EvidenceRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            ).list_artifacts(limit=limit, offset=offset)

    async def get_artifact_detail(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, object] | None:
        async with self.session_factory() as session, session.begin():
            return await EvidenceRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            ).get_artifact_detail(artifact_id)

    async def verify(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        actor_user_id: str,
        correlation_id: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> ObjectVerification:
        async with self.session_factory() as session, session.begin():
            repository = EvidenceRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            )
            operation = "evidence.verify"
            request = {"artifact_id": artifact_id}
            replay = await repository.mutation_replay(operation, idempotency_key, request)
            if replay is not None:
                return ObjectVerification(
                    str(replay["object_key"]),
                    str(replay["object_version_id"]),
                    bool(replay["verified"]),
                    str(replay["reason"]),
                )
            artifact = await repository.get_artifact(artifact_id)
            if artifact is None:
                raise EvidenceRecordConflict("evidence_artifact_not_found")
            stored = _stored_from_artifact(artifact)
            verification = self.backend.verify_exact(stored)
            await repository.record_verification(artifact, stored, verification, occurred_at=occurred_at)
            await repository.record_mutation_response(
                operation,
                idempotency_key,
                request,
                {
                    "object_key": verification.object_key,
                    "object_version_id": verification.version_id,
                    "verified": verification.ok,
                    "reason": verification.reason,
                },
                occurred_at=occurred_at,
            )
            return verification

    async def derive(
        self,
        *,
        tenant_id: str,
        request: EvidenceDerivativeRequest,
        actor_user_id: str,
        correlation_id: str,
        occurred_at: datetime,
    ) -> EvidenceIngestResult:
        source = await self.get_artifact(
            tenant_id=tenant_id,
            artifact_id=request.source_artifact_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
        )
        if source is None:
            raise EvidenceRecordConflict("evidence_artifact_not_found")
        if source["quarantine_reason"] is not None:
            raise EvidenceRecordConflict("quarantined_evidence_derivative_forbidden")
        ranks = {item.value: rank for rank, item in enumerate(ArtifactClass)}
        if ranks[request.artifact_class.value] <= ranks[str(source["artifact_class"])]:
            raise EvidenceRecordConflict("evidence_derivative_sensitivity_not_reduced")
        source_content = self.backend.get_exact(
            str(source["object_key"]),
            str(source["object_version_id"]),
        )
        redaction = sanitize_bytes(source_content, RedactionArtifactClass.EVIDENCE_ARTIFACT)
        if redaction.blocked_reason is not None:
            raise EvidenceRecordConflict("evidence_derivative_redaction_blocked")
        derived = ArtifactWriteRequest(
            tenant_id=tenant_id,
            artifact_id=request.artifact_id,
            engagement_id=str(source["engagement_id"]),
            job_id=str(source["job_id"]),
            producer_id=actor_user_id,
            content=redaction.sanitized_text.encode("utf-8"),
            content_type=str(source["content_type"]),
            artifact_class=request.artifact_class,
            classification=DataClassification(str(source["classification"])),
            redaction_state=request.artifact_class.value,
            retention_mode=RetentionMode(str(source["retention_mode"])),
            retain_until=source["retain_until"] if isinstance(source["retain_until"], datetime) else datetime.fromisoformat(str(source["retain_until"])),
            legal_hold=bool(source["legal_hold"]),
            kms_reference=str(source["kms_reference"]),
            policy_reference=str(source["policy_reference"]),
            idempotency_key=request.idempotency_key,
        )
        result = await self.ingest(
            derived,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            occurred_at=occurred_at,
        )
        async with self.session_factory() as session, session.begin():
            await EvidenceRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            ).register_derivative(request, occurred_at=occurred_at)
        return result

    async def select_for_purpose(
        self,
        *,
        tenant_id: str,
        source_artifact_id: str,
        purpose: EvidencePurpose,
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, object] | None:
        async with self.session_factory() as session, session.begin():
            return await EvidenceRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            ).select_for_purpose(source_artifact_id, purpose)

    async def place_legal_hold(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        expected_version: int,
        actor_user_id: str,
        correlation_id: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        async with self.session_factory() as session, session.begin():
            repository = EvidenceRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            )
            operation = "evidence.legal-hold"
            request = {"artifact_id": artifact_id, "expected_version": expected_version}
            replay = await repository.mutation_replay(operation, idempotency_key, request)
            if replay is not None:
                return _rehydrate_artifact(replay)
            artifact = await repository.get_artifact(artifact_id)
            if artifact is None:
                raise EvidenceRecordConflict("evidence_artifact_not_found")
            if int(artifact["version"]) != expected_version or bool(artifact["legal_hold"]):
                raise EvidenceRecordConflict("evidence_artifact_version_conflict")
            self.backend.place_legal_hold(
                str(artifact["object_key"]),
                str(artifact["object_version_id"]),
            )
            held = await repository.place_legal_hold(
                artifact_id,
                expected_version=expected_version,
                occurred_at=occurred_at,
            )
            await repository.record_mutation_response(
                operation,
                idempotency_key,
                request,
                held,
                occurred_at=occurred_at,
            )
            return held


def _stored_from_artifact(artifact: dict[str, object]) -> StoredObjectVersion:
    key = str(artifact["object_key"])
    return StoredObjectVersion(
        object_key=key,
        version_id=str(artifact["object_version_id"]),
        storage_name=hashlib.sha256(key.encode("utf-8")).hexdigest(),
        content_sha256=str(artifact["content_sha256"]),
        provider_checksum=str(artifact["provider_checksum"]),
        size_bytes=int(artifact["size_bytes"]),
        content_type=str(artifact["content_type"]),
        retention_mode=str(artifact["retention_mode"]),
        retain_until=artifact["retain_until"].isoformat() if isinstance(artifact["retain_until"], datetime) else str(artifact["retain_until"]),
        legal_hold=bool(artifact["legal_hold"]),
        kms_reference=str(artifact["kms_reference"]),
    )


def _rehydrate_artifact(artifact: dict[str, object]) -> dict[str, object]:
    restored = dict(artifact)
    retain_until = restored.get("retain_until")
    if isinstance(retain_until, str):
        restored["retain_until"] = datetime.fromisoformat(retain_until)
    return restored


def reconcile_pending_version(
    inventory: tuple[StoredObjectVersion, ...],
    *,
    expected_content_hash: str,
) -> StoredObjectVersion:
    # CRITICAL: never ignore an extra or mismatched immutable version during partial-failure recovery.
    if not inventory:
        raise EvidenceOperationPending("evidence_operation_pending_no_object")
    if len(inventory) != 1 or inventory[0].content_sha256 != expected_content_hash:
        raise EvidenceRecordConflict("evidence_pending_operation_requires_reconciliation")
    return inventory[0]


def _stable_quarantine_reason(value: object) -> str:
    reason = str(value)
    if not reason or len(reason) > 100 or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_:.-" for character in reason):
        return "evidence_operation_failed"
    return reason
