"""Read-only compat_055 JSONL compatibility input for the compat_093 relational system of record."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from sqlalchemy import insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.control_plane import (
    ControlPlaneRecordType,
    JsonlControlPlaneStore,
    PersistentControlRecord,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import IdempotencyConflict, MutationResult, RecordConflict


class LegacyImportError(ValueError):
    """Raised before commit when a legacy source cannot be imported safely."""


@dataclass(frozen=True)
class LegacyImportBundle:
    source_path: Path
    source_sha256: str
    records: tuple[PersistentControlRecord, ...]


def load_legacy_import_bundle(
    workspace: Path,
    source: Path,
    *,
    max_bytes: int = 16 * 1024 * 1024,
    max_records: int = 10_000,
) -> LegacyImportBundle:
    root = workspace.resolve()
    resolved = source.resolve()
    if not resolved.is_relative_to(root):
        raise LegacyImportError("legacy_source_outside_workspace")
    if not resolved.is_file():
        raise LegacyImportError("legacy_source_missing")
    if max_bytes <= 0 or max_records <= 0:
        raise LegacyImportError("legacy_import_limit_invalid")
    data = resolved.read_bytes()
    if len(data) > max_bytes:
        raise LegacyImportError("legacy_source_too_large")
    source_sha256 = hashlib.sha256(data).hexdigest()
    try:
        records = JsonlControlPlaneStore(resolved).read_all()
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise LegacyImportError("legacy_record_integrity_invalid") from exc
    if not records:
        raise LegacyImportError("legacy_source_empty")
    if len(records) > max_records:
        raise LegacyImportError("legacy_record_limit_exceeded")
    seen: set[tuple[ControlPlaneRecordType, str]] = set()
    for record in records:
        if not record.record_id.strip() or len(record.record_id) > 64:
            raise LegacyImportError("legacy_record_id_invalid")
        if not isinstance(record.payload, Mapping):
            raise LegacyImportError("legacy_payload_must_be_object")
        if len(json.dumps(record.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")) > 64 * 1024:
            raise LegacyImportError("legacy_payload_too_large")
        identity = (record.record_type, record.record_id)
        if identity in seen:
            raise LegacyImportError("legacy_record_duplicate")
        seen.add(identity)
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != source_sha256:
        raise LegacyImportError("legacy_source_changed")
    return LegacyImportBundle(resolved, source_sha256, records)


class LegacyJsonlImporter:
    """Map verified legacy metadata inside a caller-owned database transaction."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        self.session = session
        self.tenant_id = _required("tenant_id", tenant_id, 64)
        self.actor_user_id = _required("actor_user_id", actor_user_id, 64)
        self.correlation_id = _required("correlation_id", correlation_id, 100)

    async def import_bundle(
        self,
        bundle: LegacyImportBundle,
        *,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        _aware(occurred_at)
        key = _required("idempotency_key", idempotency_key, 200)
        self._verify_source(bundle)
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )
        operation = "legacy-jsonl:import"
        replay = await self._replay(operation, key, bundle.source_sha256)
        if replay is not None:
            return replay
        self._validate_tenant_ownership(bundle.records)

        counts = {
            "engagements": 0,
            "targets": 0,
            "roe_versions": 0,
            "approvals": 0,
            "legacy_audit_references": 0,
        }
        await self._ensure_tenant(occurred_at)
        grouped = {
            record_type: tuple(record for record in bundle.records if record.record_type is record_type)
            for record_type in ControlPlaneRecordType
        }
        for record in grouped[ControlPlaneRecordType.ENGAGEMENT]:
            await self._engagement(record)
            counts["engagements"] += 1
        for record in grouped[ControlPlaneRecordType.TARGET]:
            await self._target(record)
            counts["targets"] += 1
        for record in grouped[ControlPlaneRecordType.ROE_VERSION]:
            await self._roe(record, bundle.source_sha256)
            counts["roe_versions"] += 1
        for record in grouped[ControlPlaneRecordType.APPROVAL]:
            await self._approval(record)
            counts["approvals"] += 1
        for record_type in (
            ControlPlaneRecordType.REVOCATION,
            ControlPlaneRecordType.POLICY_DECISION,
            ControlPlaneRecordType.OPERATOR_CONFIRMATION,
        ):
            for record in grouped[record_type]:
                await self._legacy_audit_reference(record, bundle.source_sha256, occurred_at)
                counts["legacy_audit_references"] += 1

        audit_id = str(uuid4())
        outbox_id = str(uuid4())
        resource = {
            "tenant_id": self.tenant_id,
            "source_sha256": bundle.source_sha256,
            "record_count": len(bundle.records),
            "counts": counts,
            "version": 1,
        }
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=audit_id,
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=operation,
                subject_type="legacy_import",
                subject_id=bundle.source_sha256[:64],
                correlation_id=self.correlation_id,
                details={"source_sha256": bundle.source_sha256, "record_count": len(bundle.records), "counts": counts},
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self.session.execute(
            insert(metadata.tables["outbox_events"]).values(
                id=outbox_id,
                tenant_id=self.tenant_id,
                event_type="legacy.imported",
                aggregate_id=bundle.source_sha256[:64],
                payload={"source_sha256": bundle.source_sha256, "record_count": len(bundle.records)},
                published=False,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        response = {"resource": resource, "audit_id": audit_id, "outbox_id": outbox_id}
        await self.session.execute(
            insert(metadata.tables["idempotency_records"]).values(
                id=str(uuid4()),
                tenant_id=self.tenant_id,
                operation=operation,
                idempotency_key=key,
                request_hash=bundle.source_sha256,
                response_status=201,
                response_body=response,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        self._verify_source(bundle)
        return MutationResult(resource=resource, replayed=False, audit_id=audit_id, outbox_id=outbox_id)

    def _verify_source(self, bundle: LegacyImportBundle) -> None:
        try:
            current = hashlib.sha256(bundle.source_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise LegacyImportError("legacy_source_changed") from exc
        if current != bundle.source_sha256:
            raise LegacyImportError("legacy_source_changed")

    def _validate_tenant_ownership(self, records: tuple[PersistentControlRecord, ...]) -> None:
        tenant_owned = {
            ControlPlaneRecordType.ENGAGEMENT,
            ControlPlaneRecordType.TARGET,
            ControlPlaneRecordType.ROE_VERSION,
            ControlPlaneRecordType.POLICY_DECISION,
        }
        for record in records:
            if record.record_type in tenant_owned:
                organization_id = _required("organization_id", record.payload.get("organization_id"), 64)
                if organization_id != self.tenant_id:
                    raise LegacyImportError("legacy_tenant_mismatch")

    async def _ensure_tenant(self, occurred_at: datetime) -> None:
        table = metadata.tables["tenants"]
        existing = await self.session.scalar(select(table.c.id).where(table.c.id == self.tenant_id))
        if existing is None:
            await self.session.execute(
                insert(table).values(
                    id=self.tenant_id,
                    name=f"Legacy import {self.tenant_id}"[:200],
                    version=1,
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
            )

    async def _engagement(self, record: PersistentControlRecord) -> None:
        payload = record.payload
        record_id = _matching_id("engagement_id", payload, record.record_id)
        table = metadata.tables["engagements"]
        if await self.session.scalar(select(table.c.id).where(table.c.id == record_id)) is not None:
            raise RecordConflict("legacy_engagement_conflict")
        created_at = _timestamp("created_at", payload)
        await self.session.execute(
            insert(table).values(
                id=record_id,
                tenant_id=self.tenant_id,
                name=_required("name", payload.get("name"), 200),
                owner_user_id=_required("owner_user_id", payload.get("owner_user_id"), 64),
                version=1,
                created_at=created_at,
                updated_at=created_at,
            )
        )

    async def _target(self, record: PersistentControlRecord) -> None:
        payload = record.payload
        record_id = _matching_id("target_id", payload, record.record_id)
        engagement_id = _required("engagement_id", payload.get("engagement_id"), 64)
        engagements = metadata.tables["engagements"]
        if await self.session.scalar(
            select(engagements.c.id).where(
                engagements.c.tenant_id == self.tenant_id,
                engagements.c.id == engagement_id,
            )
        ) is None:
            raise LegacyImportError("legacy_engagement_dependency_missing")
        created_at = _timestamp("registered_at", payload)
        await self.session.execute(
            insert(metadata.tables["targets"]).values(
                id=record_id,
                tenant_id=self.tenant_id,
                engagement_id=engagement_id,
                target_type=_required("target_type", payload.get("target_type"), 32),
                normalized_value=_required("value", payload.get("value"), 500),
                version=1,
                created_at=created_at,
                updated_at=created_at,
            )
        )

    async def _roe(self, record: PersistentControlRecord, source_sha256: str) -> None:
        payload = record.payload
        record_id = _matching_id("roe_version_id", payload, record.record_id)
        engagement_id = _required("engagement_id", payload.get("engagement_id"), 64)
        created_at = _timestamp("created_at", payload)
        revision = payload.get("version")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise LegacyImportError("legacy_roe_revision_invalid")
        status = _required("status", payload.get("status"), 32)
        if status not in {"draft", "approved", "suspended", "revoked", "superseded"}:
            raise LegacyImportError("legacy_roe_status_invalid")
        await self.session.execute(
            insert(metadata.tables["roe_versions"]).values(
                id=record_id,
                tenant_id=self.tenant_id,
                engagement_id=engagement_id,
                revision=revision,
                status=status,
                document=dict(payload),
                version=1,
                created_at=created_at,
                updated_at=created_at,
            )
        )
        policy_id = "legacy-policy-" + hashlib.sha256(record_id.encode("utf-8")).hexdigest()[:32]
        await self.session.execute(
            insert(metadata.tables["policy_references"]).values(
                id=policy_id,
                tenant_id=self.tenant_id,
                roe_version_id=record_id,
                policy_name="legacy-jsonl-import",
                policy_version=source_sha256[:16],
                version=1,
                created_at=created_at,
                updated_at=created_at,
            )
        )

    async def _approval(self, record: PersistentControlRecord) -> None:
        payload = record.payload
        record_id = _matching_id("approval_id", payload, record.record_id)
        approved_at = _timestamp("approved_at", payload)
        await self.session.execute(
            insert(metadata.tables["approvals"]).values(
                id=record_id,
                tenant_id=self.tenant_id,
                roe_version_id=_required("roe_version_id", payload.get("roe_version_id"), 64),
                approved_by_user_id=_required("approved_by_user_id", payload.get("approved_by_user_id"), 64),
                version=1,
                created_at=approved_at,
                updated_at=approved_at,
            )
        )

    async def _legacy_audit_reference(
        self,
        record: PersistentControlRecord,
        source_sha256: str,
        occurred_at: datetime,
    ) -> None:
        audit_id = "legacy-" + hashlib.sha256(
            f"{source_sha256}:{record.record_type.value}:{record.record_id}".encode("utf-8")
        ).hexdigest()[:32]
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=audit_id,
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=f"legacy.{record.record_type.value}",
                subject_type="legacy_record_reference",
                subject_id=record.record_id,
                correlation_id=self.correlation_id,
                # IMPORTANT: retain integrity references, not potentially sensitive legacy payload bodies.
                details={
                    "source_sha256": source_sha256,
                    "legacy_record_hash": record.record_hash,
                    "legacy_record_type": record.record_type.value,
                },
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )

    async def _replay(self, operation: str, key: str, source_sha256: str) -> MutationResult | None:
        # CRITICAL: serialize import retries before any source rows are materialized.
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": _advisory_lock_key(self.tenant_id, operation, key)},
        )
        table = metadata.tables["idempotency_records"]
        row = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.operation == operation,
                    table.c.idempotency_key == key,
                )
            )
        ).mappings().one_or_none()
        if row is None:
            return None
        if row["request_hash"] != source_sha256:
            raise IdempotencyConflict("idempotency_key_request_mismatch")
        response = row["response_body"]
        return MutationResult(
            resource=dict(response["resource"]),
            replayed=True,
            audit_id=str(response["audit_id"]),
            outbox_id=str(response["outbox_id"]),
        )


def _required(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str):
        raise LegacyImportError(f"legacy_{name}_invalid")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise LegacyImportError(f"legacy_{name}_invalid")
    return normalized


def _matching_id(name: str, payload: Mapping[str, object], record_id: str) -> str:
    value = _required(name, payload.get(name), 64)
    if value != record_id:
        raise LegacyImportError("legacy_record_id_mismatch")
    return value


def _timestamp(name: str, payload: Mapping[str, object]) -> datetime:
    raw = _required(name, payload.get(name), 64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LegacyImportError(f"legacy_{name}_invalid") from exc
    _aware(parsed)
    return parsed


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LegacyImportError("legacy_timezone_required")


def _advisory_lock_key(tenant_id: str, operation: str, idempotency_key: str) -> int:
    digest = hashlib.sha256(f"{tenant_id}\x1f{operation}\x1f{idempotency_key}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)
