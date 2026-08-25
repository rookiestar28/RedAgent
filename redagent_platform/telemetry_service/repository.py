"""PostgreSQL-authoritative bounded telemetry delivery repository."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
import json
from uuid import uuid4

from sqlalchemy import case, insert, or_, select, text, update

from redagent_platform.persistence.models import metadata
from redagent_platform.telemetry_service.contracts import TelemetryEnvelope


class TelemetryRepositoryConflict(RuntimeError):
    """Stable telemetry repository conflict."""


class TelemetryRepository:
    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _identifier("tenant_id", tenant_id, 64)
        self.actor_user_id = _identifier("actor_user_id", actor_user_id, 64)
        self.correlation_id = _identifier("correlation_id", correlation_id, 100)

    async def enqueue(
        self,
        *,
        operation_id: str,
        envelope: TelemetryEnvelope,
        priority: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        operation = _identifier("operation_id", operation_id, 100)
        if envelope.tenant_id != self.tenant_id:
            raise TelemetryRepositoryConflict("telemetry_export_tenant_mismatch")
        if priority not in {"security", "operational", "debug"}:
            raise TelemetryRepositoryConflict("telemetry_export_priority_invalid")
        _aware(occurred_at)
        await self._context()
        await self._lock(f"telemetry-export:{operation}")
        table = metadata.tables["telemetry_export_operations"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.operation_id == operation,
            ))
        ).mappings().one_or_none()
        if existing is not None:
            if existing["envelope_hash"] != envelope.canonical_hash or existing["priority"] != priority:
                raise TelemetryRepositoryConflict("telemetry_export_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"telemetry-export-{uuid4().hex}", "tenant_id": self.tenant_id,
            "operation_id": operation, "event_id": envelope.event_id,
            "envelope_hash": envelope.canonical_hash, "envelope": _payload(envelope),
            "signal_kind": envelope.kind.value, "priority": priority, "export_state": "pending",
            "attempt_count": 0, "next_attempt_at": None, "claim_owner_id": None,
            "claim_expires_at": None, "last_reason_code": None, "occurred_at": occurred_at,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        return row

    async def claim_exports(
        self,
        *,
        worker_id: str,
        limit: int,
        lease_seconds: int,
        occurred_at: datetime,
    ) -> list[dict[str, object]]:
        worker = _identifier("worker_id", worker_id, 64)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise TelemetryRepositoryConflict("telemetry_claim_limit_invalid")
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 300:
            raise TelemetryRepositoryConflict("telemetry_claim_lease_invalid")
        _aware(occurred_at)
        await self._context()
        table = metadata.tables["telemetry_export_operations"]
        rows = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.export_state == "pending",
                or_(table.c.next_attempt_at.is_(None), table.c.next_attempt_at <= occurred_at),
            ).order_by(
                case((table.c.priority == "security", 0), (table.c.priority == "operational", 1), else_=2),
                table.c.occurred_at, table.c.id,
            ).with_for_update(skip_locked=True).limit(limit))
        ).mappings().all()
        claimed: list[dict[str, object]] = []
        expires = occurred_at + timedelta(seconds=lease_seconds)
        for row in rows:
            await self.session.execute(update(table).where(
                table.c.id == row["id"], table.c.export_state == "pending",
            ).values(
                export_state="delivering", claim_owner_id=worker, claim_expires_at=expires,
                version=table.c.version + 1, updated_at=occurred_at,
            ))
            claimed.append({
                **dict(row), "export_state": "delivering", "claim_owner_id": worker,
                "claim_expires_at": expires, "version": int(row["version"]) + 1,
                "updated_at": occurred_at,
            })
        return claimed

    async def record_delivery(
        self,
        *,
        operation_id: str,
        attempt_id: str,
        worker_id: str,
        destination_alias: str,
        outcome: str,
        reason_code: str,
        occurred_at: datetime,
        retry_at: datetime | None,
    ) -> dict[str, object]:
        operation = _identifier("operation_id", operation_id, 100)
        attempt = _identifier("attempt_id", attempt_id, 64)
        worker = _identifier("worker_id", worker_id, 64)
        destination = _identifier("destination_alias", destination_alias, 64)
        reason = _code("reason_code", reason_code)
        if outcome not in {"delivered", "retryable_failure", "permanent_failure"}:
            raise TelemetryRepositoryConflict("telemetry_delivery_outcome_invalid")
        _aware(occurred_at)
        if retry_at is not None:
            _aware(retry_at)
        if (outcome == "retryable_failure") != (retry_at is not None and retry_at > occurred_at):
            raise TelemetryRepositoryConflict("telemetry_delivery_retry_invalid")
        await self._context()
        await self._lock(f"telemetry-export:{operation}")
        exports = metadata.tables["telemetry_export_operations"]
        attempts = metadata.tables["telemetry_delivery_attempts"]
        existing_attempt = (
            await self.session.execute(select(attempts).where(
                attempts.c.tenant_id == self.tenant_id, attempts.c.attempt_id == attempt,
            ))
        ).mappings().one_or_none()
        row = (
            await self.session.execute(select(exports).where(
                exports.c.tenant_id == self.tenant_id, exports.c.operation_id == operation,
            ).with_for_update())
        ).mappings().one_or_none()
        if row is None:
            raise TelemetryRepositoryConflict("telemetry_export_not_found")
        if existing_attempt is not None:
            if (
                existing_attempt["export_operation_id"] != row["id"]
                or existing_attempt["attempt_state"] != outcome
                or existing_attempt["reason_code"] != reason
            ):
                raise TelemetryRepositoryConflict("telemetry_delivery_replay_mismatch")
            return dict(row)
        if row["export_state"] != "delivering" or row["claim_owner_id"] != worker:
            raise TelemetryRepositoryConflict("telemetry_delivery_claim_mismatch")
        attempt_number = int(row["attempt_count"]) + 1
        await self.session.execute(insert(attempts).values(
            id=f"telemetry-attempt-{uuid4().hex}", tenant_id=self.tenant_id,
            export_operation_id=row["id"], attempt_id=attempt, attempt_number=attempt_number,
            destination_alias=destination, attempt_state=outcome, reason_code=reason,
            started_at=occurred_at, completed_at=occurred_at,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        state = {
            "delivered": "delivered", "retryable_failure": "pending",
            "permanent_failure": "dead_letter",
        }[outcome]
        values = {
            "export_state": state, "attempt_count": attempt_number,
            "next_attempt_at": retry_at, "claim_owner_id": None, "claim_expires_at": None,
            "last_reason_code": reason, "version": int(row["version"]) + 1,
            "updated_at": occurred_at,
        }
        await self.session.execute(update(exports).where(exports.c.id == row["id"]).values(**values))
        if state == "dead_letter":
            await self.session.execute(insert(metadata.tables["telemetry_dead_letters"]).values(
                id=f"telemetry-dead-{uuid4().hex}", tenant_id=self.tenant_id,
                export_operation_id=row["id"], reason_code=reason,
                payload_hash=row["envelope_hash"], replay_id=None,
                dead_lettered_at=occurred_at, replayed_at=None,
                version=1, created_at=occurred_at, updated_at=occurred_at,
            ))
        return {**dict(row), **values}

    async def replay_dead_letter(
        self, *, operation_id: str, replay_id: str, occurred_at: datetime,
    ) -> dict[str, object]:
        operation = _identifier("operation_id", operation_id, 100)
        replay = _identifier("replay_id", replay_id, 64)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"telemetry-export:{operation}")
        exports = metadata.tables["telemetry_export_operations"]
        dead = metadata.tables["telemetry_dead_letters"]
        row = (
            await self.session.execute(select(exports).where(
                exports.c.tenant_id == self.tenant_id, exports.c.operation_id == operation,
            ).with_for_update())
        ).mappings().one_or_none()
        if row is None:
            raise TelemetryRepositoryConflict("telemetry_export_not_found")
        dead_row = (
            await self.session.execute(select(dead).where(
                dead.c.tenant_id == self.tenant_id, dead.c.export_operation_id == row["id"],
            ).with_for_update())
        ).mappings().one_or_none()
        if dead_row is None:
            raise TelemetryRepositoryConflict("telemetry_dead_letter_not_found")
        if dead_row["replayed_at"] is not None:
            if dead_row["replay_id"] != replay:
                raise TelemetryRepositoryConflict("telemetry_dead_letter_replay_mismatch")
            return dict(row)
        if row["export_state"] != "dead_letter":
            raise TelemetryRepositoryConflict("telemetry_dead_letter_state_invalid")
        await self.session.execute(update(dead).where(dead.c.id == dead_row["id"]).values(
            replay_id=replay, replayed_at=occurred_at,
            version=dead.c.version + 1, updated_at=occurred_at,
        ))
        values = {
            "export_state": "pending", "next_attempt_at": occurred_at,
            "last_reason_code": "dead_letter_replayed", "version": int(row["version"]) + 1,
            "updated_at": occurred_at,
        }
        await self.session.execute(update(exports).where(exports.c.id == row["id"]).values(**values))
        return {**dict(row), **values}

    async def reconcile_stale_claims(self, *, occurred_at: datetime) -> int:
        _aware(occurred_at)
        await self._context()
        table = metadata.tables["telemetry_export_operations"]
        result = await self.session.execute(update(table).where(
            table.c.tenant_id == self.tenant_id, table.c.export_state == "delivering",
            table.c.claim_expires_at < occurred_at,
        ).values(
            export_state="pending", claim_owner_id=None, claim_expires_at=None,
            next_attempt_at=occurred_at, last_reason_code="telemetry_claim_expired",
            version=table.c.version + 1, updated_at=occurred_at,
        ))
        return int(result.rowcount or 0)

    async def lookup_correlation(
        self, *, correlation_id: str, limit: int = 100, offset: int = 0,
    ) -> list[dict[str, object]]:
        correlation = _identifier("correlation_id", correlation_id, 100)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 501:
            raise TelemetryRepositoryConflict("telemetry_lookup_limit_invalid")
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 100000:
            raise TelemetryRepositoryConflict("telemetry_lookup_offset_invalid")
        await self._context()
        table = metadata.tables["telemetry_export_operations"]
        rows = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id,
            table.c.envelope["correlation_id"].as_string() == correlation,
        ).order_by(table.c.occurred_at.desc(), table.c.event_id).limit(limit).offset(offset))).mappings().all()
        return [dict(row) for row in rows]

    async def _context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id},
        )

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": scope})


def _payload(envelope: TelemetryEnvelope) -> dict[str, object]:
    payload = asdict(envelope)
    payload.update({
        "kind": envelope.kind.value, "service_name": envelope.service_name.value,
        "resource_type": envelope.resource_type.value, "outcome": envelope.outcome.value,
        "occurred_at": envelope.occurred_at.isoformat(),
    })
    # Defense in depth: the closed dataclass must remain JSON metadata only.
    json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return payload


def _identifier(field: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not all(
        char.isalnum() or char in "._:-" for char in value
    ):
        raise TelemetryRepositoryConflict(f"telemetry_{field}_invalid")
    return value


def _code(field: str, value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not all(
        char.islower() or char.isdigit() or char == "_" for char in value
    ):
        raise TelemetryRepositoryConflict(f"telemetry_{field}_invalid")
    return value


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise TelemetryRepositoryConflict("telemetry_time_invalid")
