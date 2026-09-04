"""PostgreSQL ownership for the canonical autonomous campaign application lifecycle."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from typing import Mapping
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.application_contracts import (
    ApplicationBindingConflict,
    ApplicationIdempotencyConflict,
    ApplicationNotFound,
    ApplicationRevisionConflict,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle,
    AutonomousCampaignMode,
    AutonomousCampaignMutationResultV1,
    CreateAutonomousCampaignIntentV1,
    RevokeAutonomousCampaignIntentV1,
    assert_lifecycle_transition,
)
from redagent_platform.persistence.models import metadata


_CREATE_OPERATION = "autonomous_campaign.application.create.v1"
_REVOKE_OPERATION = "autonomous_campaign.application.revoke.v1"


class PostgresAutonomousCampaignApplicationRepository:
    """Commit current state, append-only history, audit, and replay in one tenant transaction."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def create_intent(self, command: CreateAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1:
        if not isinstance(command, CreateAutonomousCampaignIntentV1):
            raise ValueError("create_intent_command_invalid")
        request_sha256 = _semantic_request_sha256(command)
        try:
            async with self._sessions() as session, session.begin():
                await _tenant_context(session, command.tenant_id)
                await _lock_idempotency(
                    session,
                    tenant_id=command.tenant_id,
                    operation=_CREATE_OPERATION,
                    idempotency_key=command.idempotency_key,
                )
                replay = await _read_replay(
                    session,
                    tenant_id=command.tenant_id,
                    operation=_CREATE_OPERATION,
                    idempotency_key=command.idempotency_key,
                    request_sha256=request_sha256,
                )
                if replay is not None:
                    return replay
                await _assert_canonical_bindings(
                    session,
                    tenant_id=command.tenant_id,
                    actor_user_id=command.actor_user_id,
                    engagement_id=command.engagement_id,
                    target_id=command.target_id,
                )
                state = AutonomousCampaignApplicationStateV1(
                    schema_version=command.schema_version,
                    tenant_id=command.tenant_id,
                    campaign_id=command.campaign_id,
                    engagement_id=command.engagement_id,
                    target_id=command.target_id,
                    created_by_user_id=command.actor_user_id,
                    intent_sha256=command.intent_sha256,
                    source_binding_sha256=command.source_binding_sha256,
                    mode=AutonomousCampaignMode.PLAN_ONLY,
                    lifecycle_state=AutonomousCampaignLifecycle.INTENT_CREATED,
                    aggregate_revision=1,
                    attention_reason=None,
                    created_at=command.occurred_at,
                    updated_at=command.occurred_at,
                )
                applications = metadata.tables["autonomous_campaign_applications"]
                await session.execute(
                    insert(applications).values(
                        id=state.campaign_id,
                        contract_version=state.schema_version,
                        engagement_id=state.engagement_id,
                        target_id=state.target_id,
                        created_by_user_id=state.created_by_user_id,
                        intent_sha256=state.intent_sha256,
                        source_binding_sha256=state.source_binding_sha256,
                        mode=state.mode.value,
                        lifecycle_state=state.lifecycle_state.value,
                        aggregate_revision=state.aggregate_revision,
                        attention_reason=None,
                        tenant_id=state.tenant_id,
                        version=1,
                        created_at=state.created_at,
                        updated_at=state.updated_at,
                    )
                )
                result = await _record_mutation(
                    session,
                    state=state,
                    operation=_CREATE_OPERATION,
                    idempotency_key=command.idempotency_key,
                    correlation_id=command.correlation_id,
                    actor_user_id=command.actor_user_id,
                    request_sha256=request_sha256,
                    event_type="autonomous_campaign.intent.created.v1",
                    previous_state=None,
                    event_payload={
                        "intent_sha256": command.intent_sha256,
                        "source_binding_sha256": command.source_binding_sha256,
                        "mode": AutonomousCampaignMode.PLAN_ONLY.value,
                    },
                    occurred_at=command.occurred_at,
                    response_status=201,
                )
            return result
        except IntegrityError as exc:
            raise ApplicationBindingConflict("autonomous_campaign_persistence_conflict") from exc

    async def read(self, *, tenant_id: str, campaign_id: str) -> AutonomousCampaignApplicationStateV1 | None:
        _identifier("tenant_id", tenant_id, 64)
        _identifier("campaign_id", campaign_id, 64)
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            row = await _read_row(session, tenant_id=tenant_id, campaign_id=campaign_id)
        return None if row is None else _state_from_row(row)

    async def revoke_intent(self, command: RevokeAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1:
        if not isinstance(command, RevokeAutonomousCampaignIntentV1):
            raise ValueError("revoke_intent_command_invalid")
        request_sha256 = _semantic_request_sha256(command)
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, command.tenant_id)
            await _lock_idempotency(
                session,
                tenant_id=command.tenant_id,
                operation=_REVOKE_OPERATION,
                idempotency_key=command.idempotency_key,
            )
            replay = await _read_replay(
                session,
                tenant_id=command.tenant_id,
                operation=_REVOKE_OPERATION,
                idempotency_key=command.idempotency_key,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            await _assert_actor_binding(
                session,
                tenant_id=command.tenant_id,
                actor_user_id=command.actor_user_id,
            )
            applications = metadata.tables["autonomous_campaign_applications"]
            row = (
                (
                    await session.execute(
                        select(applications)
                        .where(
                            applications.c.tenant_id == command.tenant_id,
                            applications.c.id == command.campaign_id,
                        )
                        .with_for_update()
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise ApplicationNotFound("autonomous_campaign_not_found")
            current = _state_from_row(row)
            if current.aggregate_revision != command.expected_revision:
                raise ApplicationRevisionConflict("application_revision_conflict")
            assert_lifecycle_transition(
                current.lifecycle_state,
                AutonomousCampaignLifecycle.REVOKED,
            )
            successor = AutonomousCampaignApplicationStateV1(
                schema_version=current.schema_version,
                tenant_id=current.tenant_id,
                campaign_id=current.campaign_id,
                engagement_id=current.engagement_id,
                target_id=current.target_id,
                created_by_user_id=current.created_by_user_id,
                intent_sha256=current.intent_sha256,
                source_binding_sha256=current.source_binding_sha256,
                mode=current.mode,
                lifecycle_state=AutonomousCampaignLifecycle.REVOKED,
                aggregate_revision=current.aggregate_revision + 1,
                attention_reason=None,
                created_at=current.created_at,
                updated_at=command.occurred_at,
            )
            updated = await session.execute(
                update(applications)
                .where(
                    applications.c.tenant_id == command.tenant_id,
                    applications.c.id == command.campaign_id,
                    applications.c.aggregate_revision == command.expected_revision,
                )
                .values(
                    lifecycle_state=successor.lifecycle_state.value,
                    aggregate_revision=successor.aggregate_revision,
                    version=applications.c.version + 1,
                    updated_at=successor.updated_at,
                )
            )
            if getattr(updated, "rowcount", None) != 1:
                raise ApplicationRevisionConflict("application_revision_conflict")
            return await _record_mutation(
                session,
                state=successor,
                operation=_REVOKE_OPERATION,
                idempotency_key=command.idempotency_key,
                correlation_id=command.correlation_id,
                actor_user_id=command.actor_user_id,
                request_sha256=request_sha256,
                event_type="autonomous_campaign.intent.revoked.v1",
                previous_state=current.lifecycle_state,
                event_payload={"reason_sha256": command.reason_sha256},
                occurred_at=command.occurred_at,
                response_status=202,
            )


async def _assert_canonical_bindings(
    session: AsyncSession,
    *,
    tenant_id: str,
    actor_user_id: str,
    engagement_id: str,
    target_id: str,
) -> None:
    await _assert_actor_binding(session, tenant_id=tenant_id, actor_user_id=actor_user_id)
    engagements = metadata.tables["engagements"]
    targets = metadata.tables["targets"]
    engagement = await session.scalar(
        select(engagements.c.id).where(
            engagements.c.tenant_id == tenant_id,
            engagements.c.id == engagement_id,
        )
    )
    target = await session.scalar(
        select(targets.c.id).where(
            targets.c.tenant_id == tenant_id,
            targets.c.id == target_id,
            targets.c.engagement_id == engagement_id,
        )
    )
    if engagement is None or target is None:
        raise ApplicationBindingConflict("application_binding_not_found")


async def _assert_actor_binding(session: AsyncSession, *, tenant_id: str, actor_user_id: str) -> None:
    users = metadata.tables["users"]
    actor = await session.scalar(
        select(users.c.id).where(
            users.c.tenant_id == tenant_id,
            users.c.id == actor_user_id,
        )
    )
    if actor is None:
        raise ApplicationBindingConflict("application_actor_not_found")


async def _record_mutation(
    session: AsyncSession,
    *,
    state: AutonomousCampaignApplicationStateV1,
    operation: str,
    idempotency_key: str,
    correlation_id: str,
    actor_user_id: str,
    request_sha256: str,
    event_type: str,
    previous_state: AutonomousCampaignLifecycle | None,
    event_payload: dict[str, object],
    occurred_at: datetime,
    response_status: int,
) -> AutonomousCampaignMutationResultV1:
    audit_id = f"audit-{uuid4().hex}"
    event_id = f"event-{uuid4().hex}"
    lifecycle_sha256 = _lifecycle_sha256(state)
    await session.execute(
        insert(metadata.tables["audit_events"]).values(
            id=audit_id,
            tenant_id=state.tenant_id,
            actor_user_id=actor_user_id,
            action=operation,
            subject_type="autonomous_campaign_application",
            subject_id=state.campaign_id,
            correlation_id=correlation_id,
            details={
                "aggregate_revision": state.aggregate_revision,
                "lifecycle_sha256": lifecycle_sha256,
            },
            version=1,
            created_at=occurred_at,
            updated_at=occurred_at,
        )
    )
    await session.execute(
        insert(metadata.tables["autonomous_campaign_application_events"]).values(
            id=event_id,
            application_id=state.campaign_id,
            audit_event_id=audit_id,
            event_sequence=state.aggregate_revision,
            event_type=event_type,
            previous_state=None if previous_state is None else previous_state.value,
            next_state=state.lifecycle_state.value,
            actor_user_id=actor_user_id,
            request_sha256=request_sha256,
            lifecycle_sha256=lifecycle_sha256,
            event_payload=event_payload,
            occurred_at=occurred_at,
            tenant_id=state.tenant_id,
            version=1,
            created_at=occurred_at,
            updated_at=occurred_at,
        )
    )
    result = AutonomousCampaignMutationResultV1(
        application=state,
        audit_id=audit_id,
        event_id=event_id,
        replayed=False,
    )
    await session.execute(
        insert(metadata.tables["idempotency_records"]).values(
            id=f"idem-{uuid4().hex}",
            tenant_id=state.tenant_id,
            operation=operation,
            idempotency_key=idempotency_key,
            request_hash=request_sha256,
            response_status=response_status,
            response_body=_result_payload(result),
            version=1,
            created_at=occurred_at,
            updated_at=occurred_at,
        )
    )
    return result


async def _read_replay(
    session: AsyncSession,
    *,
    tenant_id: str,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
) -> AutonomousCampaignMutationResultV1 | None:
    records = metadata.tables["idempotency_records"]
    row = (
        (
            await session.execute(
                select(records.c.request_hash, records.c.response_body).where(
                    records.c.tenant_id == tenant_id,
                    records.c.operation == operation,
                    records.c.idempotency_key == idempotency_key,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    if row["request_hash"] != request_sha256:
        raise ApplicationIdempotencyConflict("application_idempotency_mismatch")
    return _result_from_payload(row["response_body"], replayed=True)


async def _read_row(session: AsyncSession, *, tenant_id: str, campaign_id: str) -> RowMapping | None:
    applications = metadata.tables["autonomous_campaign_applications"]
    return (
        (
            await session.execute(
                select(applications).where(
                    applications.c.tenant_id == tenant_id,
                    applications.c.id == campaign_id,
                )
            )
        )
        .mappings()
        .one_or_none()
    )


async def _tenant_context(session: AsyncSession, tenant_id: str) -> None:
    _identifier("tenant_id", tenant_id, 64)
    # CRITICAL: tenant input remains a bound value; interpolation would bypass the RLS boundary.
    await session.execute(
        text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )


async def _lock_idempotency(
    session: AsyncSession,
    *,
    tenant_id: str,
    operation: str,
    idempotency_key: str,
) -> None:
    # CRITICAL: serialize before replay lookup so concurrent retries cannot both mutate lifecycle.
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": _advisory_lock_key(tenant_id, operation, idempotency_key)},
    )


def _semantic_request_sha256(
    command: CreateAutonomousCampaignIntentV1 | RevokeAutonomousCampaignIntentV1,
) -> str:
    if isinstance(command, CreateAutonomousCampaignIntentV1):
        payload = {
            "schema_version": command.schema_version,
            "tenant_id": command.tenant_id,
            "campaign_id": command.campaign_id,
            "engagement_id": command.engagement_id,
            "target_id": command.target_id,
            "actor_user_id": command.actor_user_id,
            "intent_sha256": command.intent_sha256,
            "source_binding_sha256": command.source_binding_sha256,
            "expected_revision": command.expected_revision,
        }
    else:
        payload = {
            "schema_version": command.schema_version,
            "tenant_id": command.tenant_id,
            "campaign_id": command.campaign_id,
            "actor_user_id": command.actor_user_id,
            "reason_sha256": command.reason_sha256,
            "expected_revision": command.expected_revision,
        }
    return _canonical_sha256(payload)


def _lifecycle_sha256(state: AutonomousCampaignApplicationStateV1) -> str:
    return _canonical_sha256(
        {
            "schema_version": state.schema_version,
            "tenant_id": state.tenant_id,
            "campaign_id": state.campaign_id,
            "engagement_id": state.engagement_id,
            "target_id": state.target_id,
            "created_by_user_id": state.created_by_user_id,
            "intent_sha256": state.intent_sha256,
            "source_binding_sha256": state.source_binding_sha256,
            "mode": state.mode.value,
            "lifecycle_state": state.lifecycle_state.value,
            "aggregate_revision": state.aggregate_revision,
            "attention_reason": state.attention_reason,
            "updated_at": state.updated_at.isoformat(),
        }
    )


def _result_payload(result: AutonomousCampaignMutationResultV1) -> dict[str, object]:
    state = result.application
    return {
        "application": {
            "schema_version": state.schema_version,
            "tenant_id": state.tenant_id,
            "campaign_id": state.campaign_id,
            "engagement_id": state.engagement_id,
            "target_id": state.target_id,
            "created_by_user_id": state.created_by_user_id,
            "intent_sha256": state.intent_sha256,
            "source_binding_sha256": state.source_binding_sha256,
            "mode": state.mode.value,
            "lifecycle_state": state.lifecycle_state.value,
            "aggregate_revision": state.aggregate_revision,
            "attention_reason": state.attention_reason,
            "created_at": state.created_at.isoformat(),
            "updated_at": state.updated_at.isoformat(),
        },
        "audit_id": result.audit_id,
        "event_id": result.event_id,
    }


def _result_from_payload(payload: object, *, replayed: bool) -> AutonomousCampaignMutationResultV1:
    if not isinstance(payload, dict) or not isinstance(payload.get("application"), dict):
        raise ValueError("application_replay_payload_invalid")
    application = payload["application"]
    return AutonomousCampaignMutationResultV1(
        application=AutonomousCampaignApplicationStateV1(
            schema_version=str(application["schema_version"]),
            tenant_id=str(application["tenant_id"]),
            campaign_id=str(application["campaign_id"]),
            engagement_id=str(application["engagement_id"]),
            target_id=str(application["target_id"]),
            created_by_user_id=str(application["created_by_user_id"]),
            intent_sha256=str(application["intent_sha256"]),
            source_binding_sha256=str(application["source_binding_sha256"]),
            mode=AutonomousCampaignMode(str(application["mode"])),
            lifecycle_state=AutonomousCampaignLifecycle(str(application["lifecycle_state"])),
            aggregate_revision=int(application["aggregate_revision"]),
            attention_reason=(
                None if application["attention_reason"] is None else str(application["attention_reason"])
            ),
            created_at=datetime.fromisoformat(str(application["created_at"])),
            updated_at=datetime.fromisoformat(str(application["updated_at"])),
        ),
        audit_id=str(payload["audit_id"]),
        event_id=str(payload["event_id"]),
        replayed=replayed,
    )


def _state_from_row(row: RowMapping) -> AutonomousCampaignApplicationStateV1:
    return AutonomousCampaignApplicationStateV1(
        schema_version=str(row["contract_version"]),
        tenant_id=str(row["tenant_id"]),
        campaign_id=str(row["id"]),
        engagement_id=str(row["engagement_id"]),
        target_id=str(row["target_id"]),
        created_by_user_id=str(row["created_by_user_id"]),
        intent_sha256=str(row["intent_sha256"]),
        source_binding_sha256=str(row["source_binding_sha256"]),
        mode=AutonomousCampaignMode(str(row["mode"])),
        lifecycle_state=AutonomousCampaignLifecycle(str(row["lifecycle_state"])),
        aggregate_revision=_stored_integer("aggregate_revision", row["aggregate_revision"]),
        attention_reason=None if row["attention_reason"] is None else str(row["attention_reason"]),
        created_at=_stored_datetime("created_at", row["created_at"]),
        updated_at=_stored_datetime("updated_at", row["updated_at"]),
    )


def _canonical_sha256(value: Mapping[str, object]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _advisory_lock_key(tenant_id: str, operation: str, idempotency_key: str) -> int:
    digest = hashlib.sha256(f"{tenant_id}\x1f{operation}\x1f{idempotency_key}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _identifier(name: str, value: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name}_invalid")


def _stored_integer(name: str, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"application_{name}_invalid")
    return value


def _stored_datetime(name: str, value: object) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"application_{name}_invalid")
    return value
