from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.telemetry_service.contracts import (
    TELEMETRY_SCHEMA, ResourceType, ServiceName, SignalKind, SignalOutcome, TelemetryEnvelope,
)
from redagent_platform.telemetry_service.repository import TelemetryRepository, TelemetryRepositoryConflict


ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 11, 4, 0, tzinfo=timezone.utc)


def test_durable_export_retry_dead_letter_replay_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r102-{suffix}"
    actor = f"operator-{suffix}"
    other_tenant = f"tenant-other-{suffix}"
    try:
        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}",
            )
            await control.bootstrap_tenant(name="compat_102 Tenant", occurred_at=NOW)
            await control.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
            other = ControlPlaneRepository(
                session, tenant_id=other_tenant, actor_user_id=actor, correlation_id=f"bootstrap-other-{suffix}",
            )
            await other.bootstrap_tenant(name="Other Tenant", occurred_at=NOW)

        envelope = _envelope(tenant=tenant, suffix=suffix)
        async with sessions() as session, session.begin():
            repository = TelemetryRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"enqueue-{suffix}",
            )
            created = await repository.enqueue(
                operation_id=f"export-{suffix}", envelope=envelope, priority="security", occurred_at=NOW,
            )
            replayed = await repository.enqueue(
                operation_id=f"export-{suffix}", envelope=envelope, priority="security", occurred_at=NOW,
            )
            assert replayed["id"] == created["id"]
            with pytest.raises(TelemetryRepositoryConflict, match="telemetry_export_replay_mismatch"):
                await repository.enqueue(
                    operation_id=f"export-{suffix}",
                    envelope=replace(envelope, reason_code="mutated_reason"),
                    priority="security", occurred_at=NOW,
                )

        async with sessions() as session, session.begin():
            first = await TelemetryRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"claim-1-{suffix}",
            ).claim_exports(worker_id="worker-1", limit=10, lease_seconds=30, occurred_at=NOW)
            second = await TelemetryRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"claim-2-{suffix}",
            ).claim_exports(worker_id="worker-2", limit=10, lease_seconds=30, occurred_at=NOW)
            assert len(first) == 1 and not second

        async with sessions() as session, session.begin():
            repository = TelemetryRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"retry-{suffix}",
            )
            retried = await repository.record_delivery(
                operation_id=f"export-{suffix}", attempt_id=f"attempt-1-{suffix}", worker_id="worker-1",
                destination_alias="local-siem", outcome="retryable_failure",
                reason_code="siem_http_503", occurred_at=NOW + timedelta(seconds=1),
                retry_at=NOW + timedelta(seconds=10),
            )
            assert retried["export_state"] == "pending"
            assert not await repository.claim_exports(
                worker_id="worker-2", limit=10, lease_seconds=30,
                occurred_at=NOW + timedelta(seconds=9),
            )
            claimed = await repository.claim_exports(
                worker_id="worker-2", limit=10, lease_seconds=30,
                occurred_at=NOW + timedelta(seconds=10),
            )
            assert len(claimed) == 1

        async with sessions() as session, session.begin():
            repository = TelemetryRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"dead-{suffix}",
            )
            dead = await repository.record_delivery(
                operation_id=f"export-{suffix}", attempt_id=f"attempt-2-{suffix}", worker_id="worker-2",
                destination_alias="local-siem", outcome="permanent_failure",
                reason_code="ocsf_schema_rejected", occurred_at=NOW + timedelta(seconds=11), retry_at=None,
            )
            assert dead["export_state"] == "dead_letter"
            replay = await repository.replay_dead_letter(
                operation_id=f"export-{suffix}", replay_id=f"replay-{suffix}",
                occurred_at=NOW + timedelta(seconds=12),
            )
            assert replay["export_state"] == "pending"
            assert len(await repository.claim_exports(
                worker_id="worker-3", limit=10, lease_seconds=30,
                occurred_at=NOW + timedelta(seconds=12),
            )) == 1
            delivered = await repository.record_delivery(
                operation_id=f"export-{suffix}", attempt_id=f"attempt-3-{suffix}", worker_id="worker-3",
                destination_alias="local-siem", outcome="delivered", reason_code="siem_accepted",
                occurred_at=NOW + timedelta(seconds=13), retry_at=None,
            )
            assert delivered["export_state"] == "delivered"

        stale_operation = f"stale-export-{suffix}"
        async with sessions() as session, session.begin():
            repository = TelemetryRepository(
                session, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"stale-enqueue-{suffix}",
            )
            await repository.enqueue(
                operation_id=stale_operation,
                envelope=replace(
                    envelope, event_id=f"stale-event-{suffix}",
                    resource_id=f"stale-export-{suffix}",
                ),
                priority="operational", occurred_at=NOW + timedelta(seconds=20),
            )
            assert len(await repository.claim_exports(
                worker_id="stale-worker", limit=1, lease_seconds=30,
                occurred_at=NOW + timedelta(seconds=20),
            )) == 1

        # Simulate a worker restart after the durable lease expires.
        async with sessions() as session, session.begin():
            repository = TelemetryRepository(
                session, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"stale-reconcile-{suffix}",
            )
            assert await repository.reconcile_stale_claims(
                occurred_at=NOW + timedelta(seconds=51),
            ) == 1
            recovered = await repository.claim_exports(
                worker_id="recovery-worker", limit=1, lease_seconds=30,
                occurred_at=NOW + timedelta(seconds=51),
            )
            assert len(recovered) == 1 and recovered[0]["operation_id"] == stale_operation

        async with sessions() as session, session.begin():
            await session.execute(text(
                "SELECT set_config('redagent.tenant_id', :tenant, true)"
            ), {"tenant": tenant})
            attempts = metadata.tables["telemetry_delivery_attempts"]
            assert await session.scalar(select(func.count()).select_from(
                attempts
            ).where(
                attempts.c.tenant_id == tenant
            )) == 3

        async with sessions() as session:
            transaction = await session.begin()
            role_name = f"r102_test_{suffix}"
            try:
                # CRITICAL: role identifier is generated exclusively from a hex UUID suffix.
                await session.execute(text(
                    f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB '
                    'NOCREATEROLE NOINHERIT NOBYPASSRLS'
                ))
                await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
                await session.execute(text(
                    f'GRANT SELECT ON telemetry_export_operations TO "{role_name}"'
                ))
                await session.execute(text(f'SET LOCAL ROLE "{role_name}"'))
                await session.execute(text(
                    "SELECT set_config('redagent.tenant_id', :tenant, true)"
                ), {"tenant": other_tenant})
                assert await session.scalar(select(func.count()).select_from(
                    metadata.tables["telemetry_export_operations"]
                )) == 0
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


def _envelope(*, tenant: str, suffix: str) -> TelemetryEnvelope:
    return TelemetryEnvelope(
        schema=TELEMETRY_SCHEMA, event_id=f"event-{suffix}", tenant_id=tenant,
        correlation_id=f"correlation-{suffix}", trace_id="1" * 32, span_id="2" * 16,
        parent_span_id=None, sampled=True, kind=SignalKind.EVENT,
        service_name=ServiceName.CONTAINMENT, service_version="0.1.0",
        service_instance_id="containment-local-1", resource_type=ResourceType.INCIDENT,
        resource_id=f"incident-{suffix}", operation="containment.incident.opened",
        outcome=SignalOutcome.FAILURE, reason_code="containment_incomplete", occurred_at=NOW,
        duration_ms=None, measurement_name=None, measurement_value=None,
    )
