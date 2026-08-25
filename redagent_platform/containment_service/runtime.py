"""Persistent adapter-neutral containment Activity dispatcher."""

from __future__ import annotations

from datetime import datetime
from time import monotonic_ns
from typing import Callable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.containment_service.coordinator import ContainmentBackend, ContainmentCoordinator
from redagent_platform.containment_service.repository import ContainmentRepository
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ContainmentActivityCommand,
    ContainmentActivityResult,
)


class PersistentContainmentDispatcher:
    """Runs every safe phase and persists receipts before returning a terminal result."""

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        backend_factory: Callable[[ContainmentActivityCommand], ContainmentBackend],
    ) -> None:
        self._sessions = sessions
        self._backend_factory = backend_factory

    async def contain(
        self,
        command: ContainmentActivityCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> ContainmentActivityResult:
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("containment_time_invalid")
        started = monotonic_ns()
        async with self._sessions() as session, session.begin():
            repository = ContainmentRepository(
                session,
                tenant_id=command.tenant_id,
                actor_user_id="redagent-containment-service",
                correlation_id=correlation_id,
            )
            action = await repository.begin_action(
                control_id=command.control_id,
                job_id=command.job_id,
                runner_registration_id=None,
                occurred_at=occurred_at,
                stop_id=command.stop_id,
            )
            existing_receipts = await repository.list_phase_receipts(str(action["id"]))
        acknowledgement_ms = (monotonic_ns() - started) // 1_000_000
        if acknowledgement_ms > 10_000:
            raise RuntimeError("containment_acknowledgement_slo_exceeded")

        async def persist(receipt) -> None:
            async with self._sessions() as phase_session, phase_session.begin():
                await ContainmentRepository(
                    phase_session,
                    tenant_id=command.tenant_id,
                    actor_user_id="redagent-containment-service",
                    correlation_id=correlation_id,
                ).record_phase(str(action["id"]), receipt)

        run = await ContainmentCoordinator(
            self._backend_factory(command), clock=lambda: occurred_at,
            existing_receipts=existing_receipts, receipt_sink=persist,
        ).contain()
        async with self._sessions() as session, session.begin():
            terminal = await ContainmentRepository(
                session,
                tenant_id=command.tenant_id,
                actor_user_id="redagent-containment-service",
                correlation_id=correlation_id,
            ).complete_action(str(action["id"]), occurred_at=occurred_at)
        return ContainmentActivityResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            job_id=command.job_id,
            stop_id=command.stop_id,
            action_id=str(action["id"]),
            outcome=str(terminal["outcome"]),
            acknowledgement_ms=int(acknowledgement_ms),
            residual_risk_codes=tuple(terminal["residual_risks"]),
        )
