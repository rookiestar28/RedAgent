"""Bounded tenant-partitioned runtime pump for compat_123 workflow-start outbox delivery."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
from typing import Callable, Protocol

from sqlalchemy import select

from redagent_platform.campaign_service.relay import (
    CampaignWorkflowRelay,
    WorkflowStartGateway,
)
from redagent_platform.campaign_service.repository import (
    ClaimedWorkflowStart,
    CampaignRepository,
)
from redagent_platform.campaign_service.resolver import CampaignContextResolver
from redagent_platform.persistence.models import metadata


class RelayTenantSource(Protocol):
    async def read_page(
        self, *, after_tenant_id: str | None, limit: int
    ) -> tuple[str, ...]: ...


class ClaimingWorkflowRelayRepository(Protocol):
    async def claim_workflow_starts(
        self,
        *,
        claim_owner: str,
        now: datetime,
        lease_seconds: int,
        limit: int,
    ) -> list[ClaimedWorkflowStart]: ...

    async def acknowledge_workflow_start(self, **values: object) -> object: ...

    async def record_workflow_start_failure(self, **values: object) -> object: ...


class PostgresRelayTenantSource:
    """Enumerate only tenant partition keys; all business reads remain under FORCE RLS."""

    def __init__(self, sessions: object) -> None:
        self._sessions = sessions

    async def read_page(
        self, *, after_tenant_id: str | None, limit: int
    ) -> tuple[str, ...]:
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("r123_relay_tenant_page_size_invalid")
        tenants = metadata.tables["tenants"]
        statement = select(tenants.c.id).order_by(tenants.c.id).limit(limit)
        if after_tenant_id is not None:
            _required("r123_relay_tenant_cursor", after_tenant_id, 64)
            statement = statement.where(tenants.c.id > after_tenant_id)
        async with self._sessions() as session:
            rows = (await session.scalars(statement)).all()
        return tuple(str(item) for item in rows)


class PostgresWorkflowRelayRepository:
    """Open one transaction and one exact tenant RLS context for every relay mutation."""

    def __init__(
        self,
        sessions: object,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_prefix: str,
    ) -> None:
        self._sessions = sessions
        self._tenant_id = _required("r123_relay_tenant", tenant_id, 64)
        self._actor_user_id = _required("r123_relay_actor", actor_user_id, 64)
        self._correlation_prefix = _required(
            "r123_relay_correlation", correlation_prefix, 64
        )

    async def claim_workflow_starts(self, **values: object) -> list[ClaimedWorkflowStart]:
        async with self._sessions() as session, session.begin():
            return await self._repository(session, "claim").claim_workflow_starts(**values)

    async def acknowledge_workflow_start(self, **values: object) -> object:
        async with self._sessions() as session, session.begin():
            return await self._repository(session, "ack").acknowledge_workflow_start(**values)

    async def record_workflow_start_failure(self, **values: object) -> object:
        async with self._sessions() as session, session.begin():
            return await self._repository(session, "failure").record_workflow_start_failure(
                **values
            )

    def _repository(self, session: object, phase: str) -> CampaignRepository:
        return CampaignRepository(
            session,
            tenant_id=self._tenant_id,
            actor_user_id=self._actor_user_id,
            correlation_id=f"{self._correlation_prefix}-{phase}",
        )


class CampaignRelayPump:
    """Claim and deliver a bounded page at a time without cross-tenant business reads."""

    def __init__(
        self,
        *,
        tenant_source: RelayTenantSource,
        repository_factory: Callable[[str], ClaimingWorkflowRelayRepository],
        resolver: CampaignContextResolver,
        gateway: WorkflowStartGateway,
        claim_owner: str,
        tenant_page_size: int = 50,
        claim_limit: int = 10,
        lease_seconds: int = 30,
        poll_seconds: float = 0.5,
    ) -> None:
        self._tenants = tenant_source
        self._repositories = repository_factory
        self._resolver = resolver
        self._gateway = gateway
        self._claim_owner = _required("r123_relay_claim_owner", claim_owner, 100)
        if isinstance(tenant_page_size, bool) or not 1 <= tenant_page_size <= 100:
            raise ValueError("r123_relay_tenant_page_size_invalid")
        if isinstance(claim_limit, bool) or not 1 <= claim_limit <= 100:
            raise ValueError("r123_relay_claim_limit_invalid")
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 300:
            raise ValueError("r123_relay_lease_seconds_invalid")
        if isinstance(poll_seconds, bool) or not 0.05 <= poll_seconds <= 30:
            raise ValueError("r123_relay_poll_seconds_invalid")
        self._tenant_page_size = tenant_page_size
        self._claim_limit = claim_limit
        self._lease_seconds = lease_seconds
        self._poll_seconds = poll_seconds

    async def run_once(self, *, now: datetime) -> int:
        _aware(now)
        delivered = 0
        cursor: str | None = None
        while True:
            tenant_ids = await self._tenants.read_page(
                after_tenant_id=cursor,
                limit=self._tenant_page_size,
            )
            if not tenant_ids:
                return delivered
            if (
                tuple(sorted(set(tenant_ids))) != tenant_ids
                or (cursor is not None and tenant_ids[0] <= cursor)
            ):
                raise ValueError("r123_relay_tenant_page_invalid")
            for tenant_id in tenant_ids:
                repository = self._repositories(tenant_id)
                claims = await repository.claim_workflow_starts(
                    claim_owner=self._claim_owner,
                    now=now,
                    lease_seconds=self._lease_seconds,
                    limit=self._claim_limit,
                )
                if len(claims) > self._claim_limit:
                    raise ValueError("r123_relay_claim_page_invalid")
                relay = CampaignWorkflowRelay(
                    resolver=self._resolver,
                    repository=repository,
                    gateway=self._gateway,
                )
                for claim in claims:
                    if (
                        claim.payload.get("tenant_id") != tenant_id
                        or claim.claim_owner != self._claim_owner
                    ):
                        # CRITICAL: a claimed row must never escape its current RLS partition.
                        raise ValueError("r123_relay_claim_tenant_mismatch")
                    await relay.deliver(claim, now=now)
                    delivered += 1
            cursor = tenant_ids[-1]
            if len(tenant_ids) < self._tenant_page_size:
                return delivered

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.run_once(now=datetime.now(timezone.utc))
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._poll_seconds)
            except TimeoutError:
                continue


def postgres_relay_repository_factory(
    sessions: object,
    *,
    instance_id: str,
) -> Callable[[str], PostgresWorkflowRelayRepository]:
    stable_instance = _required("r123_relay_instance", instance_id, 32)

    def factory(tenant_id: str) -> PostgresWorkflowRelayRepository:
        suffix = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:12]
        return PostgresWorkflowRelayRepository(
            sessions,
            tenant_id=tenant_id,
            actor_user_id="redagent-r123-relay",
            correlation_prefix=f"r123-relay-{stable_instance}-{suffix}",
        )

    return factory


def _required(name: str, value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name}_invalid")
    return value


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("r123_relay_now_timezone_required")
