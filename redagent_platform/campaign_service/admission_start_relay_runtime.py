"""Bounded tenant-partitioned runtime pump for R173 start-bridge delivery."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
from typing import Callable, Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.admission_start_relay import (
    AutonomousCampaignStartBridgeFailure,
    AutonomousCampaignStartBridgeRelay,
)
from redagent_platform.campaign_service.admission_start_contracts import (
    ClaimedAutonomousCampaignStartBridgeV1,
)
from redagent_platform.campaign_service.admission_start_relay_store import (
    PostgresAutonomousCampaignStartBridgeRelayRepository,
)
from redagent_platform.campaign_service.relay import WorkflowStartGateway
from redagent_platform.campaign_service.relay_runtime import RelayTenantSource
from redagent_platform.campaign_service.child_lineage import ChildLineageVerifier


class ClaimingAutonomousCampaignStartBridgeRepository(Protocol):
    async def claim_admission_start_bridges(
        self,
        *,
        claim_owner: str,
        now: datetime,
        lease_seconds: int,
        limit: int,
    ) -> list[ClaimedAutonomousCampaignStartBridgeV1]: ...

    async def confirm_admission_start_bridge_ready(
        self,
        *,
        event_id: str,
        claim_owner: str,
        payload: dict[str, object],
        occurred_at: datetime,
    ) -> bool: ...

    async def acknowledge_admission_start_bridge(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> object: ...

    async def record_admission_start_bridge_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: AutonomousCampaignStartBridgeFailure,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> object: ...


class AutonomousCampaignStartBridgeRelayPump:
    """Deliver committed R173 intents without crossing a FORCE-RLS tenant partition."""

    def __init__(
        self,
        *,
        tenant_source: RelayTenantSource,
        repository_factory: Callable[
            [str], ClaimingAutonomousCampaignStartBridgeRepository
        ],
        gateway: WorkflowStartGateway,
        claim_owner: str,
        tenant_page_size: int = 50,
        claim_limit: int = 10,
        lease_seconds: int = 30,
        poll_seconds: float = 0.5,
    ) -> None:
        self._tenants = tenant_source
        self._repositories = repository_factory
        self._gateway = gateway
        self._claim_owner = _required(
            "start_bridge_relay_claim_owner", claim_owner, 100
        )
        if type(tenant_page_size) is not int or not 1 <= tenant_page_size <= 100:
            raise ValueError("start_bridge_relay_tenant_page_size_invalid")
        if type(claim_limit) is not int or not 1 <= claim_limit <= 100:
            raise ValueError("start_bridge_relay_claim_limit_invalid")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("start_bridge_relay_lease_seconds_invalid")
        if isinstance(poll_seconds, bool) or not 0.05 <= poll_seconds <= 30:
            raise ValueError("start_bridge_relay_poll_seconds_invalid")
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
                raise ValueError("start_bridge_relay_tenant_page_invalid")
            for tenant_id in tenant_ids:
                repository = self._repositories(tenant_id)
                claims = await repository.claim_admission_start_bridges(
                    claim_owner=self._claim_owner,
                    now=now,
                    lease_seconds=self._lease_seconds,
                    limit=self._claim_limit,
                )
                if len(claims) > self._claim_limit:
                    raise ValueError("start_bridge_relay_claim_page_invalid")
                relay = AutonomousCampaignStartBridgeRelay(
                    repository=repository,
                    gateway=self._gateway,
                )
                for claim in claims:
                    if (
                        claim.payload.get("tenant_id") != tenant_id
                        or claim.claim_owner != self._claim_owner
                    ):
                        # CRITICAL: a committed start claim must never escape its RLS tenant.
                        raise ValueError("start_bridge_relay_claim_tenant_mismatch")
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


def postgres_admission_start_bridge_relay_repository_factory(
    sessions: async_sessionmaker[AsyncSession],
    *,
    instance_id: str,
    child_lineage_verifier: ChildLineageVerifier | None = None,
) -> Callable[[str], PostgresAutonomousCampaignStartBridgeRelayRepository]:
    stable_instance = _required("start_bridge_relay_instance", instance_id, 32)

    def factory(tenant_id: str) -> PostgresAutonomousCampaignStartBridgeRelayRepository:
        suffix = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:12]
        return PostgresAutonomousCampaignStartBridgeRelayRepository(
            sessions,
            tenant_id=tenant_id,
            actor_user_id="redagent-start-bridge-relay",
            correlation_prefix=f"start-bridge-{stable_instance}-{suffix}",
            child_lineage_verifier=child_lineage_verifier,
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
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("start_bridge_relay_now_timezone_required")
