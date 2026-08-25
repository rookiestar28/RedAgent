"""Fail-closed current-authority revocation propagation into exact job stops."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import Awaitable, Callable, Iterable, Protocol

from redagent_platform.containment_service.contracts import ControlScope, ControlScopeKind, StopRequest
from redagent_platform.containment_service.repository import ContainmentRepository


REVOCATION_SLO_MS = 10_000


@dataclass(frozen=True, kw_only=True)
class AuthorityFacts:
    tenant_id: str
    job_id: str
    authorization_current: bool
    roe_current: bool
    policy_current: bool
    credential_current: bool
    checked_at: datetime
    invalidated_at: datetime | None

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.job_id:
            raise ValueError("authority_fact_id_required")
        for value in (
            self.authorization_current, self.roe_current,
            self.policy_current, self.credential_current,
        ):
            if not isinstance(value, bool):
                raise ValueError("authority_fact_boolean_required")
        _aware(self.checked_at)
        if self.invalidated_at is not None:
            _aware(self.invalidated_at)
            if self.invalidated_at > self.checked_at:
                raise ValueError("authority_invalidation_time_invalid")
        if self.revocation_code is not None and self.invalidated_at is None:
            raise ValueError("authority_invalidation_time_required")

    @property
    def revocation_code(self) -> str | None:
        for current, code in (
            (self.authorization_current, "authorization_revoked"),
            (self.roe_current, "roe_revoked"),
            (self.policy_current, "policy_revoked"),
            (self.credential_current, "credential_revoked"),
        ):
            if not current:
                return code
        return None


@dataclass(frozen=True)
class RevocationPropagation:
    job_id: str
    reason_code: str
    stop_id: str
    propagation_ms: int
    within_slo: bool


class FactsProvider(Protocol):
    async def __call__(self, job_id: str, occurred_at: datetime) -> AuthorityFacts: ...


StopActivator = Callable[[AuthorityFacts, str, datetime], Awaitable[str]]
WorkflowStopSignal = Callable[[AuthorityFacts, dict[str, object], str], Awaitable[None]]


class PersistentRevocationStopActivator:
    """Persist an exact active job control before signaling durable orchestration."""

    def __init__(self, sessions, signal_stop: WorkflowStopSignal) -> None:
        self._sessions = sessions
        self._signal_stop = signal_stop

    async def __call__(self, facts: AuthorityFacts, reason: str, occurred_at: datetime) -> str:
        assert facts.invalidated_at is not None
        identity = f"{facts.tenant_id}:{facts.job_id}:{reason}:{facts.invalidated_at.isoformat()}"
        digest = hashlib.sha256(identity.encode()).hexdigest()[:24]
        stop_id = f"revocation-{digest}"
        async with self._sessions() as session, session.begin():
            control = await ContainmentRepository(
                session, tenant_id=facts.tenant_id,
                actor_user_id="redagent-revocation-monitor",
                correlation_id=f"revocation-{digest}",
            ).request_stop(StopRequest(
                schema_version="1.0", stop_id=stop_id, tenant_id=facts.tenant_id,
                scope=ControlScope(ControlScopeKind.JOB, facts.job_id),
                initiated_by="redagent-revocation-monitor",
                reason=f"Current authority invalidated: {reason}",
                requested_at=occurred_at, expected_version=1,
                idempotency_key=f"revocation-{digest}",
            ))
        await self._signal_stop(facts, control, reason)
        return stop_id


class RevocationMonitor:
    def __init__(self, facts_provider: FactsProvider, stop_activator: StopActivator) -> None:
        self._facts = facts_provider
        self._activate = stop_activator

    async def reconcile(
        self, job_ids: Iterable[str], *, occurred_at: datetime,
    ) -> tuple[RevocationPropagation, ...]:
        _aware(occurred_at)
        identifiers = tuple(job_ids)
        if not identifiers or len(identifiers) > 1_000 or len(set(identifiers)) != len(identifiers):
            raise ValueError("revocation_job_set_invalid")

        async def inspect(job_id: str) -> RevocationPropagation | None:
            facts = await self._facts(job_id, occurred_at)
            if facts.job_id != job_id or facts.checked_at != occurred_at:
                raise RuntimeError("revocation_facts_not_current")
            reason = facts.revocation_code
            if reason is None:
                return None
            assert facts.invalidated_at is not None
            stop_id = await self._activate(facts, reason, occurred_at)
            propagation_ms = max(0, int((occurred_at - facts.invalidated_at).total_seconds() * 1_000))
            return RevocationPropagation(
                job_id=job_id, reason_code=reason, stop_id=stop_id,
                propagation_ms=propagation_ms, within_slo=propagation_ms <= REVOCATION_SLO_MS,
            )

        results = await asyncio.gather(*(inspect(job_id) for job_id in identifiers))
        return tuple(item for item in results if item is not None)


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
