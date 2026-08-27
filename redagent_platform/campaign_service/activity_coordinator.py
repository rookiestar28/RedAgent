"""compat_123 Temporal Activity application coordinator.

Temporal carries only bounded routing hints.  Canonical campaign, effect, capability,
and authority material is loaded again by the state owner for every Activity.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from redagent_platform.campaign_service.execution import (
    NodeDesiredV1,
    NodeObservedV1,
    ReconcileOutcome,
    ReconcileResultV1,
    reconcile_node,
)
from redagent_platform.campaign_service.service import (
    EffectAmbiguityPersistenceError,
    EffectDispatchCommand,
    EffectReconciliationCommand,
    CampaignEffectCoordinator,
)
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ClosedLoopContainActivityCommand,
    ClosedLoopContainActivityResult,
    ClosedLoopDispatchActivityCommand,
    ClosedLoopDispatchActivityResult,
    ClosedLoopReconcileActivityCommand,
    ClosedLoopReconcileActivityResult,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ReconcileMaterial:
    tenant_id: str
    campaign_id: str
    strategy_revision_id: str
    envelope_sha256: str
    workflow_request_sha256: str
    revision: int
    depth: int
    replan_count: int
    node_id: str
    effect_id: str
    desired: NodeDesiredV1
    observed: NodeObservedV1
    committed_revision: int | None = None
    effect_reconciliation: EffectReconciliationCommand | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class DispatchMaterial:
    tenant_id: str
    campaign_id: str
    strategy_revision_id: str
    node_id: str
    effect_id: str
    envelope_sha256: str
    revision: int
    effect_command: EffectDispatchCommand
    effect_state: str = "reserved"
    committed_state: str | None = None
    committed_failure_code: str | None = None
    committed_revision: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ContainmentCommit:
    campaign_id: str
    state: str
    revision: int
    reason: str


class CampaignActivityStateOwner(Protocol):
    async def read_reconcile(
        self,
        command: ClosedLoopReconcileActivityCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ReconcileMaterial: ...

    async def commit_reconcile(
        self,
        command: ClosedLoopReconcileActivityCommand,
        material: ReconcileMaterial,
        decision: ReconcileResultV1,
        *,
        now: datetime,
        correlation_id: str,
    ) -> int: ...

    async def read_dispatch(
        self,
        command: ClosedLoopDispatchActivityCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> DispatchMaterial: ...

    async def commit_dispatch(
        self,
        command: ClosedLoopDispatchActivityCommand,
        material: DispatchMaterial,
        *,
        state: str,
        failure_code: str | None,
        now: datetime,
        correlation_id: str,
    ) -> int: ...

    async def contain(
        self,
        command: ClosedLoopContainActivityCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ContainmentCommit: ...


class CampaignActivityCoordinator:
    """Bind Temporal commands to fresh PostgreSQL-owned state and side effects."""

    def __init__(
        self,
        state_owner: CampaignActivityStateOwner,
        effect_coordinator: CampaignEffectCoordinator,
    ) -> None:
        self._state_owner = state_owner
        self._effect_coordinator = effect_coordinator

    async def reconcile(
        self,
        command: ClosedLoopReconcileActivityCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> ClosedLoopReconcileActivityResult:
        material = await self._state_owner.read_reconcile(
            command, now=occurred_at, correlation_id=correlation_id
        )
        _validate_reconcile_binding(command, material)
        if (
            material.committed_revision is None
            and material.effect_reconciliation is not None
            and (
                material.observed.next_retry_at is None
                or occurred_at >= material.observed.next_retry_at
            )
        ):
            # IMPORTANT: honor PostgreSQL backoff; due lookups are read-only and never resend.
            await self._effect_coordinator.reconcile(
                material.effect_reconciliation, now=occurred_at
            )
            material = await self._state_owner.read_reconcile(
                command, now=occurred_at, correlation_id=correlation_id
            )
            _validate_reconcile_binding(command, material)
        decision = reconcile_node(material.desired, material.observed, now=occurred_at)
        revision = await self._state_owner.commit_reconcile(
            command,
            material,
            decision,
            now=occurred_at,
            correlation_id=correlation_id,
        )
        if revision <= command.revision:
            raise RuntimeError("r123_reconcile_revision_not_advanced")
        retry_delay = None
        if decision.outcome is ReconcileOutcome.RETRY_AT:
            if decision.retry_at is None:
                raise RuntimeError("r123_reconcile_retry_missing")
            retry_delay = max(1, min(300, int((decision.retry_at - occurred_at).total_seconds())))
        return ClosedLoopReconcileActivityResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            campaign_id=material.campaign_id,
            strategy_revision_id=material.strategy_revision_id,
            revision=revision,
            depth=material.depth,
            replan_count=material.replan_count,
            node_id=material.node_id,
            effect_id=material.effect_id,
            outcome=decision.outcome.value,
            terminal=decision.outcome
            in {
                ReconcileOutcome.SETTLED,
                ReconcileOutcome.BLOCKED,
                ReconcileOutcome.CONTAINED,
                ReconcileOutcome.TERMINAL_FAILURE,
            },
            reason=decision.reason_code,
            retry_delay_seconds=retry_delay,
        )

    async def dispatch(
        self,
        command: ClosedLoopDispatchActivityCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> ClosedLoopDispatchActivityResult:
        material = await self._state_owner.read_dispatch(
            command, now=occurred_at, correlation_id=correlation_id
        )
        _validate_dispatch_binding(command, material)
        if material.committed_revision is not None:
            if material.committed_state not in {
                "dispatched",
                "reconciliation_required",
                "blocked",
            } or material.committed_revision <= command.expected_revision:
                raise ValueError("r123_dispatch_replay_invalid")
            return ClosedLoopDispatchActivityResult(
                schema_version=CONTRACT_SCHEMA_VERSION,
                campaign_id=material.campaign_id,
                effect_id=material.effect_id,
                state=material.committed_state,
                revision=material.committed_revision,
                failure_code=material.committed_failure_code,
            )
        state = "dispatched"
        failure_code = None
        if material.effect_state == "confirmed":
            # IMPORTANT: canonical confirmation may precede an Activity response loss.
            pass
        elif material.effect_state in {"dispatching", "reconciliation_required"}:
            # CRITICAL: possible acceptance means status reconciliation, never another dispatch.
            state = "reconciliation_required"
            failure_code = "adapter_acceptance_ambiguous"
        elif material.effect_state in {"reserved", "claimed", "not_applied"}:
            try:
                await self._effect_coordinator.dispatch(
                    material.effect_command, now=occurred_at
                )
            except asyncio.CancelledError as exc:
                try:
                    # CRITICAL: cancellation and durable manual reconciliation are
                    # both required after the dispatch boundary may have opened.
                    await asyncio.shield(self._state_owner.commit_dispatch(
                        command,
                        material,
                        state="reconciliation_required",
                        failure_code="activity_cancelled_after_possible_acceptance",
                        now=occurred_at,
                        correlation_id=correlation_id,
                    ))
                except BaseException:  # noqa: BLE001
                    exc.add_note("activity_ambiguity_fallback_persistence_failed")
                raise
            except EffectAmbiguityPersistenceError:
                state = "reconciliation_required"
                failure_code = "ambiguity_persistence_fallback"
            except RuntimeError as exc:
                # CRITICAL: possible adapter acceptance is durable ambiguity, never an implicit retry.
                if str(exc) != "effect_dispatch_reconciliation_required":
                    raise
                state = "reconciliation_required"
                failure_code = "adapter_acceptance_ambiguous"
        else:
            raise ValueError("r123_dispatch_effect_state_invalid")
        revision = await self._state_owner.commit_dispatch(
            command,
            material,
            state=state,
            failure_code=failure_code,
            now=occurred_at,
            correlation_id=correlation_id,
        )
        if revision <= command.expected_revision:
            raise RuntimeError("r123_dispatch_revision_not_advanced")
        return ClosedLoopDispatchActivityResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            campaign_id=material.campaign_id,
            effect_id=material.effect_id,
            state=state,
            revision=revision,
            failure_code=failure_code,
        )

    async def contain(
        self,
        command: ClosedLoopContainActivityCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> ClosedLoopContainActivityResult:
        result = await self._state_owner.contain(
            command, now=occurred_at, correlation_id=correlation_id
        )
        if result.campaign_id != command.campaign_id:
            raise ValueError("r123_containment_campaign_mismatch")
        if result.revision <= command.expected_revision:
            raise RuntimeError("r123_containment_revision_not_advanced")
        return ClosedLoopContainActivityResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            campaign_id=result.campaign_id,
            state=result.state,
            revision=result.revision,
            reason=result.reason,
        )


def _validate_reconcile_binding(
    command: ClosedLoopReconcileActivityCommand, material: ReconcileMaterial
) -> None:
    if (
        material.tenant_id != command.tenant_id
        or material.campaign_id != command.campaign_id
        or material.strategy_revision_id != command.strategy_revision_id
        or material.envelope_sha256 != command.envelope_sha256
        or material.workflow_request_sha256 != command.workflow_request_sha256
        or material.revision != command.revision
        or material.desired.tenant_id != material.tenant_id
        or material.desired.plan_revision_id != material.strategy_revision_id
        or material.desired.node_id != material.node_id
    ):
        raise ValueError("r123_reconcile_authoritative_binding_mismatch")


def _validate_dispatch_binding(
    command: ClosedLoopDispatchActivityCommand, material: DispatchMaterial
) -> None:
    effect = material.effect_command
    if (
        material.tenant_id != command.tenant_id
        or material.campaign_id != command.campaign_id
        or material.strategy_revision_id != command.strategy_revision_id
        or material.node_id != command.node_id
        or material.effect_id != command.effect_id
        or material.envelope_sha256 != command.envelope_sha256
        or material.revision != command.expected_revision
        or effect.tenant_id != material.tenant_id
        or effect.effect_id != material.effect_id
        or effect.envelope_sha256 != material.envelope_sha256
    ):
        raise ValueError("r123_dispatch_authoritative_binding_mismatch")
