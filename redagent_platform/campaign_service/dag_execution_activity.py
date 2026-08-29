"""Bounded Activity application layer for one durable DAG transition."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol

from redagent_platform.campaign_service.dag_execution_contracts import (
    DagExecutionSnapshotV1,
    DagWorkflowInputV1,
)
from redagent_platform.campaign_service.service import (
    EffectDispatchCommand,
    EffectReconciliationCommand,
)


class DagActivityAction(str, Enum):
    DISPATCH = "dispatch"
    RECONCILE = "reconcile"
    WAIT = "wait"
    TERMINAL = "terminal"


@dataclass(frozen=True, slots=True)
class DagActivityMaterialV1:
    action: DagActivityAction
    snapshot: DagExecutionSnapshotV1
    effect_command: EffectDispatchCommand | None
    reconciliation_command: EffectReconciliationCommand | None

    def __post_init__(self) -> None:
        if not isinstance(self.action, DagActivityAction) or not isinstance(
            self.snapshot, DagExecutionSnapshotV1
        ):
            raise ValueError("dag_activity_material_invalid")
        if self.action is DagActivityAction.DISPATCH:
            valid = (
                isinstance(self.effect_command, EffectDispatchCommand)
                and self.reconciliation_command is None
            )
        elif self.action is DagActivityAction.RECONCILE:
            valid = (
                self.effect_command is None
                and isinstance(
                    self.reconciliation_command, EffectReconciliationCommand
                )
            )
        else:
            valid = (
                self.effect_command is None
                and self.reconciliation_command is None
            )
        if not valid:
            raise ValueError("dag_activity_action_binding_invalid")


class DagExecutionActivityStateOwner(Protocol):
    async def prepare(
        self, request: DagWorkflowInputV1, *, now: datetime
    ) -> DagActivityMaterialV1: ...

    async def snapshot(
        self, request: DagWorkflowInputV1, *, now: datetime
    ) -> DagExecutionSnapshotV1: ...


class DagEffectCoordinator(Protocol):
    async def dispatch(
        self, command: EffectDispatchCommand, *, now: datetime
    ) -> object: ...

    async def reconcile(
        self, command: EffectReconciliationCommand, *, now: datetime
    ) -> object: ...


class DagExecutionActivity:
    def __init__(
        self,
        state: DagExecutionActivityStateOwner,
        coordinator: DagEffectCoordinator,
    ) -> None:
        self._state = state
        self._coordinator = coordinator

    async def execute(
        self, request: DagWorkflowInputV1, *, now: datetime
    ) -> DagExecutionSnapshotV1:
        if not isinstance(request, DagWorkflowInputV1):
            raise ValueError("dag_activity_workflow_input_invalid")
        _aware(now)
        material = await self._state.prepare(request, now=now)
        if material.action is DagActivityAction.TERMINAL:
            return material.snapshot
        if material.action is DagActivityAction.WAIT:
            return material.snapshot
        try:
            if material.action is DagActivityAction.DISPATCH:
                assert material.effect_command is not None
                await self._coordinator.dispatch(material.effect_command, now=now)
            else:
                assert material.reconciliation_command is not None
                await self._coordinator.reconcile(
                    material.reconciliation_command, now=now
                )
        except RuntimeError as exc:
            if str(exc) != "effect_dispatch_reconciliation_required":
                raise
        return await self._state.snapshot(request, now=now)


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("dag_activity_time_invalid")
