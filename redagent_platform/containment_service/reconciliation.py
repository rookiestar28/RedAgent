"""Restart-safe acknowledgement and stalled-containment reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from redagent_platform.containment_service.repository import ContainmentRepository


@dataclass(frozen=True)
class ReconciliationResult:
    inspected_controls: int
    incidents_opened: int
    incident_ids: tuple[str, ...]


class ContainmentReconciler:
    def __init__(self, repository: ContainmentRepository) -> None:
        self._repository = repository

    async def reconcile(self, *, occurred_at: datetime) -> ReconciliationResult:
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("containment_reconcile_time_invalid")
        result = await self._repository.reconcile_overdue_controls(occurred_at=occurred_at)
        return ReconciliationResult(
            inspected_controls=int(result["inspected_controls"]),
            incidents_opened=len(result["incident_ids"]),
            incident_ids=tuple(str(item) for item in result["incident_ids"]),
        )
