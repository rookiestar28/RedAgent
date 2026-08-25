from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from redagent_platform.containment_service.contracts import ContainmentOutcome, ContainmentPhase, PhaseReceipt
from redagent_platform.containment_service.coordinator import (
    ContainmentCoordinator, ContainmentPersistenceError,
)


NOW = datetime(2026, 7, 10, 17, 30, tzinfo=timezone.utc)


class Backend:
    def __init__(self, failing: ContainmentPhase | None = None) -> None:
        self.failing = failing
        self.calls: list[str] = []

    async def execute_phase(self, phase: ContainmentPhase) -> str:
        self.calls.append(phase.value)
        if phase is self.failing:
            raise RuntimeError(f"synthetic_{phase.value}_failure")
        return f"{phase.value}_verified"


def test_coordinator_runs_every_phase_in_order_and_requires_all_receipts() -> None:
    backend = Backend()
    result = asyncio.run(ContainmentCoordinator(backend, clock=lambda: NOW).contain())
    assert backend.calls == [phase.value for phase in ContainmentPhase]
    assert result.assessment.outcome is ContainmentOutcome.CONTAINED
    assert all(receipt.state == "verified" for receipt in result.receipts)


def test_phase_failure_does_not_skip_safer_remaining_phases_or_claim_success() -> None:
    backend = Backend(ContainmentPhase.LEASE_REVOCATION)
    result = asyncio.run(ContainmentCoordinator(backend, clock=lambda: NOW).contain())
    assert backend.calls[-2:] == ["cleanup", "evidence_lock"]
    assert result.assessment.outcome is ContainmentOutcome.CONTAINMENT_FAILED
    assert result.receipts[5].reason_code == "lease_revocation_failed"
    rendered = repr(result)
    assert "synthetic_lease_revocation_failure" not in rendered


def test_cleanup_failure_is_terminal_with_visible_residual_risk() -> None:
    result = asyncio.run(ContainmentCoordinator(
        Backend(ContainmentPhase.CLEANUP), clock=lambda: NOW,
    ).contain())
    assert result.assessment.outcome is ContainmentOutcome.CONTAINED_WITH_RESIDUAL_RISK
    assert result.assessment.residual_risks == ("cleanup:cleanup_failed",)


def test_retry_skips_immutable_existing_phase_receipts() -> None:
    backend = Backend()
    existing = tuple(
        PhaseReceipt(
            phase=phase, state="verified", reason_code=f"{phase.value}_verified",
            occurred_at=NOW, duration_ms=1,
        )
        for phase in tuple(ContainmentPhase)[:3]
    )
    result = asyncio.run(ContainmentCoordinator(
        backend, clock=lambda: NOW, existing_receipts=existing,
    ).contain())
    assert backend.calls == [phase.value for phase in tuple(ContainmentPhase)[3:]]
    assert result.assessment.outcome is ContainmentOutcome.CONTAINED


def test_receipt_persistence_failure_runs_all_safe_phases_then_fails_terminally() -> None:
    backend = Backend()

    async def unavailable(_receipt) -> None:
        raise RuntimeError("synthetic_database_outage")

    with pytest.raises(ContainmentPersistenceError, match="containment_phase_persistence_failed"):
        asyncio.run(ContainmentCoordinator(
            backend, clock=lambda: NOW, receipt_sink=unavailable,
        ).contain())
    assert backend.calls == [phase.value for phase in ContainmentPhase]
