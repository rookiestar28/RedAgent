"""Ordered best-effort containment with independent secret-free receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from time import monotonic_ns
from typing import Awaitable, Callable, Mapping, Protocol

from redagent_platform.containment_service.contracts import (
    ContainmentAssessment,
    ContainmentPhase,
    PhaseReceipt,
    aggregate_containment,
)


class ContainmentBackend(Protocol):
    async def execute_phase(self, phase: ContainmentPhase) -> str: ...


PhaseCallback = Callable[[], Awaitable[bool]]


class CallbackContainmentBackend:
    """Bind every containment phase to one explicit service-boundary callback."""

    def __init__(self, callbacks: Mapping[ContainmentPhase, PhaseCallback]) -> None:
        missing = tuple(phase.value for phase in ContainmentPhase if phase not in callbacks)
        extra = tuple(str(phase) for phase in callbacks if not isinstance(phase, ContainmentPhase))
        if missing or extra:
            raise ValueError("containment_phase_callback_set_invalid")
        self._callbacks = dict(callbacks)

    async def execute_phase(self, phase: ContainmentPhase) -> str:
        # CRITICAL: a missing or false service receipt must never become containment success.
        verified = await self._callbacks[phase]()
        if verified is not True:
            return f"{phase.value}_unverified"
        return f"{phase.value}_verified"


@dataclass(frozen=True)
class ContainmentRun:
    receipts: tuple[PhaseReceipt, ...]
    assessment: ContainmentAssessment


class ContainmentPersistenceError(RuntimeError):
    """Raised only after all remaining safe phases have been attempted."""


class ContainmentCoordinator:
    def __init__(
        self,
        backend: ContainmentBackend,
        *,
        clock: Callable[[], datetime],
        existing_receipts: tuple[PhaseReceipt, ...] = (),
        receipt_sink: Callable[[PhaseReceipt], Awaitable[None]] | None = None,
    ) -> None:
        self._backend = backend
        self._clock = clock
        self._receipt_sink = receipt_sink
        self._existing = {receipt.phase: receipt for receipt in existing_receipts}
        if len(self._existing) != len(existing_receipts):
            raise ValueError("containment_phase_duplicate")

    async def contain(self) -> ContainmentRun:
        receipts: list[PhaseReceipt] = []
        persistence_failed = False
        for phase in ContainmentPhase:
            existing = self._existing.get(phase)
            if existing is not None:
                receipts.append(existing)
                continue
            started = monotonic_ns()
            state = "verified"
            reason_code = f"{phase.value}_verified"
            try:
                reported = await self._backend.execute_phase(phase)
                if reported != reason_code:
                    state = "failed"
                    reason_code = f"{phase.value}_unverified"
            except Exception:  # noqa: BLE001 - every later safe phase must still run
                # CRITICAL: backend exception text can contain runtime details or secrets.
                state = "failed"
                reason_code = f"{phase.value}_failed"
            duration_ms = max(0, (monotonic_ns() - started) // 1_000_000)
            receipt = PhaseReceipt(
                phase=phase,
                state=state,
                reason_code=reason_code,
                occurred_at=self._clock(),
                duration_ms=duration_ms,
            )
            receipts.append(receipt)
            if self._receipt_sink is not None:
                try:
                    await self._receipt_sink(receipt)
                except Exception:  # noqa: BLE001 - safe remaining phases still must execute
                    persistence_failed = True
        frozen = tuple(receipts)
        if persistence_failed:
            raise ContainmentPersistenceError("containment_phase_persistence_failed")
        return ContainmentRun(receipts=frozen, assessment=aggregate_containment(frozen))
