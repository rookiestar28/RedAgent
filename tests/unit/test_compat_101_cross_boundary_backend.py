from __future__ import annotations

import asyncio

import pytest

from redagent_platform.containment_service.contracts import ContainmentPhase
from redagent_platform.containment_service.coordinator import CallbackContainmentBackend


def test_callback_backend_requires_and_invokes_every_exact_phase() -> None:
    observed: list[ContainmentPhase] = []

    def callback(phase: ContainmentPhase):
        async def execute() -> bool:
            observed.append(phase)
            return True
        return execute

    backend = CallbackContainmentBackend({phase: callback(phase) for phase in ContainmentPhase})
    for phase in ContainmentPhase:
        assert asyncio.run(backend.execute_phase(phase)) == f"{phase.value}_verified"
    assert observed == list(ContainmentPhase)


def test_callback_backend_rejects_missing_or_false_receipt() -> None:
    async def verified() -> bool:
        return True

    with pytest.raises(ValueError, match="containment_phase_callback_set_invalid"):
        CallbackContainmentBackend({ContainmentPhase.DISPATCH_BLOCK: verified})

    callbacks = {phase: verified for phase in ContainmentPhase}

    async def unverified() -> bool:
        return False

    callbacks[ContainmentPhase.LEASE_REVOCATION] = unverified
    backend = CallbackContainmentBackend(callbacks)
    assert asyncio.run(backend.execute_phase(ContainmentPhase.LEASE_REVOCATION)) == "lease_revocation_unverified"
