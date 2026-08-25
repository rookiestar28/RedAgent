from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from redagent_platform.lab_service.qualification import BoundaryReceipt, QualificationCoordinator
from redagent_platform.lab_service.scenarios import ScenarioStatus, golden_scenario_registry


def test_boundary_receipt_is_closed_bounded_and_secret_free_metadata_sized() -> None:
    receipt = BoundaryReceipt(
        receipt_types=("audit", "outbox", "telemetry", "cleanup"),
        reason_code="fixed_local_boundary_passed", request_count=1, contact_count=0,
        details={"boundary": "postgresql", "status": "ready"},
    )
    assert receipt.contact_count == 0
    with pytest.raises(ValueError, match="boundary_receipt_type_unknown"):
        BoundaryReceipt(
            receipt_types=("shell",), reason_code="bad", request_count=0,
            contact_count=0, details={},
        )
    with pytest.raises(ValueError, match="boundary_receipt_count_invalid"):
        BoundaryReceipt(
            receipt_types=("cleanup",), reason_code="bad", request_count=101,
            contact_count=0, details={},
        )


def test_failed_boundary_is_compensated_and_durably_cleaned_before_failure_returns() -> None:
    asyncio.run(_compensation_scenario())


async def _compensation_scenario() -> None:
    repository = _RepositoryStub()
    with pytest.raises(ValueError, match="scenario_expected_receipt_missing"):
        await QualificationCoordinator(repository, _BoundaryStub())._run_one(
            run_id="run-1", bundle_id="bundle-1",
            definition=golden_scenario_registry()["authorize_deny"],
            occurred_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )
    assert repository.transitions == [
        ScenarioStatus.FAILED, ScenarioStatus.COMPENSATING, ScenarioStatus.CLEANED,
    ]
    assert repository.steps[-1]["step_state"] == "passed"
    assert repository.steps[-1]["contact_count"] == 0


class _BoundaryStub:
    async def execute(self, _definition):
        return BoundaryReceipt(
            receipt_types=("audit",), reason_code="incomplete",
            request_count=1, contact_count=0, details={},
        )

    async def compensate(self, _definition):
        return BoundaryReceipt(
            receipt_types=("cleanup",), reason_code="cleanup_verified",
            request_count=0, contact_count=0, details={},
        )


class _RepositoryStub:
    def __init__(self) -> None:
        self.transitions: list[ScenarioStatus] = []
        self.steps: list[dict[str, object]] = []

    async def start_scenario(self, **_values):
        return {"version": 2}

    async def transition_scenario(self, *, next_status, **_values):
        self.transitions.append(next_status)
        return {"version": 2 + len(self.transitions)}

    async def record_step(self, **values):
        self.steps.append(values)
        return values
