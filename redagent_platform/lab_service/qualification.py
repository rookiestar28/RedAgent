"""Dependency-injected coordinator for durable compat_103 golden scenario receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
from typing import Protocol

from redagent_platform.lab_service.repository import LabRepository
from redagent_platform.lab_service.scenarios import (
    GoldenScenarioDefinition, ScenarioStatus, golden_scenario_registry,
)


@dataclass(frozen=True, kw_only=True)
class BoundaryReceipt:
    receipt_types: tuple[str, ...]
    reason_code: str
    request_count: int
    contact_count: int
    details: dict[str, object]

    def __post_init__(self) -> None:
        allowed = {"audit", "outbox", "telemetry", "evidence", "finding", "incident", "cleanup"}
        if not self.receipt_types or len(set(self.receipt_types)) != len(self.receipt_types):
            raise ValueError("boundary_receipt_types_invalid")
        if set(self.receipt_types) - allowed:
            raise ValueError("boundary_receipt_type_unknown")
        if not self.reason_code or len(self.reason_code) > 100:
            raise ValueError("boundary_receipt_reason_invalid")
        if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100 for value in (
            self.request_count, self.contact_count,
        )):
            raise ValueError("boundary_receipt_count_invalid")
        encoded = _canonical(self.details)
        if len(encoded) > 16_384:
            raise ValueError("boundary_receipt_details_too_large")


class ScenarioBoundary(Protocol):
    async def execute(self, definition: GoldenScenarioDefinition) -> BoundaryReceipt: ...

    async def compensate(self, definition: GoldenScenarioDefinition) -> BoundaryReceipt: ...


class QualificationCoordinator:
    def __init__(self, repository: LabRepository, boundary: ScenarioBoundary) -> None:
        self.repository = repository
        self.boundary = boundary

    async def run_all(
        self, *, run_id: str, bundle_id: str, started_at: datetime,
    ) -> tuple[dict[str, object], ...]:
        registry = golden_scenario_registry()
        results: list[dict[str, object]] = []
        for index, scenario_id in enumerate(registry):
            occurred_at = started_at + timedelta(milliseconds=index)
            results.append(await self._run_one(
                run_id=run_id, bundle_id=bundle_id, definition=registry[scenario_id],
                occurred_at=occurred_at,
            ))
        return tuple(results)

    async def _run_one(
        self, *, run_id: str, bundle_id: str, definition: GoldenScenarioDefinition,
        occurred_at: datetime,
    ) -> dict[str, object]:
        row = await self.repository.start_scenario(
            run_id=run_id, scenario_id=definition.scenario_id,
            bundle_id=bundle_id, occurred_at=occurred_at,
        )
        try:
            receipt = await self.boundary.execute(definition)
            required = set(definition.expected_receipts)
            if not required.issubset(receipt.receipt_types):
                raise ValueError("scenario_expected_receipt_missing")
            encoded = _canonical({
                "types": receipt.receipt_types, "reason_code": receipt.reason_code,
                "details": receipt.details,
            })
            await self.repository.record_step(
                run_id=run_id, scenario_id=definition.scenario_id,
                step_id="execute-fixed-scenario", action_id=f"{run_id}:{definition.scenario_id}:execute",
                step_name="execute_fixed_boundary", step_state="passed",
                request_sha256=hashlib.sha256(_canonical({"scenario_id": definition.scenario_id})).hexdigest(),
                receipt_sha256=hashlib.sha256(encoded).hexdigest(),
                request_count=receipt.request_count, contact_count=receipt.contact_count,
                reason_code=receipt.reason_code, occurred_at=occurred_at,
            )
            return await self.repository.transition_scenario(
                run_id=run_id, scenario_id=definition.scenario_id,
                action_id=f"{run_id}:{definition.scenario_id}:succeeded",
                expected_version=int(row["version"]), next_status=ScenarioStatus.SUCCEEDED,
                reason_code="scenario_succeeded", occurred_at=occurred_at,
            )
        except Exception:
            failed = await self.repository.transition_scenario(
                run_id=run_id, scenario_id=definition.scenario_id,
                action_id=f"{run_id}:{definition.scenario_id}:failed",
                expected_version=int(row["version"]), next_status=ScenarioStatus.FAILED,
                reason_code="scenario_boundary_failed", occurred_at=occurred_at,
            )
            compensating = await self.repository.transition_scenario(
                run_id=run_id, scenario_id=definition.scenario_id,
                action_id=f"{run_id}:{definition.scenario_id}:compensating",
                expected_version=int(failed["version"]), next_status=ScenarioStatus.COMPENSATING,
                reason_code="scenario_compensation_started", occurred_at=occurred_at,
            )
            compensation = await self.boundary.compensate(definition)
            if "cleanup" not in compensation.receipt_types or compensation.contact_count != 0:
                raise ValueError("scenario_compensation_receipt_invalid")
            cleanup_payload = _canonical({
                "types": compensation.receipt_types, "reason_code": compensation.reason_code,
                "details": compensation.details,
            })
            await self.repository.record_step(
                run_id=run_id, scenario_id=definition.scenario_id,
                step_id="compensate-fixed-scenario", action_id=f"{run_id}:{definition.scenario_id}:cleanup",
                step_name="verify_fixed_cleanup", step_state="passed",
                request_sha256=hashlib.sha256(_canonical({"compensate": definition.scenario_id})).hexdigest(),
                receipt_sha256=hashlib.sha256(cleanup_payload).hexdigest(),
                request_count=compensation.request_count, contact_count=compensation.contact_count,
                reason_code=compensation.reason_code, occurred_at=occurred_at,
            )
            await self.repository.transition_scenario(
                run_id=run_id, scenario_id=definition.scenario_id,
                action_id=f"{run_id}:{definition.scenario_id}:cleaned",
                expected_version=int(compensating["version"]), next_status=ScenarioStatus.CLEANED,
                reason_code="scenario_cleanup_verified", occurred_at=occurred_at,
            )
            raise


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
