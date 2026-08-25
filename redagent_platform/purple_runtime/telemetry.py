"""Owned collector for independent, integrity-bound marker observation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path

from redagent_platform.purple_runtime.compiler import CompiledAbilityPlan, verify_plan_integrity


@dataclass(frozen=True, kw_only=True)
class DetectionReceipt:
    run_id: str; collector_id: str; event_schema: str; analytic_id: str; marker_sha256: str
    observed: bool; event_sha256: str; occurred_at: datetime


class OwnedFileTelemetryCollector:
    def observe(self, *, plan: CompiledAbilityPlan, run_id: str, marker_path: str, occurred_at: datetime) -> DetectionReceipt:
        verify_plan_integrity(plan)
        path = Path(marker_path)
        if path.name != plan.marker_relative_path or path.parent.name != plan.lab_binding_id or not path.is_file():
            raise ValueError("purple_expected_telemetry_missing")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != plan.marker_sha256:
            raise ValueError("purple_telemetry_integrity_invalid")
        material = {"schema": plan.event_schema, "run_id": run_id, "ability_id": plan.ability_id,
            "collector_id": plan.telemetry_collector_id, "analytic_id": plan.analytic_id, "marker_sha256": digest,
            "occurred_at": occurred_at.isoformat()}
        event_sha = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return DetectionReceipt(run_id=run_id, collector_id=plan.telemetry_collector_id, event_schema=plan.event_schema,
            analytic_id=plan.analytic_id, marker_sha256=digest, observed=True, event_sha256=event_sha, occurred_at=occurred_at)
