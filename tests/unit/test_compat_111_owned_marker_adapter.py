from datetime import datetime, timezone
from pathlib import Path

import pytest

from redagent_platform.purple_runtime.adapter import OwnedMarkerAdapter
from redagent_platform.purple_runtime.telemetry import OwnedFileTelemetryCollector
from redagent_platform.purple_runtime.testing import compiled_marker_plan


NOW = datetime(2026, 7, 11, 15, 30, tzinfo=timezone.utc)


def test_owned_adapter_requires_independent_telemetry_then_removes_marker(tmp_path: Path):
    plan = compiled_marker_plan(now=NOW)
    adapter = OwnedMarkerAdapter(workspace_root=tmp_path)
    prepared = adapter.prepare(plan=plan, run_id="run-r111", occurred_at=NOW)
    executed = adapter.execute(plan=plan, run_id="run-r111", occurred_at=NOW)
    assert executed.marker_sha256 == plan.marker_sha256 and executed.network_contact_count == 0
    event = OwnedFileTelemetryCollector().observe(plan=plan, run_id="run-r111", marker_path=executed.marker_path, occurred_at=NOW)
    assert event.observed and event.collector_id == plan.telemetry_collector_id
    cleanup = adapter.cleanup(plan=plan, run_id="run-r111", occurred_at=NOW)
    assert prepared.before_entry_count == 0 and cleanup.residual_resource_count == 0
    assert not Path(executed.marker_path).exists()


def test_adapter_rejects_plan_tamper_and_collector_rejects_missing_marker(tmp_path: Path):
    plan = compiled_marker_plan(now=NOW)
    adapter = OwnedMarkerAdapter(workspace_root=tmp_path)
    with pytest.raises(ValueError, match="purple_plan_integrity_invalid"):
        adapter.execute(plan=plan.__class__(**{**plan.__dict__, "plan_sha256": "f" * 64}), run_id="run-r111", occurred_at=NOW)
    with pytest.raises(ValueError, match="purple_expected_telemetry_missing"):
        OwnedFileTelemetryCollector().observe(plan=plan, run_id="run-r111", marker_path=str(tmp_path / "missing"), occurred_at=NOW)
