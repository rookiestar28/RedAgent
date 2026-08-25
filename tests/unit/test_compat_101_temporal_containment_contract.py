from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ContainmentActivityCommand,
    ContainmentActivityResult,
)
from redagent_platform.orchestration.worker import worker_registration


ROOT = Path(__file__).resolve().parents[2]


def test_temporal_containment_contract_is_metadata_only_and_bounded() -> None:
    command = ContainmentActivityCommand(
        schema_version=CONTRACT_SCHEMA_VERSION, tenant_id="tenant-1", job_id="job-1",
        stop_id="stop-1", control_id="control-1", actor_user_id="operator-1",
        policy_reference="policy:r101-v1", expected_revision=4,
        reason_hash="a" * 64,
    )
    result = ContainmentActivityResult(
        schema_version=CONTRACT_SCHEMA_VERSION, job_id="job-1", stop_id="stop-1",
        action_id="action-1", outcome="contained", acknowledgement_ms=25,
        residual_risk_codes=(),
    )
    assert command.control_id == "control-1"
    assert result.outcome == "contained"
    forbidden = {
        "reason", "command", "argv", "shell", "image", "url", "target",
        "credential", "token", "provider_lease_reference", "process_id", "container_id",
    }
    assert not forbidden.intersection(ContainmentActivityCommand.__dataclass_fields__)
    with pytest.raises(ValueError, match="containment_acknowledgement_invalid"):
        replace(result, acknowledgement_ms=10_001)


def test_worker_and_workflow_register_heartbeat_cancel_and_independent_containment_activity() -> None:
    registration = worker_registration()
    assert "r101_contain_synthetic_job" in registration.activity_names
    workflow = (ROOT / "redagent_platform" / "orchestration" / "workflow.py").read_text(encoding="utf-8")
    activities = (ROOT / "redagent_platform" / "orchestration" / "activities.py").read_text(encoding="utf-8")
    assert "heartbeat_timeout=timedelta(seconds=2)" in workflow
    assert "ActivityCancellationType.WAIT_CANCELLATION_COMPLETED" in workflow
    assert "self._dispatch_handle.cancel()" in workflow
    assert '"r101_contain_synthetic_job"' in workflow
    assert "activity.heartbeat" in activities
    assert "except asyncio.CancelledError:" in activities
    assert "raise" in activities
