from datetime import datetime, timezone

import pytest

from redagent_platform.purple_runtime.lifecycle import PurpleRun, PurpleRunState, cancel_purple_run, complete_purple_run, transition_purple_run


NOW = datetime(2026, 7, 11, 16, 0, tzinfo=timezone.utc)


def test_success_requires_detection_cleanup_teardown_and_zero_residual():
    run = PurpleRun(run_id="run-r111", state=PurpleRunState.PLANNED, lease_id="lease-r111")
    for state in (PurpleRunState.PREPARED, PurpleRunState.EXECUTED, PurpleRunState.OBSERVING, PurpleRunState.CLEANING):
        run = transition_purple_run(run, state)
    with pytest.raises(ValueError, match="purple_detection_evidence_required"):
        complete_purple_run(run, occurred_at=NOW, detection_observed=False, residual_resource_ids=(), teardown_verified=True)
    final, receipt = complete_purple_run(run, occurred_at=NOW, detection_observed=True, residual_resource_ids=(), teardown_verified=True)
    assert final.state is PurpleRunState.SUCCEEDED and receipt.zero_residual


def test_kill_revokes_lease_and_blocks_dispatch_before_cleanup():
    run = PurpleRun(run_id="run-r111", state=PurpleRunState.EXECUTED, lease_id="lease-r111")
    cleaning, receipt = cancel_purple_run(run, occurred_at=NOW)
    assert receipt.lease_revoked and receipt.dispatch_blocked and receipt.kill_acknowledged
    final, cleanup = complete_purple_run(cleaning, occurred_at=NOW, detection_observed=False,
        residual_resource_ids=(), teardown_verified=True)
    assert final.state is PurpleRunState.CANCELLED and cleanup.zero_residual
