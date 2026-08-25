from datetime import datetime, timezone

import pytest

from redagent_platform.artifact_pipeline.lifecycle import ArtifactRun, ArtifactRunState, cancel_artifact_run, complete_artifact_cleanup, transition_artifact_run


NOW = datetime(2026, 7, 11, 14, 0, tzinfo=timezone.utc)


def test_artifact_cancel_blocks_reads_and_revokes_lease_before_cleanup():
    run = ArtifactRun(run_id="run-r110", state=ArtifactRunState.RESERVED, lease_id="lease-r110")
    run = transition_artifact_run(run, ArtifactRunState.VALIDATING)
    run = transition_artifact_run(run, ArtifactRunState.INVENTORYING)
    cleaning, receipt = cancel_artifact_run(run, occurred_at=NOW)
    assert receipt.new_reads_blocked and receipt.lease_revoked and receipt.untrusted_execution_count == 0
    final, cleanup = complete_artifact_cleanup(cleaning, occurred_at=NOW, residual_resource_ids=(), untrusted_execution_count=0)
    assert final.state is ArtifactRunState.CANCELLED and cleanup.residual_resource_count == 0
    with pytest.raises(ValueError, match="artifact_untrusted_execution_detected"):
        complete_artifact_cleanup(cleaning, occurred_at=NOW, residual_resource_ids=(), untrusted_execution_count=1)
