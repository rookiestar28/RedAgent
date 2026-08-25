from datetime import datetime, timezone

import pytest

from redagent_platform.cloud_connectors.checks import SnapshotCheck, evaluate_snapshot
from redagent_platform.cloud_connectors.collector import CollectionSnapshot, SnapshotResource
from redagent_platform.cloud_connectors.contracts import ProviderIdentity, ProviderKind
from redagent_platform.cloud_connectors.lifecycle import (
    CloudRun,
    CloudRunState,
    cancel_run,
    complete_cleanup,
    transition_run,
)


NOW = datetime(2026, 7, 11, 16, 0, tzinfo=timezone.utc)


def snapshot(*, complete: bool = True) -> CollectionSnapshot:
    return CollectionSnapshot(
        identity=ProviderIdentity(provider=ProviderKind.AWS, tenant="123456789012"),
        collected_at=NOW,
        plan_sha256="1" * 64,
        complete=complete,
        partial_reasons=() if complete else ("iam_throttled",),
        page_count=1,
        resource_count=2,
        resources=(
            SnapshotResource(resource_id="role/admin", operation_id="aws-iam-list-roles-v1", attributes={"mfa_required": False}),
            SnapshotResource(resource_id="role/auditor", operation_id="aws-iam-list-roles-v1", attributes={"mfa_required": True}),
        ),
        snapshot_sha256="2" * 64,
    )


def test_stateless_checks_emit_per_resource_results_and_preserve_partial_truth() -> None:
    result = evaluate_snapshot(
        snapshot=snapshot(complete=False),
        control_pack_id="r108-cloud-baseline-v1",
        control_pack_sha256="3" * 64,
        checks=(SnapshotCheck(check_id="R108-AWS-001", operation_id="aws-iam-list-roles-v1", attribute="mfa_required", expected=True, severity="high"),),
        evaluated_at=NOW,
    )
    assert result.complete is False
    assert result.partial_reasons == ("iam_throttled",)
    assert [(row.resource_id, row.passed) for row in result.results] == [
        ("role/admin", False),
        ("role/auditor", True),
    ]
    assert len(result.evaluation_sha256) == 64


def test_lifecycle_requires_lease_revoke_and_request_block_before_stop_cleanup() -> None:
    run = CloudRun(run_id="run-r108", state=CloudRunState.PLANNED, lease_id="lease-r108")
    run = transition_run(run, CloudRunState.RESERVED)
    run = transition_run(run, CloudRunState.IDENTITY_VERIFYING)
    run = transition_run(run, CloudRunState.COLLECTING)
    cancelled, receipt = cancel_run(run, occurred_at=NOW)
    assert cancelled.state is CloudRunState.CLEANING
    assert receipt.new_requests_blocked is True
    assert receipt.lease_revoked is True
    assert receipt.cooperative_stop_acknowledged is True
    assert receipt.forced_termination is False

    closed, cleanup = complete_cleanup(cancelled, occurred_at=NOW, residual_resource_ids=())
    assert closed.state is CloudRunState.CANCELLED
    assert cleanup.residual_resource_count == 0

    with pytest.raises(ValueError, match="cloud_cleanup_residual_resources"):
        complete_cleanup(cancelled, occurred_at=NOW, residual_resource_ids=("workload-1",))


def test_lifecycle_denies_invalid_transition() -> None:
    with pytest.raises(ValueError, match="cloud_run_transition_invalid"):
        transition_run(
            CloudRun(run_id="run-r108", state=CloudRunState.PLANNED, lease_id="lease-r108"),
            CloudRunState.SUCCEEDED,
        )
