from dataclasses import replace
from datetime import datetime, timezone

import pytest

from redagent_platform.identity_saas.evaluation import BaselineCheck, evaluate_identity_snapshot
from redagent_platform.identity_saas.lifecycle import IdentityRun, IdentityRunState, cancel_identity_run, complete_identity_cleanup, transition_identity_run
from redagent_platform.identity_saas.collector import IdentitySnapshot, IdentitySnapshotResource


NOW = datetime(2026, 7, 11, 5, 0, tzinfo=timezone.utc)


def _snapshot(*, complete=True):
    return IdentitySnapshot(
        provider="okta", tenant_id="org-r109", audience="okta-api-r109", consent_mode="application",
        collector_id="redagent-r109-emulator", collected_at=NOW, plan_sha256="a" * 64,
        granted_scopes=("okta.groups.read",), effective_role_permissions=("okta.groups.read",),
        complete=complete, partial_reasons=() if complete else ("throttled",), page_count=1, resource_count=1,
        resources=(IdentitySnapshotResource(resource_id="group-r109", operation_id="okta-groups-list-v1", attributes={"id": "group-r109", "type": "OKTA_GROUP"}),),
        redaction_sha256="b" * 64, snapshot_sha256="c" * 64,
    )


def test_baseline_replay_is_deterministic_and_partial_never_reports_clean():
    check = BaselineCheck(control_id="group-type", operation_id="okta-groups-list-v1", attribute="type", expected="OKTA_GROUP", severity="medium")
    first = evaluate_identity_snapshot(snapshot=_snapshot(), baseline_id="r109-baseline-v1", baseline_sha256="d" * 64, checks=(check,), evaluated_at=NOW)
    second = evaluate_identity_snapshot(snapshot=_snapshot(), baseline_id="r109-baseline-v1", baseline_sha256="d" * 64, checks=(check,), evaluated_at=NOW)
    assert first == second and first.results[0].passed is True
    partial = evaluate_identity_snapshot(snapshot=_snapshot(complete=False), baseline_id="r109-baseline-v1", baseline_sha256="d" * 64, checks=(check,), evaluated_at=NOW)
    assert partial.complete is False and partial.clean is False


def test_lease_first_cancel_and_exact_cleanup():
    run = IdentityRun(run_id="run-r109", state=IdentityRunState.RESERVED, lease_id="lease-r109")
    run = transition_identity_run(run, IdentityRunState.IDENTITY_VERIFYING)
    run = transition_identity_run(run, IdentityRunState.COLLECTING)
    cleaning, receipt = cancel_identity_run(run, occurred_at=NOW)
    assert receipt.new_requests_blocked and receipt.lease_revoked
    final, cleanup = complete_identity_cleanup(cleaning, occurred_at=NOW, residual_resource_ids=())
    assert final.state is IdentityRunState.CANCELLED and cleanup.residual_resource_count == 0
    with pytest.raises(ValueError, match="identity_cleanup_residual_resources"):
        complete_identity_cleanup(replace(cleaning, cancellation_requested=False), occurred_at=NOW, residual_resource_ids=("graph-r109",))
