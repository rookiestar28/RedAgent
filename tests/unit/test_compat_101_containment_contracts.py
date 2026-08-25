from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.containment_service.contracts import (
    REQUIRED_CONTAINMENT_PHASES,
    ContainmentOutcome,
    ContainmentPhase,
    ControlScope,
    ControlScopeKind,
    PhaseReceipt,
    QuotaDimension,
    QuotaPolicy,
    StopApproval,
    StopRequest,
    aggregate_containment,
    canonical_stop_hash,
)


NOW = datetime(2026, 7, 10, 17, 0, tzinfo=timezone.utc)


def _request(**changes: object) -> StopRequest:
    values: dict[str, object] = {
        "schema_version": "1.0",
        "stop_id": "stop-1",
        "tenant_id": "tenant-1",
        "scope": ControlScope(ControlScopeKind.CAMPAIGN, "campaign-1"),
        "initiated_by": "operator-1",
        "reason": "Bounded synthetic rehearsal",
        "requested_at": NOW,
        "expected_version": 1,
        "idempotency_key": "stop-request-1",
    }
    values.update(changes)
    return StopRequest(**values)


def test_scope_and_quota_contracts_are_closed_and_integral() -> None:
    assert ControlScope(ControlScopeKind.GLOBAL, None).canonical_key == "global:*"
    with pytest.raises(ValueError, match="control_scope_id_required"):
        ControlScope(ControlScopeKind.JOB, None)
    with pytest.raises(ValueError, match="control_global_scope_id_forbidden"):
        ControlScope(ControlScopeKind.GLOBAL, "wildcard")
    with pytest.raises(ValueError):
        ControlScope("expression", "tenant_id != ''")  # type: ignore[arg-type]

    policy = QuotaPolicy(
        policy_id="quota-1", tenant_id="tenant-1", revision=1,
        dimension=QuotaDimension.OPERATIONS, scope=ControlScope(ControlScopeKind.CAMPAIGN, "campaign-1"),
        hard_limit=10, window_seconds=60, active_from=NOW, active_until=NOW + timedelta(hours=1),
        extension_name=None,
    )
    assert policy.hard_limit == 10
    with pytest.raises(ValueError, match="quota_limit_invalid"):
        QuotaPolicy(**{**policy.__dict__, "hard_limit": 1.5})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="quota_extension_name_required"):
        QuotaPolicy(**{**policy.__dict__, "dimension": QuotaDimension.EXTENSION})


def test_stop_hash_replay_and_dual_control_are_canonical() -> None:
    request = _request()
    assert canonical_stop_hash(request) == canonical_stop_hash(_request())
    approval = StopApproval(
        approval_id="approval-1", stop_id=request.stop_id, tenant_id=request.tenant_id,
        approver_user_id="operator-2", request_hash=canonical_stop_hash(request),
        approved_at=NOW + timedelta(seconds=1), expected_version=1,
    )
    assert approval.approver_user_id == "operator-2"
    assert approval.authorize(request)
    with pytest.raises(ValueError, match="stop_approval_separation_required"):
        approval.authorize(_request(initiated_by="operator-2"))


def test_contained_requires_every_verified_phase_and_failure_is_visible() -> None:
    receipts = tuple(
        PhaseReceipt(
            phase=phase, state="verified", reason_code="verified",
            occurred_at=NOW, duration_ms=1,
        )
        for phase in REQUIRED_CONTAINMENT_PHASES
    )
    result = aggregate_containment(receipts)
    assert result.outcome is ContainmentOutcome.CONTAINED
    assert not result.residual_risks

    missing = aggregate_containment(receipts[:-1])
    assert missing.outcome is ContainmentOutcome.CONTAINMENT_FAILED
    assert "missing_phase:evidence_lock" in missing.residual_risks

    failed_cleanup = tuple(
        PhaseReceipt(
            phase=item.phase,
            state="failed" if item.phase is ContainmentPhase.CLEANUP else item.state,
            reason_code="cleanup_timeout" if item.phase is ContainmentPhase.CLEANUP else item.reason_code,
            occurred_at=item.occurred_at,
            duration_ms=item.duration_ms,
        )
        for item in receipts
    )
    partial = aggregate_containment(failed_cleanup)
    assert partial.outcome is ContainmentOutcome.CONTAINED_WITH_RESIDUAL_RISK
    assert "cleanup:cleanup_timeout" in partial.residual_risks


def test_contracts_reject_raw_execution_and_secret_surfaces() -> None:
    allowed = set(StopRequest.__dataclass_fields__)
    assert not allowed.intersection({
        "command", "argv", "shell", "image", "url", "target", "environment",
        "provider_lease_reference", "credential", "token", "process_id", "container_id",
    })
