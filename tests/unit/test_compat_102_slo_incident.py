from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from fractions import Fraction

import pytest

from redagent_platform.telemetry_service.incidents import (
    IncidentAction,
    IncidentSnapshot,
    IncidentState,
    apply_incident_action,
)
from redagent_platform.telemetry_service.slo import (
    BurnAlertState,
    SloEvaluationState,
    SloObjective,
    evaluate_ratio_window,
    evaluate_stop_window,
    evaluate_multi_window_burn,
)


NOW = datetime(2026, 7, 11, 3, 0, tzinfo=timezone.utc)


def test_ratio_and_stop_slo_math_is_exact_and_missing_data_is_not_success() -> None:
    objective = SloObjective(
        objective_id="api-availability",
        target_basis_points=9990,
        window_seconds=3600,
        threshold_ms=None,
    )
    healthy = evaluate_ratio_window(objective, total=10_000, bad=5, missing=0)
    assert healthy.state is SloEvaluationState.HEALTHY
    assert healthy.error_budget_consumed == Fraction(1, 2)

    burning = evaluate_ratio_window(objective, total=10_000, bad=20, missing=0)
    assert burning.state is SloEvaluationState.BREACHING
    assert burning.error_budget_consumed == Fraction(2, 1)

    unknown = evaluate_ratio_window(objective, total=0, bad=0, missing=1)
    assert unknown.state is SloEvaluationState.UNKNOWN
    assert unknown.error_budget_consumed is None

    stop = SloObjective(
        objective_id="emergency-stop",
        target_basis_points=10_000,
        window_seconds=300,
        threshold_ms=10_000,
    )
    stop_result = evaluate_stop_window(stop, durations_ms=(9_999, 10_000, 10_001), missing=0)
    assert stop_result.total == 3
    assert stop_result.bad == 1
    assert stop_result.state is SloEvaluationState.BREACHING


def test_multi_window_burn_requires_both_windows_and_never_alerts_unknown() -> None:
    objective = SloObjective("availability", 9990, 3600, None)
    fast = evaluate_ratio_window(objective, total=10_000, bad=200, missing=0)
    slow = evaluate_ratio_window(objective, total=100_000, bad=2_000, missing=0)
    assert evaluate_multi_window_burn(fast, slow, threshold=Fraction(144, 10)) is BurnAlertState.FIRING

    healthy = evaluate_ratio_window(objective, total=10_000, bad=5, missing=0)
    assert evaluate_multi_window_burn(fast, healthy, threshold=Fraction(144, 10)) is BurnAlertState.CLEAR

    unknown = evaluate_ratio_window(objective, total=0, bad=0, missing=1)
    assert evaluate_multi_window_burn(fast, unknown, threshold=Fraction(144, 10)) is BurnAlertState.UNKNOWN


def _incident(**changes: object) -> IncidentSnapshot:
    values: dict[str, object] = {
        "incident_id": "incident-1",
        "tenant_id": "tenant-1",
        "severity": "critical",
        "state": IncidentState.OPEN,
        "opened_by": "system-telemetry",
        "assigned_to": None,
        "acknowledged_by": None,
        "contained_by": None,
        "recovered_by": None,
        "reviewed_by": None,
        "evidence_preserved": False,
        "containment_verified": False,
        "version": 1,
    }
    values.update(changes)
    return IncidentSnapshot(**values)


def test_incident_lifecycle_requires_containment_evidence_recovery_review_and_sod() -> None:
    incident = apply_incident_action(
        _incident(), action=IncidentAction.ACKNOWLEDGE, actor_id="operator-1",
        expected_version=1, occurred_at=NOW,
    )
    assert incident.state is IncidentState.ACKNOWLEDGED
    assert incident.version == 2

    preserved = apply_incident_action(
        incident, action=IncidentAction.PRESERVE_EVIDENCE, actor_id="operator-1",
        expected_version=2, occurred_at=NOW,
    )
    with pytest.raises(ValueError, match="incident_containment_receipt_required"):
        apply_incident_action(
            preserved, action=IncidentAction.MARK_CONTAINED, actor_id="operator-1",
            expected_version=3, occurred_at=NOW,
        )

    verified = replace(preserved, containment_verified=True)
    contained = apply_incident_action(
        verified, action=IncidentAction.MARK_CONTAINED, actor_id="operator-1",
        expected_version=3, occurred_at=NOW,
    )
    with pytest.raises(ValueError, match="incident_recovery_separation_required"):
        apply_incident_action(
            contained, action=IncidentAction.MARK_RECOVERED, actor_id="operator-1",
            expected_version=4, occurred_at=NOW,
        )

    recovered = apply_incident_action(
        contained, action=IncidentAction.MARK_RECOVERED, actor_id="operator-2",
        expected_version=4, occurred_at=NOW,
    )
    reviewed = apply_incident_action(
        recovered, action=IncidentAction.COMPLETE_REVIEW, actor_id="reviewer-1",
        expected_version=5, occurred_at=NOW,
    )
    closed = apply_incident_action(
        reviewed, action=IncidentAction.CLOSE, actor_id="reviewer-2",
        expected_version=6, occurred_at=NOW,
    )
    assert closed.state is IncidentState.CLOSED
    assert closed.version == 7


def test_incident_replay_conflict_and_skipped_states_fail_closed() -> None:
    with pytest.raises(ValueError, match="incident_version_conflict"):
        apply_incident_action(
            _incident(), action=IncidentAction.ACKNOWLEDGE, actor_id="operator-1",
            expected_version=2, occurred_at=NOW,
        )
    with pytest.raises(ValueError, match="incident_transition_invalid"):
        apply_incident_action(
            _incident(), action=IncidentAction.CLOSE, actor_id="operator-1",
            expected_version=1, occurred_at=NOW,
        )


def test_incident_assignment_and_containment_verification_are_explicit() -> None:
    assigned = apply_incident_action(
        _incident(), action=IncidentAction.ASSIGN, actor_id="dispatcher-1",
        expected_version=1, occurred_at=NOW, assignee_id="responder-1",
    )
    acknowledged = apply_incident_action(
        assigned, action=IncidentAction.ACKNOWLEDGE, actor_id="responder-1",
        expected_version=2, occurred_at=NOW,
    )
    preserved = apply_incident_action(
        acknowledged, action=IncidentAction.PRESERVE_EVIDENCE, actor_id="responder-1",
        expected_version=3, occurred_at=NOW,
    )
    verified = apply_incident_action(
        preserved, action=IncidentAction.VERIFY_CONTAINMENT,
        actor_id="containment-verifier-1", expected_version=4, occurred_at=NOW,
    )
    assert verified.assigned_to == "responder-1"
    assert verified.containment_verified is True
