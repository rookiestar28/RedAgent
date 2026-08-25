from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.telemetry_service.slo import (
    Comparison,
    EvaluationState,
    SloObjective,
    SloWindow,
    evaluate_count_slo,
    evaluate_latency_slo,
)


START = datetime(2026, 7, 11, 0, 0, tzinfo=timezone.utc)


def _objective(**overrides) -> SloObjective:
    values = {
        "objective_id": "foundation-api-availability",
        "metric_name": "api_availability_ratio",
        "comparison": Comparison.MIN,
        "threshold_millionths": 999_000,
        "window_seconds": 3600,
        "minimum_samples": 100,
        "error_budget_millionths": 1_000,
    }
    values.update(overrides)
    return SloObjective(**values)


def test_count_slo_reports_unknown_without_minimum_data_and_never_healthy() -> None:
    evaluation = evaluate_count_slo(
        _objective(),
        SloWindow(started_at=START, ended_at=START + timedelta(hours=1), good=9, total=10),
    )
    assert evaluation.state is EvaluationState.UNKNOWN
    assert evaluation.reason_code == "slo_minimum_samples_missing"


def test_count_slo_uses_integer_millionths_and_error_budget_burn() -> None:
    healthy = evaluate_count_slo(
        _objective(),
        SloWindow(started_at=START, ended_at=START + timedelta(hours=1), good=999, total=1000),
    )
    assert healthy.state is EvaluationState.HEALTHY
    assert healthy.observed_millionths == 999_000
    assert healthy.burn_millionths == 1_000_000

    burning = evaluate_count_slo(
        _objective(),
        SloWindow(started_at=START, ended_at=START + timedelta(hours=1), good=990, total=1000),
    )
    assert burning.state is EvaluationState.BREACHED
    assert burning.burn_millionths == 10_000_000


def test_latency_slo_uses_deterministic_nearest_rank_p95() -> None:
    objective = _objective(
        objective_id="foundation-api-p95",
        metric_name="api_request_duration_ms",
        comparison=Comparison.MAX,
        threshold_millionths=300_000_000,
        minimum_samples=20,
        error_budget_millionths=0,
    )
    durations = tuple(range(100, 120))
    evaluation = evaluate_latency_slo(
        objective, durations_ms=durations,
        started_at=START, ended_at=START + timedelta(hours=1), percentile=95,
    )
    assert evaluation.state is EvaluationState.HEALTHY
    assert evaluation.observed_millionths == 118_000_000
    assert evaluation.sample_count == 20


def test_slo_contract_rejects_invalid_windows_and_float_thresholds() -> None:
    with pytest.raises(ValueError, match="slo_threshold_invalid"):
        _objective(threshold_millionths=999.0)
    with pytest.raises(ValueError, match="slo_window_invalid"):
        SloWindow(started_at=START, ended_at=START, good=1, total=1)
