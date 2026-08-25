"""Deterministic integer/fraction-only SLO and multi-window burn evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from fractions import Fraction


_MILLION = 1_000_000


class Comparison(str, Enum):
    MIN = "min"
    MAX = "max"


class EvaluationState(str, Enum):
    HEALTHY = "healthy"
    BREACHED = "breached"
    UNKNOWN = "unknown"


class SloEvaluationState(str, Enum):
    HEALTHY = "healthy"
    BREACHING = "breaching"
    UNKNOWN = "unknown"


class BurnAlertState(str, Enum):
    CLEAR = "clear"
    FIRING = "firing"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SloObjective:
    objective_id: str
    target_basis_points: int | None = None
    window_seconds: int = 3600
    threshold_ms: int | None = None
    metric_name: str | None = None
    comparison: Comparison | None = None
    threshold_millionths: int | None = None
    minimum_samples: int = 1
    error_budget_millionths: int | None = None

    def __post_init__(self) -> None:
        if not _code(self.objective_id) or not _positive_int(self.window_seconds):
            raise ValueError("slo_identity_invalid")
        if self.target_basis_points is not None:
            if not isinstance(self.target_basis_points, int) or isinstance(self.target_basis_points, bool) or not 0 <= self.target_basis_points <= 10_000:
                raise ValueError("slo_target_invalid")
            if self.threshold_ms is not None and not _nonnegative_int(self.threshold_ms):
                raise ValueError("slo_threshold_invalid")
            return
        if not _code(self.metric_name) or not isinstance(self.comparison, Comparison):
            raise ValueError("slo_metric_config_invalid")
        if not _nonnegative_int(self.threshold_millionths):
            raise ValueError("slo_threshold_invalid")
        if not _positive_int(self.minimum_samples) or not _nonnegative_int(self.error_budget_millionths):
            raise ValueError("slo_window_config_invalid")


@dataclass(frozen=True, kw_only=True)
class SloWindow:
    started_at: datetime
    ended_at: datetime
    good: int
    total: int

    def __post_init__(self) -> None:
        if not _aware(self.started_at) or not _aware(self.ended_at) or self.ended_at <= self.started_at:
            raise ValueError("slo_window_invalid")
        if not _nonnegative_int(self.good) or not _nonnegative_int(self.total) or self.good > self.total:
            raise ValueError("slo_counts_invalid")


@dataclass(frozen=True, kw_only=True)
class SloEvaluation:
    objective_id: str
    state: EvaluationState
    reason_code: str
    observed_millionths: int | None
    threshold_millionths: int
    burn_millionths: int | None
    sample_count: int
    started_at: datetime
    ended_at: datetime


@dataclass(frozen=True, kw_only=True)
class RatioEvaluation:
    objective_id: str
    state: SloEvaluationState
    total: int
    bad: int
    missing: int
    error_budget_consumed: Fraction | None


def evaluate_ratio_window(
    objective: SloObjective, *, total: int, bad: int, missing: int,
) -> RatioEvaluation:
    _require_ratio_objective(objective)
    if not _nonnegative_int(total) or not _nonnegative_int(bad) or not _nonnegative_int(missing) or bad > total:
        raise ValueError("slo_counts_invalid")
    if total == 0 or missing > 0:
        return RatioEvaluation(
            objective_id=objective.objective_id, state=SloEvaluationState.UNKNOWN,
            total=total, bad=bad, missing=missing, error_budget_consumed=None,
        )
    allowed_bad_basis_points = 10_000 - int(objective.target_basis_points or 0)
    if allowed_bad_basis_points == 0:
        consumed = Fraction(0, 1) if bad == 0 else None
        state = SloEvaluationState.HEALTHY if bad == 0 else SloEvaluationState.BREACHING
    else:
        consumed = Fraction(bad * 10_000, total * allowed_bad_basis_points)
        state = SloEvaluationState.HEALTHY if consumed <= 1 else SloEvaluationState.BREACHING
    return RatioEvaluation(
        objective_id=objective.objective_id, state=state, total=total,
        bad=bad, missing=missing, error_budget_consumed=consumed,
    )


def evaluate_stop_window(
    objective: SloObjective, *, durations_ms: tuple[int, ...], missing: int,
) -> RatioEvaluation:
    _require_ratio_objective(objective)
    if objective.threshold_ms is None or any(not _nonnegative_int(item) for item in durations_ms):
        raise ValueError("slo_stop_window_invalid")
    bad = sum(item > objective.threshold_ms for item in durations_ms)
    return evaluate_ratio_window(objective, total=len(durations_ms), bad=bad, missing=missing)


def evaluate_multi_window_burn(
    fast: RatioEvaluation, slow: RatioEvaluation, *, threshold: Fraction,
) -> BurnAlertState:
    if threshold <= 0:
        raise ValueError("slo_burn_threshold_invalid")
    if fast.error_budget_consumed is None or slow.error_budget_consumed is None:
        return BurnAlertState.UNKNOWN
    if fast.error_budget_consumed >= threshold and slow.error_budget_consumed >= threshold:
        return BurnAlertState.FIRING
    return BurnAlertState.CLEAR


def evaluate_count_slo(objective: SloObjective, window: SloWindow) -> SloEvaluation:
    if objective.target_basis_points is not None:
        raise ValueError("slo_millionths_objective_required")
    if window.total < objective.minimum_samples:
        return _unknown(objective, window.started_at, window.ended_at, window.total)
    observed = window.good * _MILLION // window.total
    healthy = _meets(objective, observed)
    bad = window.total - window.good
    burn = None
    if int(objective.error_budget_millionths or 0) > 0:
        burn = bad * _MILLION * _MILLION // (window.total * int(objective.error_budget_millionths or 0))
    return SloEvaluation(
        objective_id=objective.objective_id,
        state=EvaluationState.HEALTHY if healthy else EvaluationState.BREACHED,
        reason_code="slo_objective_met" if healthy else "slo_objective_breached",
        observed_millionths=observed,
        threshold_millionths=int(objective.threshold_millionths or 0),
        burn_millionths=burn,
        sample_count=window.total,
        started_at=window.started_at,
        ended_at=window.ended_at,
    )


def evaluate_latency_slo(
    objective: SloObjective,
    *,
    durations_ms: tuple[int, ...],
    started_at: datetime,
    ended_at: datetime,
    percentile: int,
) -> SloEvaluation:
    if objective.target_basis_points is not None:
        raise ValueError("slo_millionths_objective_required")
    if not _aware(started_at) or not _aware(ended_at) or ended_at <= started_at:
        raise ValueError("slo_window_invalid")
    if not isinstance(percentile, int) or not 1 <= percentile <= 100:
        raise ValueError("slo_percentile_invalid")
    if any(not _nonnegative_int(item) for item in durations_ms):
        raise ValueError("slo_duration_invalid")
    if len(durations_ms) < objective.minimum_samples:
        return _unknown(objective, started_at, ended_at, len(durations_ms))
    ordered = sorted(durations_ms)
    rank = (percentile * len(ordered) + 99) // 100
    observed = ordered[rank - 1] * _MILLION
    healthy = _meets(objective, observed)
    return SloEvaluation(
        objective_id=objective.objective_id,
        state=EvaluationState.HEALTHY if healthy else EvaluationState.BREACHED,
        reason_code="slo_objective_met" if healthy else "slo_objective_breached",
        observed_millionths=observed,
        threshold_millionths=int(objective.threshold_millionths or 0),
        burn_millionths=None,
        sample_count=len(ordered),
        started_at=started_at,
        ended_at=ended_at,
    )


def _unknown(objective: SloObjective, start: datetime, end: datetime, samples: int) -> SloEvaluation:
    return SloEvaluation(
        objective_id=objective.objective_id, state=EvaluationState.UNKNOWN,
        reason_code="slo_minimum_samples_missing", observed_millionths=None,
        threshold_millionths=int(objective.threshold_millionths or 0),
        burn_millionths=None, sample_count=samples, started_at=start, ended_at=end,
    )


def _meets(objective: SloObjective, observed: int) -> bool:
    if objective.comparison is Comparison.MIN:
        return observed >= int(objective.threshold_millionths or 0)
    return observed <= int(objective.threshold_millionths or 0)


def _require_ratio_objective(objective: SloObjective) -> None:
    if objective.target_basis_points is None:
        raise ValueError("slo_basis_points_objective_required")


def _code(value: object) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 100 and all(
        char.islower() or char.isdigit() or char in "_-" for char in value
    )


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
