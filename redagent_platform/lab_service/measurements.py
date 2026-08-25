"""Deterministic compat_103 qualification measurement calculations."""

from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True, kw_only=True)
class QualificationMeasurement:
    metric_id: str
    comparison: str
    samples: tuple[float, ...]
    threshold: float
    unit: str

    def __post_init__(self) -> None:
        if not self.metric_id or not self.unit:
            raise ValueError("qualification_measurement_field_required")
        if self.comparison not in {"lte", "gte"}:
            raise ValueError("qualification_measurement_comparison_invalid")
        if not self.samples or len(self.samples) > 100_000:
            raise ValueError("qualification_measurement_samples_invalid")
        if any(not math.isfinite(value) or value < 0 for value in (*self.samples, self.threshold)):
            raise ValueError("qualification_measurement_value_invalid")

    @property
    def observed(self) -> float:
        return self.p95 if len(self.samples) > 1 else self.samples[0]

    @property
    def p95(self) -> float:
        ordered = sorted(self.samples)
        return ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]

    @property
    def passed(self) -> bool:
        return self.observed <= self.threshold if self.comparison == "lte" else self.observed >= self.threshold

    def receipt(self) -> dict[str, object]:
        return {
            "metric_id": self.metric_id, "comparison": self.comparison,
            "observed_millionths": round(self.observed * 1_000_000),
            "threshold_millionths": round(self.threshold * 1_000_000),
            "unit": self.unit, "sample_count": len(self.samples),
            "p95_millionths": round(self.p95 * 1_000_000),
            "result_state": "passed" if self.passed else "failed",
        }
