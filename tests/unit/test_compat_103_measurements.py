from __future__ import annotations

import math

import pytest

from redagent_platform.lab_service.measurements import QualificationMeasurement


def test_measurement_uses_nearest_rank_p95_and_integer_millionths() -> None:
    measurement = QualificationMeasurement(
        metric_id="api-read-p95", comparison="lte", samples=tuple(float(value) for value in range(1, 101)),
        threshold=95, unit="milliseconds",
    )
    assert measurement.p95 == 95
    assert measurement.passed is True
    assert measurement.receipt() == {
        "metric_id": "api-read-p95", "comparison": "lte",
        "observed_millionths": 95_000_000, "threshold_millionths": 95_000_000,
        "unit": "milliseconds", "sample_count": 100, "p95_millionths": 95_000_000,
        "result_state": "passed",
    }


def test_measurement_threshold_failure_and_invalid_input_fail_closed() -> None:
    assert QualificationMeasurement(
        metric_id="throughput", comparison="gte", samples=(19.9,), threshold=20, unit="actions_per_second",
    ).passed is False
    for samples in ((), (-1.0,), (math.inf,), (math.nan,)):
        with pytest.raises(ValueError, match="qualification_measurement"):
            QualificationMeasurement(metric_id="metric", comparison="lte", samples=samples, threshold=1, unit="ms")
