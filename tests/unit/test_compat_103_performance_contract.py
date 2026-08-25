from __future__ import annotations

from pathlib import Path

import json

from scripts.compat_103_performance import metric, write_checkpoint


ROOT = Path(__file__).resolve().parents[2]


def test_metric_comparisons_are_objective_and_performance_workloads_are_bounded() -> None:
    assert metric("latency", 300, 300, "lte", "ms")["passed"] is True
    assert metric("throughput", 19.9, 20, "gte", "rps")["passed"] is False
    source = (ROOT / "scripts/compat_103_performance.py").read_text(encoding="utf-8")
    for bound in ("total: int = 1000", "concurrency: int = 50", "ThreadPoolExecutor(max_workers=10)"):
        assert bound in source
    assert 'default=600' in source
    assert '1 <= args.idle_seconds <= 600' in source
    assert 'target.is_relative_to(ROOT.resolve())' in source
    assert 'measurement_method="time_series_mean_over_full_idle_window"' in source
    assert "raw_samples=cpu_samples" in source
    assert '"reference_vcpu": 4' in source
    assert "elapsed_seconds=elapsed" in source
    assert "concurrency=concurrency" in source
    assert '"previous_attempts": previous_attempts' in source


def test_performance_checkpoint_is_atomic_and_does_not_claim_partial_pass(tmp_path: Path) -> None:
    target = tmp_path / "performance.json"
    write_checkpoint(
        target,
        status="in_progress",
        measured_at="2026-07-12T00:00:00+00:00",
        environment={"reference_vcpu": 4},
        measurements=[metric("startup", 1, 60, "lte", "seconds")],
        previous_attempts=[],
    )

    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["status"] == "in_progress"
    assert payload["passed"] is False
    assert not target.with_suffix(".json.tmp").exists()
