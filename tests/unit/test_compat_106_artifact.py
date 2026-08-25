from __future__ import annotations

import json
from pathlib import Path

import pytest

from redagent_platform.api_differential_service.artifact import verify_schemathesis_artifact


ROOT = Path(__file__).resolve().parents[2]


def test_exact_schemathesis_lock_review_and_safe_feature_receipt_pass() -> None:
    receipt = verify_schemathesis_artifact(ROOT)
    assert receipt["version"] == "4.22.4"
    assert receipt["locked_component_count"] == 73
    assert receipt["production_qualified"] is False


def test_lock_or_wheel_tamper_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "config").mkdir(parents=True)
    for relative in (
        "config/r106-schemathesis-runtime.json",
        "config/python-runtime-dependencies.json",
        "requirements-runtime.lock",
    ):
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    lock = workspace / "requirements-runtime.lock"
    lock.write_text(lock.read_text(encoding="utf-8").replace("schemathesis==4.22.4", "schemathesis==4.22.3"), encoding="utf-8")
    with pytest.raises(ValueError, match="api_engine_artifact_drift"):
        verify_schemathesis_artifact(workspace)

    wheel = tmp_path / "schemathesis.whl"
    wheel.write_bytes(b"not-the-wheel")
    with pytest.raises(ValueError, match="api_engine_wheel_mismatch"):
        verify_schemathesis_artifact(ROOT, wheel_path=wheel)
