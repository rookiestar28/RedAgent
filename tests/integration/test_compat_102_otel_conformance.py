from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def test_real_sdk_collector_fixed_loopback_sink_redaction_and_hardening() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "otel_conformance.py"), "conformance"],
        cwd=ROOT, text=True, capture_output=True, timeout=120, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["ok"] is True
    assert result["schema"] == "redagent.telemetry/v1"
    assert result["service_name"] == "containment"
    assert result["loopback_receiver"] is True
    assert result["read_only_root"] is True and result["cap_drop"] == ["ALL"]
    assert 0 < result["bounded_receipt_bytes"] <= 64 * 1024
