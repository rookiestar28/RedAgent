from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def test_real_restricted_synthetic_image_supply_chain_tamper_and_cleanup() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "runner_conformance.py"), "conformance"],
        cwd=ROOT, text=True, capture_output=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["ok"] is True
    assert result["signature_verified"] is True
    assert result["tamper_rejected"] is True
    assert result["runtime"] == "runc-local-conformance"
    assert result["network_mode"] == "none"
    assert result["read_only_root"] is True
    assert result["privileged"] is False
    assert result["cap_drop"] == ["ALL"]
    assert result["user"] == "65532:65532"
    assert result["pids_limit"] == 32 and result["memory_bytes"] == 134_217_728
    assert result["synthetic_output"] == {"result": "synthetic-ok", "uid": 65532, "workdir": "writable"}
    assert result["container_removed"] is True
