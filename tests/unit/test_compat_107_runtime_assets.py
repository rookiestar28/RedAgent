from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "config/r107-network-runtime.json"
QUALIFICATION = ROOT / "runtime-assets/attestations/260711-R107_NETWORK_QUALIFICATION.json"


def test_runtime_lock_binds_all_repo_owned_sources_images_and_safety_state() -> None:
    value = json.loads(LOCK.read_text(encoding="utf-8"))
    assert value["schema"] == "redagent.r107-runtime-lock/v1"
    assert value["critical_vulnerability_count"] == 0
    assert value["external_scanner_present"] is False
    assert value["external_target_allowed"] is False
    assert value["raw_socket_allowed"] is False
    assert value["runtime_update_allowed"] is False
    assert value["production_qualified"] is False
    for component in ("target", "gateway", "worker"):
        assert value[f"{component}_image_id"].startswith("sha256:")
        dockerfile = ROOT / f"containers/r107-{component}/Dockerfile"
        source = ROOT / f"containers/r107-{component}/" / (
            "fixture_server.py" if component == "target" else
            "gateway_server.py" if component == "gateway" else "worker.py"
        )
        assert value[f"{component}_dockerfile_sha256"] == hashlib.sha256(dockerfile.read_bytes()).hexdigest()
        assert value[f"{component}_source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()


def test_runtime_controller_fails_closed_without_literal_confirmation() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/compat_107_network_lab.py"), "qualify"],
        cwd=ROOT, check=False, capture_output=True, text=True,
    )
    assert completed.returncode == 2
    assert "r107_local_lab_confirmation_required" in completed.stderr


def test_runtime_lock_loader_rejects_source_tamper_contract() -> None:
    spec = importlib.util.spec_from_file_location("r107_network_lab", ROOT / "scripts/compat_107_network_lab.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    value = module.runtime_lock(require_images=False)
    assert value["profile_id"] == "tcp-connect-discovery-v1"


def test_live_qualification_proves_gateway_first_cooperative_stop_and_zero_residual() -> None:
    value = json.loads(QUALIFICATION.read_text(encoding="utf-8"))
    assert value["passed"] is True
    assert value["gateway_blocked_before_worker_stop"] is True
    assert value["cooperative_stop_acknowledged"] is True
    assert value["forced_termination"] is False
    assert value["residual_container_count"] == 0
    assert value["residual_network_count"] == 0
