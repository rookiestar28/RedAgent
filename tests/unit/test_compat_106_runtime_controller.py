from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/compat_106_api_diff.py"
LOCK = ROOT / "config/r106-api-runtime.json"


def test_runtime_lock_is_closed_content_addressed_and_non_production() -> None:
    value = json.loads(LOCK.read_text(encoding="utf-8"))
    assert value["schema"] == "redagent.r106-runtime-lock/v1"
    assert value["schemathesis_version"] == "4.22.4"
    assert value["critical_vulnerability_count"] == 0
    for key in ("external_target_allowed", "arbitrary_transport_allowed", "runtime_update_allowed",
                "production_qualified"):
        assert value[key] is False
    for key in ("worker_image_id", "gateway_image_id", "target_image_id", "python_base_digest"):
        assert value[key].startswith("sha256:") and len(value[key]) == 71


def test_controller_is_confirmation_gated_and_exposes_no_native_transport_input() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--confirm-r106-local-lab" in source
    assert 'choices=("build", "qualify", "cleanup")' in source
    for unsafe in ("--target", "--url", "--spec", "--request", "--header", "--cookie",
                   "--token", "--credential", "--body", "--flags", "--plugin"):
        assert unsafe not in source


def test_controller_enforces_dual_internal_network_and_owned_cleanup() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    for value in (
        "redagent-r106-worker", "redagent-r106-gateway", "redagent-r106-target",
        "redagent-r106-worker-gateway", "redagent-r106-gateway-target",
            "redagent.owner=r106", "--internal", "--read-only", "--cap-drop", "ALL",
        "no-new-privileges", "--pids-limit", "--memory", "--cpus",
    ):
        assert value in source
    assert "PortBindings" in source
    assert "ownership_mismatch" in source


def test_controller_verifies_promotion_and_business_security_oracles() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "verify_api_differential_promotion" in source
    for value in (
        '"bola"', '"valid_negative"', '"cross_tenant"', '"bfla"', '"bopla"',
        '"anonymous"', '"expired"', '"revoked"', '"ownership_transition"',
        '"credential_material_present"',
        '"external_target_contacts": 0', '"SIGTERM"', '"docker", "kill"',
    ):
        assert value in source
    assert "unlink(missing_ok=True)" in source
