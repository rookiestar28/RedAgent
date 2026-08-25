from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "config" / "r104-zap-runtime.json"
LIFECYCLE = ROOT / "scripts" / "compat_104_zap.py"
TARGET = ROOT / "containers" / "r104-target" / "fixture_server.py"
GATEWAY = ROOT / "containers" / "r104-gateway" / "gateway_server.py"


def test_runtime_lock_pins_zap_and_owned_image_supply_chain() -> None:
    value = json.loads(LOCK.read_text(encoding="utf-8"))
    assert value["schema"] == "redagent.r104-runtime-lock/v1"
    assert value["platform"] == "linux/amd64"
    assert value["zap_upstream_image"] == "ghcr.io/zaproxy/zaproxy:bare"
    assert value["zap_upstream_platform_digest"] == "sha256:627781353231d056d5a6305ec1f2092f54735cc654915f533d2e8d5d9d41bcb2"
    assert value["zap_runtime_image_id"] == "sha256:ccd16df57aed6724abdafe71b1077099c2b992d0945359d32d84f0939186b0c3"
    assert value["chromium_version"] == "149.0.7827.53-r0"
    assert value["zap_addon_inventory_count"] == 48
    assert len(value["zap_addon_inventory_sha256"]) == 64
    assert value["target_source_sha256"] and value["gateway_source_sha256"]
    assert value["target_image_id"].startswith("sha256:")
    assert value["gateway_image_id"].startswith("sha256:")
    assert value["runtime_update_allowed"] is False
    assert value["external_target_allowed"] is False


def test_fixture_exposes_only_reviewed_benign_qualification_routes() -> None:
    source = TARGET.read_text(encoding="utf-8")
    for path in (
        "/health/ready", "/passive/missing-header", "/auth/protected",
        "/browser/start", "/browser/client-route", "/active/reflected-input",
    ):
        assert path in source
    assert "X-Content-Type-Options" not in source
    assert "ThreadingHTTPServer((\"0.0.0.0\", 8080)" in source
    assert "urllib.request" not in source and "import requests" not in source


def test_gateway_is_a_fixed_forwarder_with_no_connect_or_redirect_following() -> None:
    source = GATEWAY.read_text(encoding="utf-8")
    assert 'UPSTREAM_HOST = "redagent-r104-target"' in source
    assert "def do_CONNECT" in source
    assert "zap_gateway_connect_denied" in source
    assert "NoRedirect" in source
    assert "MAX_RESPONSE_BYTES" in source
    assert "_ACTIVE_REQUESTS" in source and "zap_gateway_concurrency_exceeded" in source
    assert "zap_gateway_body_denied" in source
    assert "X-RedAgent-Lab-Auth" in source
    assert "sys.argv" not in source and "subprocess" not in source


def test_lifecycle_cli_has_closed_actions_confirmation_and_exact_owned_resources() -> None:
    source = LIFECYCLE.read_text(encoding="utf-8")
    requalification_source = (ROOT / "scripts" / "compat_104_requalify.py").read_text(encoding="utf-8")
    for action in ("validate", "pull", "build", "start", "status", "compile", "run", "cancel", "qualify", "stop", "reset"):
        assert f'"{action}"' in source
    assert "--confirm-r104-local-lab" in source
    assert "redagent.owner=r104" in source
    assert "--network=none" in requalification_source or '"--network", "none"' in requalification_source
    assert '"--publish"' not in source and '"-p"' not in source
    assert "docker system prune" not in source
    assert "ghcr.io/zaproxy/zaproxy:2.17.0" not in source
    assert "sensitive_files_remaining" in source
    assert "_erase_sensitive_files" in source
