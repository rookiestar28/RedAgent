from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

from redagent_platform.campaign_service.cli import (
    build_cli_parser,
    build_qualification_call,
    build_status_call,
)


ROOT = Path(__file__).resolve().parents[2]


def test_r123_cli_has_no_human_runtime_id_or_arbitrary_execution_option() -> None:
    parser = build_cli_parser()
    help_text = parser.format_help()
    qualify = parser.parse_args([
        "qualify",
        "--api-base", "http://127.0.0.1:58000",
        "--auth-header-file", ".tmp/r123-auth.json",
        "--objective", "http_posture",
    ])

    assert qualify.command == "qualify"
    for forbidden in (
        "--tenant", "--principal", "--engagement", "--target", "--campaign",
        "--workflow", "--runner", "--adapter", "--url", "--template", "--credential",
        "--lease", "--command", "--idempotency-key",
    ):
        assert forbidden not in help_text


def test_r123_cli_generates_transport_idempotency_and_fixed_fixture_payload() -> None:
    call = build_qualification_call(
        api_base="http://localhost:58000",
        auth_headers={"Authorization": "Bearer redacted"},
        objective_kind="security_header_assertion",
        require_corroboration=True,
        idempotency_factory=lambda: "generated-request-token",
    )

    assert call.method == "POST"
    assert call.url == "http://localhost:58000/api/v1/internal/r123/qualification"
    assert call.headers["Idempotency-Key"] == "generated-request-token"
    assert call.headers["X-RedAgent-Policy-Reference"] == "policy-r123-owned-loopback"
    assert call.payload == {
        "fixture_id": "owned-loopback-http-first-slice",
        "objective_kind": "security_header_assertion",
        "header_code": "x-content-type-options",
        "require_corroboration": True,
        "risk_profile": "tier1_passive",
    }
    assert not {
        "tenant_id", "principal_id", "engagement_id", "target_id", "campaign_id",
        "workflow_id", "runner_id", "adapter_id", "url", "command",
    }.intersection(call.payload)


def test_r123_cli_status_is_read_only_and_control_plane_endpoint_is_loopback_only() -> None:
    status = build_status_call(
        api_base="http://127.0.0.1:58000/",
        auth_headers={"Cookie": "redacted"},
    )
    assert status.method == "GET"
    assert status.url == "http://127.0.0.1:58000/api/v1/internal/r123/status"
    assert status.payload is None
    assert "Idempotency-Key" not in status.headers

    with pytest.raises(ValueError, match="r123_cli_api_loopback_required"):
        build_status_call(
            api_base="https://public.example/api",
            auth_headers={"Authorization": "Bearer redacted"},
        )


def test_r123_cli_help_has_no_network_or_secret_file_read_side_effect() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "compat_123_campaign.py"), "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "qualify" in completed.stdout
    assert "status" in completed.stdout
