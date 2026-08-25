from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from redagent_platform.skill_command_contract import evaluate_skill_assessment_request, load_request_json


def valid_request(**overrides: Any) -> dict[str, Any]:
    request: dict[str, Any] = {
        "request_id": "req-047",
        "skill_client": "codex",
        "skill_version": "redagent-operator/0.1",
        "mode": "dry_run",
        "assessment_type": "passive_metadata",
        "requested_at": "2026-07-09T01:30:00+08:00",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "owner_label": "Ray Chiu",
        "approver_label": "Ray Chiu",
        "operator_label": "Codex",
        "authorization_label": "compat_047 test authorization",
        "roe_status": "approved",
        "authorization_confirmed": True,
        "authorized_targets": [{"target_type": "domain", "value": "agentique.io"}],
        "requested_targets": [{"target_type": "domain", "value": "agentique.io"}],
        "excluded_targets": [{"target_type": "domain", "value": "admin.agentique.io"}],
        "environment": "staging",
        "sensitivity": "metadata_only",
        "allowed_categories": ["passive_metadata"],
        "forbidden_actions": ["exploit", "brute_force", "fuzzing"],
        "window": {
            "start": "2026-07-09T01:00:00+08:00",
            "end": "2026-07-09T02:00:00+08:00",
        },
        "limits": {
            "rate_limit_per_second": 1,
            "max_concurrency": 1,
            "max_interactions": 50,
            "timeout_seconds": 900,
        },
        "credential_requirement": "not_required",
        "output_paths": {
            "command_log_path": ".local/validation/automated-runs/req-047-COMMAND_LOG.md",
            "evidence_dir": ".tmp/skill-runs/req-047",
            "report_path": "reports/assessments/req-047-report.md",
        },
        "emergency_stop_method": "email",
        "data_handling": {
            "redaction_required": True,
            "retention_class": "metadata",
            "export_allowed": False,
        },
        "user_confirmation": {
            "confirmed": True,
            "confirmed_by": "Ray Chiu",
            "confirmed_at": "2026-07-09T01:29:00+08:00",
        },
        "policy_decision": {
            "decision_id": "pd-047",
            "outcome": "allow",
            "expires_at": "2026-07-09T02:00:00+08:00",
        },
    }
    request.update(overrides)
    return request


def test_dry_run_success_defaults_without_delegate() -> None:
    request = valid_request()
    request.pop("policy_decision")
    request["user_confirmation"] = {"confirmed": False}

    decision = evaluate_skill_assessment_request(request)
    output = decision.to_jsonable()

    assert decision.allowed
    assert output["mode"] == "dry_run"
    assert output["reason"] == "dry_run_ready"
    assert output["delegated"] is False
    assert output["next_action"] == "ready_for_final_confirmation"
    assert output["evidence"]["command_log_path"].startswith(".local/validation/")


def test_missing_authorization_fails_closed() -> None:
    decision = evaluate_skill_assessment_request(valid_request(authorization_confirmed=False))

    assert not decision.allowed
    assert decision.reason == "authorization_not_confirmed"


def test_out_of_scope_target_fails_closed() -> None:
    request = valid_request(requested_targets=[{"target_type": "domain", "value": "api.agentique.io"}])

    decision = evaluate_skill_assessment_request(request)

    assert not decision.allowed
    assert decision.reason == "target_not_in_allowlist"


def test_excluded_target_fails_closed() -> None:
    request = valid_request(
        authorized_targets=[
            {"target_type": "domain", "value": "agentique.io"},
            {"target_type": "domain", "value": "admin.agentique.io"},
        ],
        requested_targets=[{"target_type": "domain", "value": "admin.agentique.io"}],
    )

    decision = evaluate_skill_assessment_request(request)

    assert not decision.allowed
    assert decision.reason == "target_forbidden"


def test_expired_window_fails_closed() -> None:
    request = valid_request(requested_at="2026-07-09T03:00:00+08:00")

    decision = evaluate_skill_assessment_request(request)

    assert not decision.allowed
    assert decision.reason == "outside_time_window"


def test_unsafe_mode_fails_closed() -> None:
    decision = evaluate_skill_assessment_request(valid_request(mode="autonomous_attack"))

    assert not decision.allowed
    assert decision.reason == "unsupported_mode"


def test_malformed_json_returns_structured_denial() -> None:
    request, parse_error = load_request_json("{not-json")

    assert request is None
    assert parse_error is not None
    assert parse_error.to_jsonable()["decision"] == "deny"
    assert parse_error.reason == "malformed_json"


def test_loader_accepts_utf8_bom_from_windows_set_content() -> None:
    request, parse_error = load_request_json("\ufeff" + json.dumps(valid_request()))

    assert parse_error is None
    assert request is not None
    assert request["request_id"] == "req-047"


def test_evidence_path_failure_blocks_request() -> None:
    request = valid_request(
        output_paths={
            "command_log_path": "../outside.md",
            "evidence_dir": ".tmp/skill-runs/req-047",
            "report_path": "reports/assessments/req-047-report.md",
        }
    )

    decision = evaluate_skill_assessment_request(request)

    assert not decision.allowed
    assert decision.reason == "invalid_command_log_path"


def test_execute_requires_final_confirmation() -> None:
    request = valid_request(mode="execute", user_confirmation={"confirmed": False})

    decision = evaluate_skill_assessment_request(request)

    assert not decision.allowed
    assert decision.reason == "confirmation_required"


def test_execute_requires_current_policy_decision() -> None:
    request = valid_request(mode="execute")
    request.pop("policy_decision")

    decision = evaluate_skill_assessment_request(request)

    assert not decision.allowed
    assert decision.reason == "policy_decision_required"


def test_approved_wrapper_delegation_uses_fake_delegate_only() -> None:
    captured: dict[str, Any] = {}

    def fake_delegate(payload: dict[str, Any]) -> dict[str, Any]:
        captured.update(payload)
        return {"status": "accepted", "run_id": "fake-run"}

    decision = evaluate_skill_assessment_request(valid_request(mode="execute"), delegate=fake_delegate)
    output = decision.to_jsonable()

    assert decision.allowed
    assert output["reason"] == "delegate_completed"
    assert output["delegated"] is True
    assert output["delegate_result"] == {"status": "accepted", "run_id": "fake-run"}
    assert captured["wrapper"] == "authorized_web_assessment"
    assert captured["wrapper_mode"] == "passive"
    assert captured["targets"] == ["agentique.io"]
    assert captured["dry_run"] is False


def test_cli_stdout_is_json_and_diagnostics_stay_on_stderr(tmp_path: Path) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(valid_request()), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "scripts/redagent_skill_assess.py", "--request", str(request_path)],
        check=True,
        capture_output=True,
        text=True,
    )

    output = json.loads(completed.stdout)
    assert output["decision"] == "allow"
    assert output["reason"] == "dry_run_ready"
    assert completed.stderr.startswith("allow:dry_run_ready")
