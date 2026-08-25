from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from redagent_platform import domain, evidence_chain
from redagent_platform.skill_command_contract import evaluate_skill_assessment_request
from redagent_platform.skill_invocation import SkillInvocationRecordingError, record_skill_invocation_artifacts


ROOT = Path(__file__).resolve().parents[2]


def request_fixture(**overrides: Any) -> dict[str, Any]:
    request: dict[str, Any] = {
        "request_id": "req-r051",
        "skill_client": "codex",
        "skill_version": "redagent-operator/0.1",
        "mode": "dry_run",
        "assessment_type": "passive_metadata",
        "requested_at": "2026-07-09T10:30:00+08:00",
        "organization_id": "org-r051",
        "engagement_id": "eng-r051",
        "owner_label": "Owner",
        "approver_label": "Approver",
        "operator_label": "Codex",
        "authorization_label": "compat_051 local unit authorization",
        "roe_status": "approved",
        "authorization_confirmed": True,
        "authorized_targets": [{"target_type": "domain", "value": "example.test"}],
        "requested_targets": [{"target_type": "domain", "value": "example.test"}],
        "excluded_targets": [{"target_type": "domain", "value": "admin.example.test"}],
        "environment": "staging",
        "sensitivity": "metadata_only",
        "allowed_categories": ["passive_metadata"],
        "forbidden_actions": ["exploit", "brute_force", "fuzzing"],
        "window": {
            "start": "2026-07-09T10:00:00+08:00",
            "end": "2026-07-09T11:00:00+08:00",
        },
        "limits": {
            "rate_limit_per_second": 1,
            "max_concurrency": 1,
            "max_interactions": 50,
            "timeout_seconds": 900,
        },
        "credential_requirement": "not_required",
        "output_paths": {
            "command_log_path": ".local/validation/automated-runs/req-r051-COMMAND_LOG.md",
            "evidence_dir": ".tmp/skill-runs/req-r051",
            "report_path": "reports/assessments/req-r051-report.md",
        },
        "emergency_stop_method": "email",
        "data_handling": {
            "redaction_required": True,
            "retention_class": "metadata",
            "export_allowed": False,
        },
        "user_confirmation": {
            "confirmed": False,
        },
    }
    request.update(overrides)
    return request


def test_allowed_dry_run_records_evidence_report_and_ui_preview(tmp_path: Path) -> None:
    request = request_fixture()
    decision = evaluate_skill_assessment_request(request)

    artifacts = record_skill_invocation_artifacts(
        request,
        decision.to_jsonable(),
        repo_root=tmp_path,
        ui_log_path=".tmp/ui-terminal.log",
    )

    command_log = tmp_path / artifacts.command_log_path
    report_path = tmp_path / artifacts.report_path
    ui_log = tmp_path / ".tmp" / "ui-terminal.log"
    assert command_log.exists()
    assert report_path.exists()
    assert ui_log.exists()
    assert (tmp_path / artifacts.evidence_dir / "decision.json").exists()
    assert (tmp_path / artifacts.evidence_dir / "artifact-index.json").exists()

    assert artifacts.evidence_record.kind is domain.EvidenceKind.COMMAND_LOG
    assert artifacts.evidence_record.redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert evidence_chain.verify_evidence_record(artifacts.evidence_record)
    assert artifacts.evidence_metadata["operator_label"] == "Codex"
    assert artifacts.evidence_metadata["skill_client"] == "codex"
    assert artifacts.evidence_metadata["skill_version"] == "redagent-operator/0.1"
    assert artifacts.evidence_metadata["command_contract_version"].startswith("r047.")
    assert artifacts.evidence_metadata["redaction_status"] == "redacted"
    assert artifacts.report_package.report_hash
    assert artifacts.artifact_hashes["command_log"]

    rendered_report = report_path.read_text(encoding="utf-8")
    assert "No confirmed findings are present" in rendered_report
    assert "No target-facing assessment" in rendered_report
    assert "exploitability" not in rendered_report.lower()

    preview = ui_log.read_text(encoding="utf-8")
    assert "no browser execution" in preview
    assert "no target interaction" in preview
    assert "run " not in preview.lower()


def test_cli_record_artifacts_writes_json_and_local_artifacts(tmp_path: Path) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request_fixture()), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "redagent_skill_assess.py"),
            "--request",
            str(request_path),
            "--record-artifacts",
            "--artifact-root",
            str(tmp_path),
            "--ui-log-path",
            ".tmp/ui-terminal.log",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    output = json.loads(completed.stdout)
    assert output["decision"] == "allow"
    assert output["artifact_recording"]["status"] == "recorded"
    assert (tmp_path / output["artifact_recording"]["paths"]["command_log_path"]).exists()
    assert (tmp_path / output["artifact_recording"]["paths"]["report_path"]).exists()
    assert completed.stderr.startswith("allow:dry_run_ready")


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"authorization_confirmed": False}, "authorization_not_confirmed"),
        (
            {
                "mode": "execute",
                "user_confirmation": {
                    "confirmed": True,
                    "confirmed_by": "Codex",
                    "confirmed_at": "2026-07-09T10:29:00+08:00",
                },
            },
            "policy_decision_required",
        ),
        (
            {
                "output_paths": {
                    "command_log_path": "../outside.md",
                    "evidence_dir": ".tmp/skill-runs/req-r051",
                    "report_path": "reports/assessments/req-r051-report.md",
                }
            },
            "invalid_command_log_path",
        ),
        (
            {
                "output_paths": {
                    "command_log_path": ".local/validation/automated-runs/req-r051-COMMAND_LOG.md",
                    "evidence_dir": ".tmp/skill-runs/req-r051",
                    "report_path": "../outside-report.md",
                }
            },
            "invalid_report_path",
        ),
    ],
)
def test_cli_denials_do_not_create_artifacts(tmp_path: Path, overrides: dict[str, Any], reason: str) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request_fixture(**overrides)), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "redagent_skill_assess.py"),
            "--request",
            str(request_path),
            "--record-artifacts",
            "--artifact-root",
            str(tmp_path),
            "--ui-log-path",
            ".tmp/ui-terminal.log",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    output = json.loads(completed.stdout)
    assert completed.returncode == 2
    assert output["reason"] == reason
    assert output["artifact_recording"] == {"status": "skipped", "reason": "decision_not_allowed"}
    assert not (tmp_path / ".local").exists()
    assert not (tmp_path / "reports").exists()
    assert not (tmp_path / ".tmp" / "ui-terminal.log").exists()


def test_direct_recording_rejects_denied_decision(tmp_path: Path) -> None:
    request = request_fixture(authorization_confirmed=False)
    decision = evaluate_skill_assessment_request(request)

    with pytest.raises(SkillInvocationRecordingError, match="decision_not_allowed"):
        record_skill_invocation_artifacts(request, decision.to_jsonable(), repo_root=tmp_path)
