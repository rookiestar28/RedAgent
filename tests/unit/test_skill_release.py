from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys

from redagent_platform.skill_release import (
    build_skill_release_manifest,
    validate_skill_release_manifest,
)


ROOT = Path(__file__).resolve().parents[2]


def test_release_manifest_covers_clients_docs_commands_and_hashes() -> None:
    manifest = build_skill_release_manifest(ROOT)

    assert validate_skill_release_manifest(manifest) == ()
    assert {client.platform for client in manifest.clients} == {"codex", "claude"}
    assert any(client.activation == "$redagent-operator" for client in manifest.clients)
    assert any(client.activation == "/redagent-operator" for client in manifest.clients)
    assert {doc.relative_path for doc in manifest.release_docs} >= {
        "docs/sop/AGENT_SKILL_OPERATOR_SOP.md",
        "docs/release/AGENT_SKILL_RELEASE_PACKAGE.md",
    }
    command_blob = "\n".join(manifest.validation_commands)
    assert "validate_agent_skills.py" in command_blob
    assert "test_skill_invocation.py" in command_blob
    assert "run_full_tests_windows.ps1" in command_blob
    for client in manifest.clients:
        for file in client.files:
            assert len(file.sha256) == 64
            assert file.size_bytes > 0


def test_release_manifest_validator_fails_missing_client() -> None:
    manifest = build_skill_release_manifest(ROOT)
    changed = replace(manifest, clients=tuple(client for client in manifest.clients if client.platform != "claude"))

    assert "missing_client:claude" in validate_skill_release_manifest(changed)


def test_operator_docs_include_required_release_and_safety_terms() -> None:
    sop = (ROOT / "docs" / "sop" / "AGENT_SKILL_OPERATOR_SOP.md").read_text(encoding="utf-8").lower()
    release = (ROOT / "docs" / "release" / "AGENT_SKILL_RELEASE_PACKAGE.md").read_text(encoding="utf-8").lower()
    combined = sop + "\n" + release

    for term in (
        "approved roe",
        "current testing window",
        "target allowlist",
        "current allow policy decision",
        "rate limits",
        "evidence path",
        "emergency stop method",
        "not authorization records",
        "cannot approve their own actions",
        "$redagent-operator",
        "/redagent-operator",
        "dry-run",
        "execute-mode",
        "log retrieval",
        "report drafting",
        "full gate",
    ):
        assert term in combined


def test_release_manifest_cli_outputs_json(tmp_path: Path) -> None:
    output_path = tmp_path / "manifest.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build_agent_skill_release.py"),
            "--json",
            "--output",
            str(output_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["release_version"] == "phase8.r052.v1"
    assert written["skill_name"] == "redagent-operator"
    assert {client["platform"] for client in payload["clients"]} == {"codex", "claude"}
