from __future__ import annotations

import json
from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[2]
CLAUDE_ROOT = ROOT / "skills" / "claude" / "redagent-operator"
CODEX_ROOT = ROOT / "skills" / "codex" / "redagent-operator"
SKILL = CLAUDE_ROOT / "SKILL.md"
EVALS = CLAUDE_ROOT / "evals" / "evals.json"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def frontmatter(text: str) -> dict[str, object]:
    match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "SKILL.md must start with YAML frontmatter"
    data = yaml.safe_load(match.group(1))
    assert isinstance(data, dict)
    return data


def test_claude_skill_layout_exists() -> None:
    required = [
        SKILL,
        CLAUDE_ROOT / "references" / "safety-gates.md",
        CLAUDE_ROOT / "references" / "workflows.md",
        CLAUDE_ROOT / "references" / "command-contract.md",
        EVALS,
    ]
    for path in required:
        assert path.exists(), path


def test_claude_frontmatter_requires_direct_invocation_without_tool_grants() -> None:
    meta = frontmatter(read(SKILL))

    assert meta["name"] == "redagent-operator"
    assert meta["disable-model-invocation"] is True
    assert "allowed-tools" not in meta
    assert "Direct-invoked Claude Code skill" in meta["description"]
    assert len(str(meta["description"])) <= 1024


def test_claude_skill_treats_arguments_as_intent_only() -> None:
    text = read(SKILL)

    assert "/redagent-operator" in text
    assert "$ARGUMENTS" in text
    assert "initial user intent only" in text
    assert "not as validated scope or authorization" in text
    assert "explicit user confirmation before execute mode" in text
    assert "stdout as JSON" in text


def test_claude_skill_uses_same_core_references_as_codex() -> None:
    claude_text = read(SKILL)
    codex_text = read(CODEX_ROOT / "SKILL.md")

    for reference in ("references/safety-gates.md", "references/workflows.md", "references/command-contract.md"):
        assert reference in claude_text
        assert reference in codex_text
    for phrase in ("Start with specification collection", "repo-local", "command contract"):
        assert phrase in claude_text
        assert phrase in codex_text


def test_claude_skill_does_not_expose_forbidden_execution_patterns() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in CLAUDE_ROOT.rglob("*.md"))
    forbidden = [
        "allowed-tools:",
        "invoke-expression",
        "iex ",
        "os.system",
        "eval(",
        "exec(",
        "wsl.exe",
        "nmap",
        "sqlmap",
        "gobuster",
        "ffuf",
    ]
    for phrase in forbidden:
        assert phrase not in combined


def test_claude_evals_cover_required_workflows() -> None:
    data = json.loads(read(EVALS))

    assert data["skill_name"] == "redagent-operator"
    ids = {item["id"] for item in data["evals"]}
    assert {
        "claude-direct-invocation",
        "claude-arguments-not-authorization",
        "claude-denial",
        "claude-dry-run",
        "claude-approved-workflow-prep",
        "claude-evidence-report",
    } <= ids
    for item in data["evals"]:
        assert item["prompt"].startswith("/redagent-operator")
        assert item["expected_output"]
