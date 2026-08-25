from __future__ import annotations

import json
from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[2]
SKILL_ROOT = ROOT / "skills" / "codex" / "redagent-operator"
SKILL = SKILL_ROOT / "SKILL.md"
OPENAI_YAML = SKILL_ROOT / "agents" / "openai.yaml"
EVALS = SKILL_ROOT / "evals" / "evals.json"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def frontmatter(text: str) -> dict[str, str]:
    match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "SKILL.md must start with YAML frontmatter"
    data = yaml.safe_load(match.group(1))
    assert isinstance(data, dict)
    return {str(key): str(value) for key, value in data.items()}


def test_codex_skill_layout_exists() -> None:
    required = [
        SKILL,
        SKILL_ROOT / "references" / "safety-gates.md",
        SKILL_ROOT / "references" / "workflows.md",
        SKILL_ROOT / "references" / "command-contract.md",
        EVALS,
        OPENAI_YAML,
    ]
    for path in required:
        assert path.exists(), path


def test_skill_frontmatter_is_valid_and_scoped() -> None:
    meta = frontmatter(read(SKILL))

    assert meta["name"] == "redagent-operator"
    assert len(meta["name"]) < 64
    assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", meta["name"])
    assert "authorized RedAgent platform workflows" in meta["description"]
    assert "unsanctioned testing" in meta["description"]
    assert len(meta["description"]) <= 1024


def test_skill_requires_safety_references_and_spec_collection() -> None:
    text = read(SKILL)

    for reference in ("references/safety-gates.md", "references/workflows.md", "references/command-contract.md"):
        assert reference in text
    assert "Start with specification collection" in text
    assert "explicit user confirmation before execute mode" in text
    assert "scripts\\redagent_skill_assess.py" in text
    assert "stdout as JSON" in text


def test_skill_does_not_expose_forbidden_execution_patterns() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in SKILL_ROOT.rglob("*.md"))
    forbidden = [
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


def test_openai_yaml_is_safe_and_explicit() -> None:
    data = yaml.safe_load(read(OPENAI_YAML))

    assert data["interface"]["display_name"] == "RedAgent Operator"
    assert "$redagent-operator" in data["interface"]["default_prompt"]
    assert data["policy"]["allow_implicit_invocation"] is False
    assert "dependencies" not in data


def test_codex_evals_cover_required_workflows() -> None:
    data = json.loads(read(EVALS))

    assert data["skill_name"] == "redagent-operator"
    ids = {item["id"] for item in data["evals"]}
    assert {
        "codex-plan-missing-specs",
        "codex-deny-unauthorized-public-target",
        "codex-dry-run-approved-passive",
        "codex-progressive-execute-prep",
        "codex-evidence-report-drafting",
    } <= ids
    for item in data["evals"]:
        assert item["prompt"]
        assert item["expected_output"]
