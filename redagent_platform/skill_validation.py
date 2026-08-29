"""Safety validation for repo-local RedAgent operator skill packages."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any


SKILL_NAME = "redagent-operator"
REQUIRED_REFERENCES = (
    "references/safety-gates.md",
    "references/workflows.md",
    "references/command-contract.md",
)
REQUIRED_CORE_TERMS = {
    "missing_specification_collection": ("specification collection",),
    "missing_explicit_confirmation": ("explicit user confirmation",),
    "missing_roe_requirement": ("roe",),
    "missing_authorization_requirement": ("authorization",),
    "missing_evidence_requirement": ("evidence",),
    "missing_dry_run_default": ("dry-run", "dry run"),
    "missing_command_contract": ("command contract",),
    "missing_stdout_json": ("stdout as json",),
}
FORBIDDEN_DIRECT_EXECUTION_PATTERNS = (
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
    "nuclei",
    "zap",
)
UNSCOPED_TARGET_PATTERNS = (
    "against any target",
    "any public target",
    "all public sites",
    "public site i do not own",
    "scan everything",
)
REQUIRED_EVAL_COVERAGE = {
    "missing_specifications": ("missing", "direct-invocation"),
    "denial": ("deny", "denial", "unauthorized"),
    "ambiguous_request": ("ambiguous",),
    "safe_planning": ("safe-planning",),
    "dry_run": ("dry-run", "dry_run"),
    "approved_wrapper_execution": ("approved-wrapper", "execute-prep", "workflow-prep"),
    "log_retrieval": ("log-retrieval",),
    "report_drafting": ("report", "evidence-report"),
}


@dataclass(frozen=True)
class SkillValidationIssue:
    code: str
    message: str
    path: str

    def to_jsonable(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
            "path": self.path,
        }


@dataclass(frozen=True)
class SkillValidationReport:
    platform: str
    skill_root: str
    issues: tuple[SkillValidationIssue, ...]

    @property
    def passed(self) -> bool:
        return not self.issues

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "skill_root": self.skill_root,
            "passed": self.passed,
            "issue_count": len(self.issues),
            "issues": [issue.to_jsonable() for issue in self.issues],
        }


def validate_default_skill_packages(repo_root: str | Path = ".") -> tuple[SkillValidationReport, ...]:
    root = Path(repo_root)
    return (
        validate_skill_package(root / "skills" / "codex" / SKILL_NAME, platform="codex"),
        validate_skill_package(root / "skills" / "claude" / SKILL_NAME, platform="claude"),
    )


def validate_skill_package(skill_root: str | Path, *, platform: str) -> SkillValidationReport:
    root = Path(skill_root)
    normalized_platform = platform.lower()
    issues: list[SkillValidationIssue] = []

    if normalized_platform not in {"codex", "claude"}:
        issues.append(_issue("unsupported_platform", f"Unsupported platform: {platform}", root))
        return SkillValidationReport(platform=platform, skill_root=str(root), issues=tuple(issues))

    skill_path = root / "SKILL.md"
    _validate_required_layout(root, normalized_platform, issues)
    if skill_path.exists():
        skill_text = _read_text(skill_path)
        metadata, body_text = _parse_frontmatter(skill_text, skill_path, issues)
        _validate_frontmatter(metadata, normalized_platform, skill_path, issues)
        _validate_skill_body(root, body_text, issues)
        _validate_safety_terms(root, skill_text, issues)
        if normalized_platform == "claude":
            _validate_claude_permissions(metadata, skill_text, skill_path, issues)
    if normalized_platform == "codex":
        _validate_openai_metadata(root / "agents" / "openai.yaml", issues)
    _validate_evals(root / "evals" / "evals.json", issues)

    return SkillValidationReport(platform=normalized_platform, skill_root=str(root), issues=tuple(issues))


def _validate_required_layout(root: Path, platform: str, issues: list[SkillValidationIssue]) -> None:
    required: tuple[str, ...] = (
        "SKILL.md",
        *REQUIRED_REFERENCES,
        "evals/evals.json",
    )
    if platform == "codex":
        required = (*required, "agents/openai.yaml")
    for relative_path in required:
        path = root / relative_path
        if not path.exists():
            issues.append(_issue("missing_required_file", f"Missing required file: {relative_path}", path))


def _parse_frontmatter(
    text: str,
    path: Path,
    issues: list[SkillValidationIssue],
) -> tuple[dict[str, object], str]:
    normalized = text.replace("\r\n", "\n")
    if not normalized.startswith("---\n"):
        issues.append(_issue("missing_frontmatter", "SKILL.md must start with YAML frontmatter.", path))
        return {}, normalized

    end_index = normalized.find("\n---\n", 4)
    if end_index == -1:
        issues.append(_issue("invalid_frontmatter", "SKILL.md frontmatter is not closed.", path))
        return {}, normalized

    raw_frontmatter = normalized[4:end_index]
    body = normalized[end_index + len("\n---\n") :]
    metadata: dict[str, object] = {}
    for line_number, line in enumerate(raw_frontmatter.splitlines(), start=2):
        stripped = line.strip()
        if not stripped:
            continue
        if ":" not in stripped:
            issues.append(
                _issue(
                    "invalid_frontmatter_line",
                    f"Frontmatter line {line_number} must use key: value syntax.",
                    path,
                )
            )
            continue
        key, raw_value = stripped.split(":", 1)
        key = key.strip()
        value = raw_value.strip()
        if value.lower() == "true":
            parsed: object = True
        elif value.lower() == "false":
            parsed = False
        else:
            parsed = _strip_quotes(value)
        metadata[key] = parsed
    return metadata, body


def _validate_frontmatter(
    metadata: dict[str, object],
    platform: str,
    path: Path,
    issues: list[SkillValidationIssue],
) -> None:
    allowed_keys = {"name", "description"}
    if platform == "claude":
        allowed_keys.add("disable-model-invocation")

    unexpected = sorted(set(metadata) - allowed_keys)
    for key in unexpected:
        issues.append(_issue("unexpected_frontmatter_key", f"Unexpected frontmatter key: {key}", path))

    name = metadata.get("name")
    if name != SKILL_NAME:
        issues.append(_issue("invalid_skill_name", f"Skill name must be {SKILL_NAME}.", path))
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        issues.append(_issue("invalid_skill_name_format", "Skill name must be lowercase hyphen-case.", path))

    description = metadata.get("description")
    if not isinstance(description, str) or not description.strip():
        issues.append(_issue("missing_description", "Skill description is required.", path))
    elif len(description) > 1024:
        issues.append(_issue("description_too_long", "Skill description must be 1024 characters or less.", path))

    if platform == "claude" and metadata.get("disable-model-invocation") is not True:
        issues.append(
            _issue(
                "claude_model_invocation_not_disabled",
                "Claude skill must set disable-model-invocation: true.",
                path,
            )
        )


def _validate_skill_body(root: Path, body_text: str, issues: list[SkillValidationIssue]) -> None:
    lower_body = body_text.lower()
    for reference in REQUIRED_REFERENCES:
        if reference not in body_text:
            issues.append(
                _issue("missing_reference_link", f"SKILL.md must link to {reference}.", root / "SKILL.md")
            )
    if "read:" in lower_body or "required reading" not in lower_body:
        return


def _validate_safety_terms(root: Path, skill_text: str, issues: list[SkillValidationIssue]) -> None:
    combined_parts = [skill_text]
    for reference in REQUIRED_REFERENCES:
        path = root / reference
        if path.exists():
            combined_parts.append(_read_text(path))
    combined = "\n".join(combined_parts)
    lower_combined = combined.lower()

    for code, acceptable_terms in REQUIRED_CORE_TERMS.items():
        if not any(term in lower_combined for term in acceptable_terms):
            issues.append(_issue(code, f"Required safety term missing: {code}", root / "SKILL.md"))

    for pattern in FORBIDDEN_DIRECT_EXECUTION_PATTERNS:
        if pattern in lower_combined:
            issues.append(
                _issue(
                    "forbidden_direct_execution",
                    f"Forbidden direct-execution pattern appears in skill text: {pattern}",
                    root / "SKILL.md",
                )
            )
    for pattern in UNSCOPED_TARGET_PATTERNS:
        if pattern in lower_combined:
            issues.append(
                _issue(
                    "unscoped_target_wording",
                    f"Unscoped target wording appears in skill text: {pattern}",
                    root / "SKILL.md",
                )
            )


def _validate_claude_permissions(
    metadata: dict[str, object],
    skill_text: str,
    path: Path,
    issues: list[SkillValidationIssue],
) -> None:
    if "allowed-tools" in metadata:
        issues.append(
            _issue(
                "claude_allowed_tools_declared",
                "Claude skill must not declare allowed-tools without a reviewed exception.",
                path,
            )
        )
        value = str(metadata["allowed-tools"]).lower()
        if "*" in value or "bash" in value or "shell" in value:
            issues.append(
                _issue(
                    "claude_overbroad_allowed_tools",
                    "Claude allowed-tools grant is overbroad for this safety-sensitive skill.",
                    path,
                )
            )
    if re.search(r"(?im)^allowed-tools\s*:", skill_text):
        issues.append(
            _issue(
                "claude_allowed_tools_declared",
                "Claude SKILL.md text includes an allowed-tools declaration.",
                path,
            )
        )


def _validate_openai_metadata(path: Path, issues: list[SkillValidationIssue]) -> None:
    if not path.exists():
        return
    text = _read_text(path)
    lower_text = text.lower()
    if "$redagent-operator" not in text:
        issues.append(_issue("codex_missing_default_prompt", "OpenAI metadata must expose the skill trigger.", path))
    if "dependencies" in lower_text:
        issues.append(
            _issue("codex_metadata_declares_dependencies", "OpenAI metadata must not declare dependencies.", path)
        )
    if not re.search(r"(?im)^\s*allow_implicit_invocation\s*:\s*false\s*$", text):
        issues.append(
            _issue(
                "codex_implicit_invocation_not_disabled",
                "Codex skill metadata must set allow_implicit_invocation: false.",
                path,
            )
        )


def _validate_evals(path: Path, issues: list[SkillValidationIssue]) -> None:
    if not path.exists():
        return
    try:
        data = json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        issues.append(_issue("invalid_evals_json", f"Eval fixture JSON is invalid: {exc}", path))
        return
    if not isinstance(data, dict):
        issues.append(_issue("invalid_evals_shape", "Eval fixture must be a JSON object.", path))
        return
    if data.get("skill_name") != SKILL_NAME:
        issues.append(_issue("invalid_evals_skill_name", f"Eval skill_name must be {SKILL_NAME}.", path))

    evals = data.get("evals")
    if not isinstance(evals, list) or not evals:
        issues.append(_issue("missing_evals", "Eval fixture must contain a non-empty evals list.", path))
        return

    eval_ids: list[str] = []
    for index, item in enumerate(evals):
        if not isinstance(item, dict):
            issues.append(_issue("invalid_eval_case", f"Eval case {index} must be an object.", path))
            continue
        case_id = item.get("id")
        prompt = item.get("prompt")
        expected_output = item.get("expected_output")
        if not isinstance(case_id, str) or not case_id.strip():
            issues.append(_issue("invalid_eval_case", f"Eval case {index} must include an id.", path))
        else:
            eval_ids.append(case_id.lower())
        if not isinstance(prompt, str) or not prompt.strip():
            issues.append(_issue("invalid_eval_case", f"Eval case {index} must include a prompt.", path))
        if not isinstance(expected_output, str) or not expected_output.strip():
            issues.append(_issue("invalid_eval_case", f"Eval case {index} must include expected_output.", path))

    for category, markers in REQUIRED_EVAL_COVERAGE.items():
        if not any(any(marker in eval_id for marker in markers) for eval_id in eval_ids):
            issues.append(
                _issue(
                    "missing_eval_coverage",
                    f"Eval fixture missing required coverage category: {category}",
                    path,
                )
            )


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _issue(code: str, message: str, path: Path) -> SkillValidationIssue:
    return SkillValidationIssue(code=code, message=message, path=str(path))
