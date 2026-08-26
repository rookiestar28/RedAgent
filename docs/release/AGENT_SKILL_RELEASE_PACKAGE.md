# Agent Skill Release Package

The public repository includes equivalent repository-local RedAgent operator skills for two clients:

- Codex: `skills/codex/redagent-operator/`, activated with `$redagent-operator`
- Claude Code: `skills/claude/redagent-operator/`, activated with `/redagent-operator`

Do not copy these packages into global user or administrator paths as part of the repository release. A separate review must authorize wider installation.

## Validation

```powershell
.venv\Scripts\python.exe scripts\validate_agent_skills.py --json
.venv\Scripts\python.exe -m pytest tests\unit\test_codex_skill_package.py tests\unit\test_claude_skill_package.py tests\unit\test_skill_validation.py
.venv\Scripts\python.exe -m pytest tests\unit\test_skill_invocation.py tests\unit\test_skill_command_contract.py tests\unit\test_skill_release.py
.venv\Scripts\python.exe scripts\build_agent_skill_release.py --json
powershell -ExecutionPolicy Bypass -File scripts\run_full_tests_windows.ps1
```

The full gate must pass before a skill package is accepted.

## Safety boundary

Skills are not authorization records and cannot approve their own actions. An operator must provide approved ROE, the current testing window, a target allowlist, the current allow policy decision, rate limits, an evidence path, and an emergency stop method before any execute-mode preparation. Dry-run, log retrieval, and report drafting remain repository-local, and no target-facing test is authorized merely by this release package.
