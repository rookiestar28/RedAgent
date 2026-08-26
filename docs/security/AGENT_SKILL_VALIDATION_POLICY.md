# Agent Skill Validation Policy

## Purpose

The RedAgent operator skills are safety-sensitive control-plane entry points. They must collect
specifications, verify authorization and ROE, default to dry-run, and call only the repo-local
command contract. The local validator makes Codex and Claude skill packages fail closed when unsafe
edits are introduced.

## Validation Scope

The validator checks:

- Skill frontmatter naming and description requirements.
- Required package layout for Codex and Claude.
- Required safety references: `safety-gates.md`, `workflows.md`, and `command-contract.md`.
- Safety language covering specification collection, explicit confirmation, ROE, authorization, evidence, dry-run default, command contract usage, and stdout JSON handling.
- Forbidden direct-execution wording and unscoped target wording in skill instructions and references.
- Codex `agents/openai.yaml` policy metadata, including `allow_implicit_invocation: false`.
- Claude direct invocation metadata, including `disable-model-invocation: true` and no `allowed-tools` grants.
- Eval fixture shape and coverage for missing specifications, denial, ambiguous requests, safe planning, dry-run, approved wrapper execution, log retrieval, and report drafting.

## Non-Goals

The validator does not run Codex, Claude, Kali, web assessment wrappers, scanners, payloads, target checks, browser UI flows, Docker builds, package lifecycle hooks, or external reference repository code. It validates local repository text and JSON only.

## Required Usage

Run the validator directly:

```powershell
.venv\Scripts\python.exe scripts\validate_agent_skills.py --json
```

The Windows and Linux full-gate scripts also run the validator after `scripts/validate_secure_sdlc.py`. A validation failure blocks acceptance until the root cause is fixed and the failed gate is rerun.

## Failure Handling

Validation issues are emitted with stable issue codes and paths. Fix the unsafe skill text, missing metadata, or incomplete eval fixture, then rerun:

```powershell
.venv\Scripts\python.exe -m pytest tests\unit\test_skill_validation.py
.venv\Scripts\python.exe scripts\validate_agent_skills.py --json
```

Do not bypass the validator by adding tool grants, broad target wording, direct scanner commands, or execution shortcuts to skill packages.
