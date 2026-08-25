# Skill Invocation Evidence Policy

Date: 2026-07-09
Roadmap item: compat_051

## Purpose

compat_051 connects validated RedAgent operator skill requests to repo-local evidence and reporting artifacts. The integration records only sanitized command-contract decisions. It does not run Codex or Claude prompts, contact targets, invoke scanners, call Kali/WSL tools, execute browser commands, or run the real assessment wrapper.

## Artifact Boundary

Artifact recording is explicit and opt-in through:

```powershell
.venv\Scripts\python.exe scripts\redagent_skill_assess.py --request <request.json> --record-artifacts --ui-log-path .tmp\ui-terminal.log
```

The command first evaluates the compat_047 command contract. Artifacts are written only when the decision is `allow`. Denied decisions produce structured JSON and do not create command-log, evidence, report, or UI-preview artifacts.

Allowed artifact roots:

- `.local/validation/` or `.tmp/` for command logs
- `.tmp/` or `reports/` for evidence directories
- `reports/` or `.tmp/` for generated reports
- `.tmp/` for UI log previews

Absolute paths, parent traversal, missing paths, and disallowed roots fail closed.

## Evidence Requirements

Recorded evidence must include:

- operator label
- skill client and skill version
- command contract version
- policy decision outcome and reason
- requested target scope
- requested timestamp
- redaction status
- specification fingerprint
- artifact hashes

Evidence content is a sanitized summary, not the raw request. Raw credentials, cookies, tokens, payloads, and sensitive target data must not be written.

## Reporting Requirements

Generated reports use the existing compat_028 reporting contract and locked compat_008 evidence records. Reports must:

- state that no target-facing assessment ran through the artifact recorder
- avoid vulnerability, exploitability, or remediation claims not backed by evidence
- mark unsupported statements as assumptions
- remain internal until redaction review is approved

## UI Preview Boundary

The browser UI remains log preview only. compat_051 may update `.tmp/ui-terminal.log` with sanitized progress text, but the UI must not expose command input, run buttons, scanner controls, or arbitrary execution parameters.
