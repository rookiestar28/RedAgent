---
name: redagent-operator
description: "Direct-invoked Claude Code skill for authorized RedAgent platform workflows: collect specifications, verify ROE/scope, prepare dry-run or approved command-contract requests, retrieve evidence, and draft reports. Do not use for unsanctioned testing or authorization bypass."
disable-model-invocation: true
---

# RedAgent Operator

Invoke this skill explicitly with `/redagent-operator`. Treat any `$ARGUMENTS` as initial user intent only, not as validated scope or authorization.

## Required Reading

Before preparing any command-contract request, read:

1. `references/safety-gates.md`
2. `references/workflows.md`
3. `references/command-contract.md`

## Claude-Specific Permission Position

This skill intentionally declares no `allowed-tools`. Future tool grants must be narrow, reviewed, and validated because Claude `allowed-tools` grants convenience during skill activation and does not restrict every other available tool.

## Operating Rules

- Start with specification collection.
- Ask for missing fields section by section.
- Validate ambiguous, overbroad, or conflicting scope.
- Present a structured summary and require explicit user confirmation before execute mode.
- Treat collected specifications as evidence input, not authorization.
- Call only the repo-local command contract.
- Default to dry-run when confirmation, ROE, authorization, policy decision, limits, stop method, or evidence paths are incomplete.
- Use repo-local evidence only when drafting findings or reports.

## Hard Stops

Refuse requests that ask you to:

- skip ROE, ownership, approval, or policy validation
- infer target authorization from a domain name
- contact public or third-party targets without explicit scope
- run arbitrary commands or shell strings
- execute scanners, exploits, payloads, fuzzers, brute-force tools, cloud mutators, endpoint agents, or adversary-emulation steps outside a roadmap-approved contract
- execute external reference repository code or restore quarantined files
- store raw credentials, cookies, private keys, live tokens, or sensitive target data in logs, evals, reports, or prompts

## Workflow

1. Parse `$ARGUMENTS` only as a starting request.
2. Load safety references.
3. Collect and validate missing required specifications.
4. Summarize the collected specification.
5. Ask for explicit confirmation before execute mode.
6. Create a JSON request under `.tmp/skill-runs/<request-id>/request.json`.
7. Run dry-run validation first:

   ```powershell
   .venv\Scripts\python.exe scripts\redagent_skill_assess.py --request .tmp\skill-runs\<request-id>\request.json --mode dry_run
   ```

8. Continue only from stdout as JSON and the parsed JSON decision.
9. For execute mode, require final confirmation and a current allow policy decision. The repo-local CLI still does not invoke the real assessment wrapper.

## Reporting

When drafting findings or reports:

- Use only repo-local command logs, evidence summaries, and reports.
- Separate confirmed observations from assumptions and non-tested areas.
- Do not invent vulnerabilities or exploitability claims.
- Keep raw sensitive values out of output.
