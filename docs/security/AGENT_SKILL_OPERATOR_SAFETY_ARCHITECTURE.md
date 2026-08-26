# Agent Skill Operator Safety Architecture

## Purpose

This document defines the safety architecture for future Codex and Claude RedAgent operator skills. These skills will guide authorized platform workflows, but they must not become authorization records, execution engines, scanners, or arbitrary command surfaces.

This architecture introduces no runtime execution path. It defines the safety requirements for the
repository-local command contract, validation, evidence recording, and release package.

## Safety Position

Agent skills are an operator workflow layer above the RedAgent control plane. A skill may collect user intent, ask for missing specifications, summarize scope, prepare structured requests, and guide evidence review. A skill must not decide that a target is authorized, bypass policy gates, construct arbitrary shell commands, or contact targets directly.

All execution-oriented actions must flow through repo-local reviewed contracts and existing platform gates.

## Cross-Agent Layout Requirements

### Codex

Future Codex skill package:

```text
skills/codex/
  skills/
    redagent-operator/
      SKILL.md
      references/
        safety-gates.md
        workflows.md
        command-contract.md
      evals/
        evals.json
      agents/
        openai.yaml
```

Codex-specific requirements:

- Use concise `name` and `description` frontmatter.
- Trigger on authorized RedAgent planning, specification collection, dry-run preparation, approved workflow execution, evidence retrieval, and report drafting.
- Do not trigger for unsanctioned exploitation, public internet scanning, credential attacks, malware handling, payload generation, or authorization bypass requests.
- Keep `SKILL.md` concise and move detailed procedures into `references/`.
- Optional `agents/openai.yaml` must not widen permissions or imply authorization.

### Claude

Future Claude skill package:

```text
skills/claude/
  skills/
    redagent-operator/
      SKILL.md
      references/
        safety-gates.md
        workflows.md
        command-contract.md
      evals/
        evals.json
```

Claude-specific requirements:

- Support direct invocation through `/redagent-operator`.
- Treat `$ARGUMENTS` as initial user intent only, not as validated scope.
- Any `allowed-tools` use must be narrow, reviewed, and validated. It grants preapproval for listed tools; it is not a complete restriction mechanism.
- Project trust review must happen before accepting the skill package.
- Skill behavior must mirror Codex safety invariants.

## Mandatory Specification Collection

After skill activation, the first workflow stage is specification collection. The skill must ask for missing fields section by section, validate answers, and produce a structured summary before execution mode can be considered.

Required fields:

| Field | Requirement |
| --- | --- |
| Engagement objective | User must describe why the test is being requested and what outcome is expected. |
| Assessment type | Closed-set category such as passive metadata, progressive web assessment, API lab review, report drafting, or future approved module type. |
| Owner label | Business or system owner accountable for target permission. |
| Approver label | Person or process approving the test scope. |
| Operator label | Person or agent operating the workflow. |
| Authorized targets | Exact hostnames, URLs, API specs, repositories, cloud accounts, lab identifiers, or other target identifiers supported by the module. |
| Excluded targets | Explicit no-test hosts, paths, networks, tenants, repositories, user groups, or environments. |
| Environment | Lab, development, staging, production, or other controlled classification. |
| Sensitivity | Data and business sensitivity classification for evidence handling. |
| Allowed categories | Approved test categories and module modes. |
| Forbidden actions | Disallowed techniques, target classes, payload classes, and interaction types. |
| Testing window | Start and end timestamp with timezone or offset. |
| Rate and concurrency limits | Minimum delay, maximum concurrency, request or interaction cap, timeout cap, and retry policy. |
| Credential/session requirements | Whether credentials are forbidden, not needed, brokered, or explicitly approved through future credential controls. |
| Evidence outputs | Expected command log, evidence, summary, finding, and report paths. |
| Emergency stop method | Contact or mechanism that can halt the run immediately. |
| Data handling | Redaction, retention, and export limits. |
| User confirmation | Explicit confirmation that the collected specification is accurate and authorized. |

Rules:

- Missing required fields block execution-mode request preparation.
- Ambiguous, overbroad, or conflicting scope must be rejected or clarified.
- A final structured summary must be presented before execution mode.
- The explicit user confirmation marker must be carried into the repo-local command contract.
- Specification collection is evidence input, not an authorization substitute.
- Dry-run can be used to preview missing fields and policy decisions; it must not contact targets.

## Required Workflow

```text
1. User asks Codex or Claude to perform RedAgent work.
2. Agent activates the RedAgent operator skill.
3. Skill reads safety references and this architecture.
4. Skill collects missing required specifications section by section.
5. Skill validates field completeness, scope shape, and obvious conflicts.
6. Skill presents a structured summary for explicit user confirmation.
7. Skill prepares a structured request for the repo-local command contract.
8. The repo-local command contract validates schema, ROE, authorization, time window, quotas, evidence paths, and dry-run or execute mode.
9. Existing platform gates decide allow or deny.
10. Approved workflows create sanitized logs and evidence.
11. Findings and reports use repo-local evidence only.
```

## Safety Invariants

1. Skills never authorize their own target scope.
2. Skills never enter a test procedure before required specifications are collected, validated, summarized, and explicitly confirmed.
3. Skills never construct shell commands from free-form user input.
4. Skills call only reviewed repo-local entry points.
5. Skills never execute external reference repository code or content.
6. Skills never restore quarantined files.
7. Skills never run scanner, exploit, payload, fuzzing, brute-force, cloud mutation, endpoint agent, or adversary-emulation behavior unless the relevant roadmap item, ROE, and policy gates explicitly allow that class of action.
8. Skills never store raw credentials, cookies, private keys, live tokens, or sensitive target data in command logs, reports, eval outputs, or UI logs.
9. Skills preserve the browser UI as a log preview surface only.
10. Skills fail closed when authorization, target scope, time window, rate limit, evidence path, stop condition, or user confirmation is incomplete.

## Threat Model

| Threat | Scenario | Impact | Required mitigation |
| --- | --- | --- | --- |
| Malicious prompt input | User asks the skill to skip ROE, infer ownership, or attack an unapproved target. | Unauthorized target interaction. | Skill must refuse and request authorization/specification fields; command contract must deny missing or invalid scope. |
| Stale context after compaction | Agent loses earlier constraints and proceeds from incomplete memory. | Scope drift or missing safety steps. | Skill must reload safety references and re-confirm required fields before execution mode. |
| Overbroad Claude tool grants | `allowed-tools` grants broad Bash authority during skill activation. | Arbitrary local command execution. | Keep grants narrow, validate them with the package validator, and require repo-local wrapper commands only. |
| Skill drift | Codex and Claude skill copies evolve different safety behavior. | Inconsistent operator controls. | Shared references and parity validation must compare required fields, refusals, and command-boundary text. |
| Evidence tampering | Skill-generated summaries or logs omit policy denials or change scope after confirmation. | Broken audit trail. | The evidence recorder must preserve the specification summary, confirmation marker, policy decision, timestamps, and artifact hashes. |
| Accidental public-target testing | User provides a public host without adequate ownership proof or approved ROE. | Third-party testing risk. | Skill must ask for owner/approver labels, authorized target list, excluded scope, time window, stop method, and explicit authorization confirmation; command contract must fail closed. |
| Prompt-induced secret leakage | User pastes credentials or private tokens into specification fields. | Sensitive data exposure in logs or reports. | Skill must warn against credential disclosure and route future credentials through approved brokered-session controls only. |
| UI command confusion | Operator expects browser log UI to execute commands. | Uncontrolled execution path. | Architecture keeps UI preview-only; evidence tests must prove skill workflows do not expose arbitrary browser command input. |

## Authorization Boundary

Skill-collected specifications are not approval records. The platform authorization engine remains the source of execution permission. The skill may prepare a request, but only the repo-local command contract and downstream policy gates can produce an allow decision.

Required downstream checks:

- target allowlist
- excluded scope
- authorized owner/approver labels
- time window and timezone
- allowed categories
- forbidden actions
- rate, concurrency, and request caps
- emergency stop method
- evidence and redaction requirements
- dry-run versus execute mode
- current policy decision

## Evidence Requirements for Future Items

Future skill-driven workflows must preserve:

- skill client: Codex or Claude
- skill package version
- command contract version
- collected specification summary
- explicit confirmation marker
- policy decision and refusal reason if denied
- target scope and excluded scope
- timestamps
- operator label
- evidence path
- command-log path
- report path when generated
- redaction status
- artifact hashes when available

## Non-Goals

- No skill package is created.
- No command contract is implemented.
- No validator or eval harness is implemented.
- No runner or scanner is invoked.
- No target is contacted.
- No external repository is cloned or executed.

## Acceptance Mapping

| Architecture requirement | Coverage |
| --- | --- |
| Map request to activation, specification collection, confirmation, ROE, authorization, command contract, policy, evidence, findings, and reports | Required Workflow; Authorization Boundary; Evidence Requirements |
| Define Codex and Claude layouts with shared safety model | Cross-Agent Layout Requirements |
| Define mandatory fields before testing | Mandatory Specification Collection |
| Forbid skill self-authorization, unapproved target interaction, arbitrary shell construction, external reference execution, quarantined file restoration, sensitive data leakage, and policy bypass | Safety Invariants |
| Cover malicious prompt input, stale context, overbroad tool grants, skill drift, evidence tampering, and accidental public-target testing | Threat Model |
| Introduce no execution path | Non-Goals |
