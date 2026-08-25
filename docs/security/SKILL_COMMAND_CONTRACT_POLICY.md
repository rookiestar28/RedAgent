# Skill Command Contract Policy

Date: 2026-07-09
Roadmap item: compat_047

## Purpose

The skill command contract is the only planned entry point that future Codex and Claude RedAgent operator skills may use to prepare assessment execution requests. It converts collected test specifications into a structured allow or deny decision.

compat_047 is not a scanner, runner, exploit framework, or target interaction feature.

## Required Inputs

Requests must be JSON objects with:

- request id, skill client, assessment type, and requested timestamp
- organization and engagement identifiers
- owner, approver, operator, and authorization labels
- approved ROE status and explicit authorization confirmation
- authorized targets, requested targets, and excluded targets
- environment and sensitivity labels
- allowed categories and forbidden actions
- time window with timezone-aware start and end
- rate limit, concurrency cap, interaction cap, and timeout cap
- credential requirement classification
- repo-relative output paths for command log, evidence directory, and report
- emergency stop method
- redaction and retention requirements
- final user confirmation for execute mode
- current allow policy decision for execute mode

## Mode Rules

`dry_run`:

- Default mode.
- Performs validation only.
- Does not require final user confirmation.
- Does not invoke any delegate.
- Must not contact targets.

`execute`:

- Requires valid ROE, authorization confirmation, complete target scope, valid time window, limits, evidence paths, redaction, final user confirmation, and current allow policy decision.
- Can only delegate through an injected, reviewed wrapper boundary.
- compat_047 CLI does not invoke the real web assessment wrapper.

## Output Rules

CLI stdout must contain one JSON object with:

- contract version
- decision and reason
- refusal reason when denied
- exit classification
- request id
- skill client
- mode
- assessment type
- policy decision
- requested targets
- request counts
- evidence paths
- delegation state
- next action

Diagnostics must go to stderr and must remain secret-free.

## Path Rules

Accepted output paths must be repo-relative and must not contain parent traversal.

Allowed roots:

- `.local/validation`
- `.tmp`
- `reports`

Absolute paths and paths outside these roots fail closed.

## Delegation Rules

compat_047 supports fake delegate injection for tests. Production delegation is deferred until later roadmap items. A delegate payload may only include:

- approved wrapper id
- wrapper mode
- normalized requested targets
- approved window
- authorization label
- rate and request limits
- output paths
- dry-run false marker for execute mode

## Forbidden Behavior

The contract must not:

- infer ownership or authorization
- widen target scope
- contact targets directly
- spawn shells or build command strings from free-form input
- invoke WSL/Kali
- execute scanners, templates, exploits, payloads, fuzzers, brute-force tools, cloud mutators, endpoint agents, or adversary-emulation steps
- execute external reference repository code or content
- store raw credentials, cookies, private keys, live tokens, or sensitive target data in output
