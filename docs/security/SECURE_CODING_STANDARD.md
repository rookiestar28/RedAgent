# Secure Coding Standard

Date: 2026-07-08
Status: compat_004 baseline

## Purpose

This standard defines baseline secure coding expectations for the RedAgent platform. It applies to application code, scripts, validators, tests, local tooling, and future runner or adapter code.

## Authentication and Authorization

- Every user-visible or API action must identify the actor before processing sensitive requests.
- Authorization checks must use explicit roles, engagement scope, target scope, and policy decisions.
- Cross-tenant or cross-organization access must fail closed.
- Service runner identity must be separate from human user identity.

## Input Validation

- Treat all operator input, file input, imported metadata, scanner output, HTTP responses, target metadata, and reference-source data as untrusted.
- Validate target type, ownership, allowed mode, testing window, rate limit, and maximum interaction count before any target interaction.
- Use structured parsers for JSON, YAML, TOML, URLs, and domain data instead of ad hoc string parsing where practical.
- Reject ambiguous, malformed, over-broad, or out-of-scope inputs by default.

## Output Encoding and Rendering

- UI and report rendering must encode untrusted text.
- Scanner output, target-controlled content, error messages, and imported metadata must not be rendered as trusted HTML.
- Reports must distinguish observed evidence from assumptions and reviewer commentary.

## Secrets and Credentials

- Treat credential material as high-risk data across code, logs, reports, evidence, SBOMs, and tests.
- Do not store secrets in source, command logs, reports, screenshots, traces, videos, tests, SBOMs, or evidence exports.
- Future credential flows must use a credential broker and least-privilege, time-bounded access.
- Redaction must happen before evidence is exported or rendered to lower-trust surfaces.

## Logging and Evidence

- Logs must preserve enough context for auditability without exposing credentials or sensitive payloads.
- Evidence must record provenance, timestamp, operator or runner identity, redaction status, and integrity hash.
- Findings cite evidence; findings must not become uncontrolled stores of raw sensitive data.

## Error Handling

- Security-sensitive operations must fail closed.
- User-facing errors should be actionable without revealing secrets, stack traces, internal topology, or tool command details.
- Runners and adapters must preserve failure states for cleanup and audit.

## Data Retention

- Raw runtime artifacts belong under ignored `.tmp/` unless sanitized and explicitly promoted.
- Evidence retention and redaction class must be defined by engagement policy.
- Reports and command logs must be reviewed for secret-free content before commit.

## Dangerous Tool Execution

- Browser UI and control-plane APIs must not expose arbitrary command execution.
- Future runner implementations must use structured command contracts, allowlisted tools, explicit modes, timeouts, cancellation, cleanup, and output redaction.
- Do not execute external reference repository code, scripts, tests, package lifecycle hooks, Docker builds, binaries, payloads, samples, or generated artifacts.
- High-risk modules require threat-model review before implementation and full-gate validation before merge.

## High-Risk Module Threat-Model Requirement

Before implementation begins, a threat-model review is required for modules involving:

- active scanning
- adversary emulation
- cloud techniques
- endpoint or agent runners
- authenticated testing
- credential brokers
- external connectors
- evidence export
- report publishing
- social engineering, physical, wireless, IoT, or OT planning
- AI/LLM/agentic testing

The review must document abuse cases, authorization boundaries, secrets exposure risks, rollback, stop conditions, logging, and evidence handling.
