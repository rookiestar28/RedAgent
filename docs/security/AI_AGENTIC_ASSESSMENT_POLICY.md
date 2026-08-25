# AI and Agentic Assessment Policy

Date: 2026-07-08
Roadmap item: compat_042
Branch: `dev`

## Purpose

compat_042 defines safe AI, LLM, and agentic application assessment planning. It does not call live AI providers, execute agent tools, perform side-effecting actions, extract unauthorized system prompts, exfiltrate real sensitive data, abuse accounts, violate provider terms, or execute external reference repository content.

## Test Case Review

AI test cases must be:

- reviewed
- versioned
- risk-classified
- tied to a prompt template id
- tied to an expected observation

Unreviewed test cases fail closed.

## Provider Scope

Live provider use requires:

- approved provider account
- approved model allowlist
- cost limit
- request limit
- data redaction
- logging boundary

This item only prepares dry-run plans.

## Agent Tool Boundary

Agent tool-use tests require:

- explicit tool allowlist
- dry-run mode
- side-effect controls
- kill switch

## Prohibited Intents

Tests must not attempt:

- real sensitive-data exfiltration
- unauthorized system prompt extraction from third-party systems
- account abuse
- provider ToS violations

## Finding Mapping

Findings must map to:

- LLM or agentic risk category
- affected workflow
- data boundary
- tool/action boundary
- remediation guidance
