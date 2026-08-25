# Issue Connector Policy

Date: 2026-07-08
Roadmap item: compat_027

## Purpose

compat_027 defines the enterprise workflow export boundary for reviewed findings. It creates connector contracts and deterministic issue export plans, but it does not call live issue tracker, webhook, chat, email, or collaboration APIs.

## Connector Boundary

Connectors must use a generic integration interface. A concrete connector may plan an issue export only when:

- the finding status is `confirmed`
- the finding can be exported through the compat_011 sanitized finding boundary
- the connector configuration uses a credential reference and redaction label, not a secret value
- the generated payload contains no secret-like fields or canary markers
- sensitive evidence is redacted or blocked before any evidence link is included

## Export Payload Requirements

Issue payloads may include:

- sanitized summary
- severity
- owner user ID
- evidence IDs, integrity hashes, and redaction status
- remediation
- source taxonomy, rule ID, CVE IDs, CWE IDs, and correlation key
- deterministic labels

Issue payloads must not include:

- raw request or response bodies
- cookies, tokens, API keys, passwords, private keys, session material, or live credential values
- unredacted sensitive evidence
- payload samples, exploit details, or scanner raw output
- canary markers used by tests

## Idempotency

Duplicate export must be deterministic. The connector derives an external key from connector ID, project key, and finding correlation key. If that external key already exists for the connector, the export result must be `updated_existing` rather than creating a new issue.

## Audit

Every export plan emits an compat_008 `export` audit event. Audit details must include connector ID, connector kind, external key, issue key, export action, and payload hash. Audit details must not include connector secrets or raw payload content.

## Future Live Connectors

Future live adapters for Jira, GitHub, Linear, Slack, email, or webhooks require separate roadmap planning. They must add credential leasing, outbound allowlists, rate limits, retry controls, failure handling, audit evidence, and secret-free log tests before any network call is enabled.
