# Abuse Prevention Policy

Date: 2026-07-07
Status: Initial policy baseline

## Purpose

This policy defines controls that prevent the platform from being used for unauthorized testing, broad scanning, destructive actions, credential misuse, or evidence leakage.

## Blocked Target Classes

The platform must block these targets by default:

- domains, subdomains, IP addresses, cloud accounts, APIs, or applications without an approved authorization record
- public demo targets and third-party training systems unless explicitly approved for lab use
- customer, partner, vendor, or employee personal systems
- internet-wide ranges, search-engine-derived host lists, or broad ASN/CIDR scans
- production cloud accounts unless a later executive exception policy is implemented and validated
- identity providers, payment providers, email services, analytics providers, and other third-party SaaS dependencies unless explicitly authorized

## Blocked Action Classes

The platform must block these actions by default:

- exploit execution
- destructive payloads
- denial-of-service, stress, or load testing
- credential stuffing, brute force, password spraying, MFA fatigue, and credential harvesting
- phishing, social engineering, or impersonation
- malware handling or execution
- persistence, lateral movement, and endpoint agent deployment
- privilege escalation outside lab-only reviewed tests
- cloud resource detonation without lifecycle cleanup controls
- data exfiltration beyond an approved and minimal proof point
- external callbacks, OAST, or blind interaction endpoints unless explicitly approved and controlled

## Required Abuse-Prevention Controls

Before any executable testing feature ships, the platform must implement:

- target allowlist checks
- explicit forbidden target checks
- time-window checks
- module and test-class authorization checks
- rate limits, concurrency limits, request caps, and duration caps
- operator confirmation for active tests
- emergency kill switch
- immutable policy-decision audit events
- evidence redaction and access control
- secret scanning over logs, evidence, and reports
- runner identity and capability checks
- template/test-definition review states
- fail-closed behavior when policy data is missing or malformed

## Public Internet Restrictions

Public internet scanning is out of scope. A single public domain may be tested only when:

- ownership or written authorization is recorded
- target hostnames are explicitly allowlisted
- third-party dependencies and unrelated subdomains are excluded
- test categories are approved
- rate limits and windows are defined
- emergency contacts and stop conditions are recorded

Broad discovery, internet-wide enumeration, or automated expansion from one domain to unapproved assets is forbidden.

## Production Cloud Safeguards

Production cloud technique testing is blocked until a later roadmap item implements:

- account/project/subscription allowlists
- service and region allowlists
- cost estimates
- resource tags
- warm-up, detonate, revert, and cleanup states
- cleanup verification
- failed-cleanup escalation
- explicit production exception workflow

## Rate and Concurrency Policy

Default behavior before approval:

- max active jobs: `0`
- max target requests: `0`
- max concurrency: `0`

Every approved engagement must define explicit limits. Missing limits block execution.

## Kill Switch Requirements

The kill switch must:

- stop queued jobs
- request cancellation of running jobs
- revoke runner policy tokens when possible
- prevent new jobs for suspended engagements
- record who triggered the stop and why
- preserve evidence generated before the stop
- require owner review before resuming

## Evidence and Privacy Controls

Evidence collection must:

- minimize captured content
- redact tokens, cookies, credentials, keys, and personal data
- hash evidence files or records
- record retention class
- block export until redaction review passes
- avoid storing private contact details in repository files

## Operator Guardrails

Operators must not:

- run tools directly from Kali against enterprise targets outside approved platform workflows
- copy command snippets from external repositories into live tests without review
- bypass repository gates or local policy checks
- use personal credentials for testing
- store secrets in `.local/validation/`, `docs/`, command logs, screenshots, or reports
- continue testing after a stop condition

## Current Enforcement State

Implemented:

- repository-level safety policy in `CONTRIBUTING.md`
- roadmap gates in `PUBLIC_RELEASE.md`
- external reference execution disabled in `redagent_platform/safety.py`
- `reference/` docs-only validation in unit tests and full-gate scripts
- secret-detection pre-commit hook

Not implemented yet:

- compat_006 authorization engine
- compat_013 passive reconnaissance module
- compat_017 active testing policy gate
- runner identity, isolation, and kill switch
- evidence store and redaction pipeline
- credential broker

Therefore no live target testing is currently allowed by the platform.
