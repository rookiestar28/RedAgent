# User Operation Guide

Date: 2026-07-08
Status: Initial release baseline

## Permitted Use

This repository is for authorized enterprise red-team planning, local policy validation, evidence handling, and controlled assessment workflow development. Active testing requires a repo-local authorization record, explicit target scope, approved testing window, rate and volume limits, emergency stop method, and a roadmap item that permits the relevant execution class.

Forbidden by default:

- testing third-party or production systems without explicit authorization;
- public internet scanning outside approved ROE;
- exploit or payload execution without a specific approved plan;
- malware-analysis execution in this repository;
- restoring quarantined external reference files; and
- executing external reference repository scripts, tests, binaries, Docker builds, payloads, or samples.

## Onboarding

Operators must:

- read `CONTRIBUTING.md`;
- read `docs/TESTING.md` and `docs/E2E_TESTING.md`;
- use the project-local Python environment and Node 20.9+ on 20.x, 22.x, or 24+ test path;
- keep Kali WSL2 as a separate lab node, not the primary project root;
- run full-gate validation before accepted non-documentation work; and
- record evidence under `.local/validation/` for accepted implementation work.

## Target Authorization

Every target requires a scope record with:

- owner and approver;
- exact allowed target values;
- forbidden targets when applicable;
- allowed test modes;
- testing window and timezone;
- maximum rate and interaction caps; and
- emergency stop contact method.

If target scope is ambiguous, expired, unapproved, or missing emergency contact details, testing must not proceed.

## Execution Safety

Execution features are disabled until policy-approved. Operators must verify:

- RBAC and scope authorization passed;
- active policy gate passed when active testing is requested;
- scheduler quotas and cooldowns allow the job;
- runner boundary and credential lease are valid;
- stop conditions and kill switch are documented; and
- evidence handling and redaction are ready.

## Evidence Handling

Evidence must be tamper-evident, redacted when sensitive capture is possible, and linked to audit events. Command logs must not include credentials, cookies, private keys, raw payloads, sensitive target data, or external-reference execution output.

Reports and exports require redaction review before external sharing.

## Incident Escalation

Escalate immediately for:

- out-of-scope attempts;
- failed cleanup;
- runner anomalies;
- auth anomalies;
- evidence integrity failures;
- leaked evidence; or
- accidental production testing.

Use the incident runbooks defined by `docs/security/OBSERVABILITY_INCIDENT_RESPONSE_POLICY.md` and preserve audit/evidence chain state before cleanup whenever possible.
