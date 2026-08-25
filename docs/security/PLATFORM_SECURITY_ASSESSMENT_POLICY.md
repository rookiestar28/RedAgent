# Platform Security Assessment Policy

Date: 2026-07-08
Status: compat_031 baseline

## Purpose

The platform security assessment is a release-control artifact for the RedAgent platform itself. It verifies that the implemented control plane, evidence boundary, credential boundary, runner boundary, and validation harness are represented in a threat model, assessed against ASVS-informed categories, and blocked from release when critical or high findings remain unresolved.

## Scope

In scope:

- Repository-local platform implementation.
- Authorization and scope enforcement contracts.
- Audit and evidence integrity contracts.
- Credential lease and redaction contracts.
- Runner isolation and persistent-agent gates.
- Dependency, secret, and validation harness controls.
- Findings disposition for release blockers.

Out of scope:

- Live target testing.
- Public internet scanning.
- Exploit validation.
- Payload execution.
- External reference repository execution.
- Production deployment hardening; that is handled by compat_032.
- Operational alerting and incident-response automation; that is handled by compat_033.

## Required Assessment Domains

The compat_031 assessment must cover these ASVS-informed domains:

- Architecture and threat modeling.
- Authentication.
- Session management.
- Access control.
- Input validation.
- Output encoding and export safety.
- Configuration.
- Data protection.
- Error handling and logging.
- API and service boundaries.

## Required Platform Control Checks

The assessment is incomplete unless the following controls have evidence:

- Dependency gate.
- Secret and canary redaction.
- Authorization and scope fail-closed behavior.
- Audit event coverage.
- Evidence integrity and overwrite protection.
- Runner isolation and persistent-agent gate.

## Release Blocker Rule

Critical and high findings must be either:

- fixed; or
- formally risk-accepted with owner, rationale, and evidence references.

Deferred, open, unowned, or evidence-free critical/high findings block release. Medium and lower findings may be tracked through the normal finding workflow, but they do not satisfy the compat_031 release-blocker rule by themselves.

## Evidence Handling

Assessment evidence must reference repository files, command logs, tests, and policy documents. It must not include secrets, credentials, cookies, raw payloads, target-sensitive data, quarantined-file contents, or external repository execution output.

## Safety Boundary

compat_031 does not authorize active testing. It is limited to local modeling, static policy review, unit tests, and the repository full gate.
