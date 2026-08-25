# Supply Chain Assessment Policy

Date: 2026-07-08
Roadmap item: compat_040
Branch: `dev`

## Purpose

compat_040 defines CI/CD and software supply-chain assessment controls for trusted target repositories. It does not run scanner binaries, connect to external verification services, scan unapproved repositories, or store raw credentials, tokens, cookies, private keys, live secret values, or scanner payloads.

## Required Scope

Repository and pipeline assessment requires:

- owner approval
- explicit repository allowlist
- trusted repository flag
- pipeline allowlist when pipeline checks are requested
- local-only check planning by default

Unapproved or untrusted repositories fail closed.

## Local Checks

Initial planned check categories are:

- static analysis
- dependency inventory
- SBOM import
- sensitive-value scanning
- provenance checks

These are planning contracts only. Tool execution requires a later controlled runner item.

## Redacted Evidence

Sensitive-value evidence must:

- store redacted locations only
- reject raw values
- reject canary marker leakage
- carry redaction status

External verification is disabled by default unless separately approved.

## Result Mapping

Results must map to:

- source file/path or pipeline object
- control category
- severity
- remediation guidance
- false-positive workflow
