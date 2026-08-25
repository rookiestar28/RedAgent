# Audit and Evidence Chain Policy

Date: 2026-07-08
Roadmap item: compat_008

## Purpose

Audit and evidence records provide traceability for sensitive platform actions and test artifacts. The initial compat_008 implementation is a local control-plane contract; it does not store data in a database, write to WORM storage, sign records, or capture live target traffic.

## Required Audit Actions

The audit taxonomy must cover:

- login
- policy decision
- target change
- job lifecycle
- runner callback
- evidence creation
- finding change
- report generation
- export

Audit events include a timestamp, actor, organization, action, subject, details hash, previous event hash, and event hash.

## Required Evidence Metadata

Evidence records include:

- evidence id
- organization id
- source job id
- evidence kind
- timestamp
- redaction status
- retention class
- access policy
- content hash
- metadata hash
- previous evidence hash
- integrity hash

The content hash is stored instead of raw content. Findings and reports must reference evidence by id and hash rather than owning raw sensitive data.

## Sensitive Capture Policy

Sensitive request/response capture must be redacted or blocked:

- `redacted` means only sanitized content may be hashed and retained.
- `blocked` means the raw content is not retained; the evidence record stores a deterministic blocked-content marker hash.
- raw sensitive capture is rejected.

## Append-Only Semantics

Evidence ids are immutable inside a chain. Adding a record with an existing evidence id is a policy violation and must fail instead of replacing the original record.

## Future Hardening

Future storage work should add durable append-only persistence, access-control enforcement, legal-hold retention jobs, cryptographic signing or external timestamping where required, and alerting on failed overwrite attempts.
