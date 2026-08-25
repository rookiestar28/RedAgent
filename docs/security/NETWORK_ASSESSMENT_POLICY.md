# Network Assessment Policy

Date: 2026-07-08
Roadmap item: compat_037
Branch: `dev`

## Purpose

compat_037 defines network and infrastructure assessment scope, passive/inventory-only decisions, and evidence records. It does not execute port scans, service probes, packet captures, exploit validation, DoS tests, credential attacks, scanner binaries, Kali tools, or external reference repository content.

## Required ROE

Network ROE must define:

- explicit network ranges
- explicit host allowlist
- testing window
- max rate
- max connection count
- max concurrent jobs
- emergency stop contact
- approving user
- local lab or owned infrastructure validation

Missing ROE fields fail closed.

## Implemented Modes

Implemented:

- inventory-only
- passive metadata

Not implemented:

- active probe
- exploit validation
- credential attack
- DoS testing
- internet-wide scanning

Active probing requires a later roadmap item with scanner adapter boundaries, lab validation, kill-switch behavior, and full validation.

## Evidence Requirements

Network evidence records must include:

- scope
- method
- request and connection counts
- timestamps
- operator
- runner
- redaction status

Evidence capture is metadata and chain-of-custody only. It is not proof that active network interaction is authorized.
