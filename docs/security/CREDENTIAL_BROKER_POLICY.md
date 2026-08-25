# Credential Broker Policy

Date: 2026-07-08
Roadmap item: compat_029

## Purpose

The credential broker boundary prevents scanners, runners, and connectors from receiving long-lived credential material. compat_029 defines local contracts only; it does not integrate with a real vault, KMS, cloud secret manager, identity provider, scanner, or runner.

## Secret References

Credential records must store references, not values. A credential reference includes:

- credential reference id
- credential kind
- storage provider
- external reference
- owner
- engagement and organization scope
- allowed targets
- allowed modes
- allowed permissions
- expiration time
- rotation due time
- status
- redaction label

Raw credential values, cookies, tokens, passwords, private keys, cloud session material, and SSH keys must not be stored in repository files, logs, evidence, reports, screenshots, traces, or UI snapshots.

## Scoped Leases

Runners receive leases, not secrets. A lease is valid only for:

- one credential reference
- one job
- one runner
- one target
- one mode
- a subset of allowed permissions
- a short time window

Lease issuance fails if the credential reference is expired, revoked, rotation-due, out of scope, over-broad, or requests a TTL above policy.

## Canary Marker Checks

Tests and future output pipelines should seed non-usable canary markers and fail if those markers appear in logs, evidence, reports, command logs, or UI traces.

## Audit

Credential lease decisions emit compat_008 audit-chain events using the `credential_lease` action. Audit details must not include credential values.
