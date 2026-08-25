# ADR-0007: Finding Operations and Publication Boundary

Status: Accepted for compat_115 implementation
Date: 2026-07-12

## Context

RedAgent already normalizes synthetic and qualified adapter outputs and has early in-process finding, review, reporting, publication, and connector contracts. It lacks durable canonical identity, occurrence history, deterministic reimport, disposition preservation, collaborative workflows, exact report snapshots, and qualified connector delivery.

## Decision

Use a RedAgent-owned, tenant-isolated finding operations service with four boundaries:

1. canonical issues hold reusable weakness identity and reviewed current state;
2. immutable occurrences bind an issue to an adapter run, resource/location, producer fingerprint/version, coverage state, and approved evidence hashes;
3. append-only operations record disposition, assignment, SLA, comment digests, risk acceptance/expiry, merge/split lineage, retest, close/reopen, and audit truth;
4. publication/delivery projections bind an exact reviewed snapshot to report/connector profile revisions, allowlisted fields, policy revision, idempotency key, and outcome.

PostgreSQL revision 0022 will use FORCE RLS and explicit tenant predicates. Imports use a versioned deterministic recipe and explainable candidate ledger. Absence closes an occurrence only for complete comparable coverage and never silently changes reviewed issue disposition. Merge/split create lineage operations; they do not destroy prior identity or evidence.

Reports are deterministic and content-addressed. AI suggestions are untrusted draft inputs until independently adopted by a reviewer; AI cannot approve or publish. Connectors use transactional outbox, opaque credential references, allowlisted fields/destinations, bounded retry/dead-letter, signed callbacks, reconciliation, and revoke/disable. Initial promotion is network-free and fixture-only.

## Rejected Alternatives

- scanner finding row as the canonical issue;
- global or fuzzy/LLM correlation as an authoritative dedup decision;
- destructive reimport or automatic disposition reset;
- marking absent results fixed without complete comparable coverage;
- reports assembled from mutable live rows or unsupported AI claims;
- direct API-request delivery inside finding transactions;
- arbitrary webhook URLs, payload templates, connector code, or credentials in persisted objects;
- external platform state as RedAgent's authority.

## Consequences

The model is more explicit and uses additional tables, but it makes identity, review, evidence, publication, retries, and reconciliation independently auditable. External schemas remain replaceable projections. Real connectors require later profile-specific provisioning and qualification; compat_115 proves the product workflow with deterministic fixtures and no external side effects.

## Rollback

Disable the compat_115 runtime promotion and routes, stop fixture delivery workers, and retain append-only audit/import/outbox truth. Rollback does not delete occurrences, undo dispositions, restore expired exceptions, republish stale reports, or replay delivery under a changed snapshot.
