# ADR-0004: Staged Migration and Compatibility

Status: Accepted
Date: 2026-07-10
Architecture contract: compat_091-1

## Context

The current code has reviewed immutable data models, JSONL/filesystem persistence, deterministic state machines, synthetic adapters, and supplied-result import paths. A production rewrite that discards these contracts would lose safety behavior and make rollback unverifiable.

## Decision

Migration is additive and versioned. Current dataclasses and local artifacts remain supported inputs through adapters until an owning roadmap item proves schema/API compatibility and a later removal item is approved. No stage may reinterpret historical evidence hashes, expand authorization, convert a denial into an allow, or drop tenant/audit attributes silently.

| Stage | Owner | Compatibility requirement | Rollback |
| --- | --- | --- | --- |
| 1. Contract freeze | compat_091 | compat_001-compat_089 reality/architecture contract validates exactly | Revert documentation/validator commit |
| 2. Production foundation | compat_092 | Import/export current JSONL/filesystem state without semantic loss | Stop services, restore prior local state, disable new profile |
| 3. API and identity | compat_093-compat_095 | Versioned API plus tenant/RBAC parity for legacy domain inputs | Disable public routes; retain local adapters |
| 4. Workflow and safety | compat_096-compat_103 | Workflow replay, policy parity, evidence hash, lease, cancel, and lab tests | Pause dispatch, revoke leases, preserve accepted evidence |
| 5. Production adapters | compat_104-compat_112 | Adapter certification and normalized finding/import parity | Disable adapter/version through policy; retain supplied imports |
| 6. Agent and reporting | compat_113-compat_115 | Structured-plan/tool/evidence/report claim compatibility | Disable AI/tool calls; retain deterministic manual workflow |
| 7. Release and GA | compat_116-compat_117 | Upgrade/downgrade, backup/restore, full gate, NFR, and provenance | Roll back signed release and restore compatible backup |

## Compatibility Rules

- Public APIs, workflow payloads, policy decisions, job envelopes, evidence manifests, normalized findings, audit events, and connector messages carry explicit schema versions.
- Readers accept the current and immediately previous compatible schema during a documented migration window; writers emit only the current schema.
- Database changes use expand/backfill/verify/contract. Destructive contraction occurs only after compatibility telemetry and rollback rehearsal.
- Evidence bytes are immutable. Metadata migration creates new attestations that reference original hashes rather than rewriting objects.
- A breaking change requires an objective pre-change fixture, explicit migration test, operator communication, backup/restore proof, and roadmap acceptance criterion.
- If state cannot be converted safely, the new feature stays disabled and the legacy read-only path remains available.
