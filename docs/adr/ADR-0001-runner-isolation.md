# ADR-0001: Runner Isolation Model

## Status

Accepted as the public design baseline. Persistent endpoint agents remain out of scope unless a
separate threat model, authorization policy, and release decision approve them.

## Context

Controlled security validation needs bounded execution without introducing unreviewed persistence,
rogue-runner behavior, credential theft, command injection, or lateral movement.

## Decision

Use agentless integrations and ephemeral runners as the default implementation direction.

| Model | Persistence | Public position |
| --- | --- | --- |
| Agentless | None | Allowed only through an explicit, bounded integration contract. |
| Ephemeral runner | Short-lived | Preferred when execution is required; identity, scope, time, and cleanup must be bounded. |
| Persistent endpoint agent | Long-lived | Not implemented or authorized by this baseline. |

## Required Controls

Any runner design must define and verify:

- registration and workload identity;
- command authorization and target scope;
- short-lived credentials and revocation;
- timeout, cancellation, and cleanup behavior;
- evidence integrity, redaction, and retention;
- telemetry and audit events;
- artifact and payload boundaries; and
- safe removal and rollback.

Threat analysis must cover at least a rogue runner, stolen identity, command injection, replay,
cleanup failure, and lateral movement. Local tool availability never constitutes authorization to
execute a security assessment.
