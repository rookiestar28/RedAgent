# Runner Isolation Policy

compat_025 defines the design baseline for future runner and endpoint-agent work.

## Default Direction

- Agentless workflows are acceptable for passive, read-only, and manually mediated operations.
- Ephemeral runners are the preferred default for controlled execution.
- Persistent agents are blocked until threat-model review is recorded and a future roadmap item explicitly approves implementation.

## Required Design Controls

Any runner design must document:

- trust boundaries
- registration
- authentication
- command authorization
- telemetry
- payload storage
- revocation
- uninstall

## Abuse Cases

Design validation must cover:

- rogue runner
- stolen runner token
- command injection
- lateral movement

## Kali WSL2 Boundary

Kali WSL2 may be used as a controlled lab/tool node only after a runner policy gate exists. It must not become the primary repo development root and must not run tools directly against this project tree.

## Non-Shipping Boundary

This item ships no persistent agent, installer, service, daemon, command channel, payload store, or endpoint telemetry collector.
