# Cloud Lifecycle Policy

compat_024 defines a local state-machine baseline for future cloud technique lifecycle workflows.

## Execution Boundary

The compat_024 module must not call cloud APIs, run cloud CLIs, execute Terraform, create resources, mutate IAM, change network policy, detonate techniques, or interact with production cloud accounts.

Lifecycle events are local evidence and state transitions only.

## Required Definition Fields

Every cloud technique definition must include:

- provider
- account or project guardrails
- allowed regions
- required permissions
- cost estimate and maximum cost guardrail
- resource tags
- warm-up step
- detonation step
- revert step
- cleanup step
- idempotence key
- expected logs

Each lifecycle step must be idempotent and must declare expected log sources.

## Production Boundary

Production cloud accounts are blocked until a future executive exception policy is implemented and tested under a separate roadmap item.

## Cleanup Boundary

Cleanup verification is mandatory before evidence lock. Failed detonation and failed revert transitions must enter cleanup-required state. Cleanup retry behavior must be bounded by the technique definition.
