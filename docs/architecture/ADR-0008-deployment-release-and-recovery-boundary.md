# ADR-0008: Deployment, Release, and Recovery Boundary

Date: 2026-07-12
Status: Proposed for compat_116

## Context

RedAgent now has accepted product control, execution, evidence, integration, agent, and finding planes. Existing deployment policy is descriptive and the local Compose stack is intentionally non-HA. compat_116 needs an installable enterprise contract without equating generated YAML or local simulation with production qualification.

## Decision

Use four independently validated release planes:

1. **Topology plane** compiles supported single-node and Kubernetes enterprise profiles into canonical component, identity, network, storage, probe, resource, and isolation manifests.
2. **Recovery plane** models component-specific backup artifacts, ordered restore dependencies, RPO/RTO objectives, verification checks, cleanup, and signed drill receipts.
3. **Distribution plane** verifies a closed, content-addressed, signed bundle graph and its provenance/SBOM/signature expectations before any environment loader may run.
4. **Upgrade plane** enforces compatibility, expand/backfill/contract ordering, N-1 worker coexistence, traffic ramp, drain, rollback, and forward-recovery decisions.

Every plane fails closed. A generated enterprise profile is `structurally_conformant`, not `environment_qualified`. Only compat_117 may promote evidence from an authorized real environment to a production/GA claim.

## Security consequences

- Mutable tags, default service accounts, public management endpoints, unrestricted ingress/egress, unsafe pod security contexts, and unreviewed exceptions are rejected.
- Backup/restore claims require artifact integrity, isolated restore, semantic verification, and cleanup evidence.
- Bundle verification never executes content and has no network fallback.
- Signature presence is insufficient; trusted identity, subject digest, provenance predicate/source, and required attestations must match policy.
- Contract migrations cannot run until expansion and backfill checks pass, old workers are unreachable/drained, and a recovery path is recorded.

## Consequences and limitations

- The repository can prove deterministic structural and state-machine invariants on a workstation.
- Provider-specific operators and admission controllers remain replaceable adapters; their source is not embedded.
- Actual multi-zone availability, numeric RPO/RTO, performance, and provider recovery remain compat_117 qualification work.
