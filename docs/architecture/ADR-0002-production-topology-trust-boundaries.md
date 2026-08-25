# ADR-0002: Production Topology and Trust Boundaries

Status: Accepted for staged implementation
Date: 2026-07-10
Architecture contract: compat_091-1

## Context

compat_001-compat_089 created a strong set of local contracts, validators, state machines, supplied-result importers, synthetic runtimes, and one bounded target-facing local web runner. They did not create a deployed multi-tenant service, durable service database, distributed workflow engine, external policy/secret services, object evidence service, or isolated production runner fleet. The production design must preserve those reviewed contracts without treating them as deployed infrastructure.

## Decision

RedAgent will start as a modular-monolith control plane with explicit owned ports around independently isolated workflow, policy, secret, evidence-object, runner, adapter, AI-agent, and connector boundaries. This keeps the first operable release understandable and easy to install while preserving extraction seams for scale and fault isolation.

The control plane owns engagements, targets, authorization records, workflow references, findings, report state, and audit/outbox metadata in PostgreSQL. Evidence bytes are owned by the evidence service in S3-compatible immutable object storage; PostgreSQL stores hashes, classification, retention, tenant/engagement ownership, and object references. Secret values remain owned by OpenBao-compatible storage and are represented elsewhere only by opaque lease references. Workflow history is owned by the workflow engine. External delivery state is owned by connector outbox/dead-letter records.

### Profiles

- Local profile: pinned Docker Compose topology, local Keycloak-compatible OIDC profile, one control-plane instance, one workflow service, one policy service, one secret service, one object store, and disabled-by-default synthetic runner. It is optimized for an authorized evaluator to reach a first synthetic campaign quickly.
- Enterprise profile: Kubernetes-compatible deployment with workload identity, independently scalable public API/workflow/runner components, managed PostgreSQL and S3-compatible storage, high-availability identity/policy/secret services, network policies, encrypted backups, and observable rollback.
- Both profiles use the same versioned API, domain contracts, policy input/output, evidence manifest, job envelope, adapter result, and audit event schemas.

### Boundaries

| Boundary | Trust decision | Failure behavior |
| --- | --- | --- |
| Public API/BFF | OIDC identity, browser CSRF/session controls, tenant and permission checks | Reject before persistence or dispatch. |
| Modular control plane | Service-layer authorization plus tenant-scoped repositories; row-level isolation is defense in depth | Roll back the transaction and emit no dispatch event. |
| Workflow engine | Receives opaque IDs and bounded state, not raw secrets; policy/human checkpoints are durable | Retry safely or enter failed/contained state. |
| Policy decision point | Deterministic normalized input; AI output is never authority | Deny on missing input, stale policy, timeout, error, or ambiguity. |
| Secret broker | Purpose-, tenant-, engagement-, and TTL-scoped leases | Do not start credential-dependent work; revoke when possible. |
| Evidence service | Redact before durable write; require committed hash/metadata before success | Quarantine partial artifacts and block successful completion claims. |
| Runner fleet | Ephemeral single-job identity, signed envelope, egress allow-list, timeout/cancel/cleanup | Contain, revoke, record acknowledgement, and require review. |
| Adapters | Certified pinned version, closed-set arguments, schema/resource limits | Terminate adapter and preserve only sanitized diagnostics. |
| AI agent | Redacted context and bounded tools; deterministic authorization and human approval remain outside its trust root | Deny tool call and stop the loop with a sanitized trace. |
| Connectors | Short-lived destination credential, tenant allow-list, idempotency and redaction | Bounded retry or dead-letter without duplicate mutation. |

## Data Flow

1. A browser or CLI authenticates through OIDC and submits a tenant-bound request to the public API.
2. The application service revalidates authorization, stores the transaction plus outbox/audit metadata, and creates an opaque workflow reference.
3. The workflow obtains deterministic policy decisions and required human approvals before dispatch.
4. The runner receives a signed, single-job envelope and retrieves a short-lived secret lease only when policy permits.
5. A certified adapter executes inside the runner boundary. Results cross back only through normalized schemas and the evidence port.
6. Evidence is redacted, hashed, committed to object storage, and linked to immutable metadata before findings can claim support.
7. Findings/reporting and external connectors consume normalized records and opaque evidence links through an idempotent outbox.
8. AI may propose plans or summarize evidence, but cannot issue authorization, expand target scope, retrieve unrestricted secrets, or bypass adapter controls.

## Consequences

- The first production implementation has fewer independently deployed application services, reducing installation and operational burden.
- Explicit ports prevent the modular monolith from becoming an implicit trust blob.
- Runner and evidence isolation are mandatory before target-facing production execution.
- Local JSONL/filesystem implementations remain compatibility inputs during migration, not production stores.
- Persistent endpoint agents, public-internet scanning, production cloud detonation, arbitrary shell execution, and unapproved AI tool autonomy remain out of scope unless separately authorized and replanned.
