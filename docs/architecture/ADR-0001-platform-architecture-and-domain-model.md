# ADR-0001: Platform Architecture and Core Domain Model

Date: 2026-07-08
Status: Accepted for compat_003 baseline

## Context

The RedAgent platform is a private enterprise red-team testing application. Its future capabilities are dual-use, so architecture must make authorization, scope, evidence integrity, auditability, and execution isolation harder to bypass than ad hoc tool operation.

The repository already has governance, ROE templates, assessment SOPs, a local log-preview UI, and a controlled manual assessment harness. The generalized platform modules are not implemented yet.

## Decision

Adopt a control-plane / execution-plane architecture with explicit contracts between planning, authorization, execution, evidence, findings, and reporting.

### Control Plane

The control plane owns:

- organization and user identity
- role and tenant boundary policy
- engagement records
- target inventory
- authorization records
- test-definition registry
- policy decisions
- job lifecycle state
- evidence metadata
- finding review state
- report metadata
- audit events
- UI and API workflows

The control plane must not concatenate shell commands, directly invoke scanners, directly run exploit logic, or contact targets on behalf of the browser UI. Execution requests are serialized into constrained jobs after policy checks.

### Execution Plane

The execution plane owns future runner workers and tool adapters. Runners receive only the scoped job payload, runner identity, allowed capability, target scope, timeout, rate/concurrency policy, and redaction/evidence instructions required for one job.

Execution-plane capabilities must be separated by mode:

- passive scan
- active scan
- adversary emulation
- cloud technique
- lab-only run

No execution-plane capability is enabled by this ADR. compat_006, compat_010, compat_017, compat_029, and compat_030 must exist before generalized execution is accepted.

### Storage Boundary

Initial storage design is logical, not implementation-specific. Later items may choose a database and object store, but the domain split is:

- relational or document store for organizations, users, roles, engagements, targets, authorizations, test definitions, runners, jobs, findings, reports, audit events, and policy decisions
- evidence store for immutable or append-only evidence payloads and metadata
- secret store or credential broker for any future credentials
- ignored local runtime storage for raw temporary artifacts during development

### Queue Boundary

The future queue mediates control-plane job approval and execution-plane dispatch. It must preserve job state transitions and must not accept arbitrary commands from UI/API inputs.

Required lifecycle vocabulary:

- planned
- authorized
- queued
- dispatched
- running
- cleanup
- completed
- failed
- cancelled
- evidence locked

### Evidence Store Boundary

Evidence is separate from findings. Evidence records preserve provenance, redaction status, integrity hash, retention class, related job, and safe payload references. Findings cite evidence; findings do not own raw sensitive data.

### UI Boundary

The UI is a control-plane surface. It can preview logs, collect scope inputs, display policy decisions, show job states, present findings, and render reports. It must not expose arbitrary command execution controls.

### Integration Boundary

External integrations are adapters, not core control-plane logic. Examples include scanner adapters, issue trackers, cloud providers, identity tenants, source-control systems, CI systems, and report exporters. Each adapter must use reviewed contracts, credential boundaries, redaction rules, and audit events.

## Core Domain Entities

The baseline core model includes:

- Organization
- User
- Role
- Engagement
- Target
- Authorization
- TestDefinition
- Runner
- Job
- Evidence
- Finding
- Report
- AuditEvent
- PolicyDecision

The Python implementation in `redagent_platform/domain.py` defines these as immutable dataclasses and enums. These are not persistence schemas yet; they are stable contract vocabulary and validation anchors for future roadmap items.

## Rejected Alternatives

### Direct UI-to-Tool Execution

Rejected because it would let browser/UI inputs become command execution paths and would weaken authorization, audit, and evidence controls.

### Single Monolithic Scanner Service

Rejected because passive web checks, active scans, adversary emulation, cloud techniques, and lab-only runs have different legal, operational, and safety boundaries.

### Importing External Tool Schemas as the Core Model

Rejected because external projects are untrusted references and use different execution assumptions. The platform can map to tool-specific metadata through adapters, but internal policy and evidence contracts must remain product-owned.

### Database-First Schema Design

Rejected for compat_003 because the product still needs compat_004-compat_011 decisions before choosing persistence. The domain model is intentionally framework-neutral.

## Rollback Path

If later implementation proves these contracts too narrow:

1. Add a new ADR describing the replacement contract.
2. Keep compatibility tests for existing entity names until all downstream code migrates.
3. Migrate unit tests and roadmap acceptance mappings before deleting old contract names.
4. Preserve audit/evidence terminology unless a security review approves the migration.

## Consequences

- Later roadmap items can share stable domain terms.
- Execution remains disabled until explicit policy and runner gates exist.
- Tool adapters must normalize into internal contracts instead of shaping the platform around a single scanner.
- Evidence, finding, report, and audit concerns stay separate from the beginning.
