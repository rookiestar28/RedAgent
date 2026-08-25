# Target Inventory Policy

Date: 2026-07-08
Roadmap item: compat_007

## Purpose

The target inventory is the control-plane source for authorized assets. It records what an engagement may reference before any runner, scanner, adapter, or adversary-emulation module can request execution.

compat_007 is local validation only. It does not perform DNS lookups, HTTP requests, cloud API calls, Kubernetes API calls, CIDR expansion, vulnerability checks, or any other live target interaction.

## Required Target Metadata

Every inventory target must record:

- Stable target id.
- Organization id.
- Engagement id.
- Owner label.
- Target type.
- Normalized target value.
- Environment classification.
- Data-sensitivity classification.
- Authorization status.
- Explicit allowed test modes.
- Explicit-review status and review reason when an entry needs manual acceptance.

## Supported Target Types

- Web origin.
- API spec.
- Domain.
- CIDR.
- Cloud account.
- Cloud project.
- Cloud subscription.
- Kubernetes cluster.
- Lab target.

## Import Validation Rules

The import validator is fail-closed:

- Malformed target values are denied.
- Empty owner, organization, engagement, target id, target value, or allowed test modes are denied.
- Unknown environment or unknown data sensitivity requires explicit review.
- Wildcard domains require explicit review.
- Single-label, `.local`, and `.internal` domains require explicit review because public/private routing can be ambiguous.
- Broad CIDR ranges require explicit review: IPv4 prefix length below `/24` and IPv6 prefix length below `/64`.
- Private, loopback, link-local, and reserved CIDR entries require explicit review.
- Lab targets must be marked as `lab`; otherwise they require explicit review.

Explicit review allows intentionally broad or private entries to be imported, but only when a review reason is recorded.

## Audit Semantics

Inventory create, update, and delete operations must produce structured audit-event candidates. compat_008 will make audit storage immutable and tamper-evident; compat_007 only standardizes the event shape.

## Execution Boundary

Target inventory acceptance does not authorize active testing. compat_006 scope authorization remains required for any future job, and compat_017 remains required before active testing adapters or adversary-emulation execution are enabled.
