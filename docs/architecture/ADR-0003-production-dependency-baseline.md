# ADR-0003: Provisional Production Dependency Baseline

Status: Accepted as provisional; installation begins no earlier than compat_092
Date: 2026-07-10
Architecture contract: compat_091-1

## Decision

The following choices define replacement interfaces and governance ownership; compat_091 installs none of them. Exact supported versions and lock/image digests are selected by the owning roadmap item after license, provenance, vulnerability, and compatibility review.

| Dependency | Purpose and owner | License/security posture | Version and upgrade policy | Fail-closed behavior / replacement interface |
| --- | --- | --- | --- | --- |
| FastAPI | Public/internal ASGI API; compat_093 | MIT; pinned-version review | Compatible minor plus exact lock; monthly/advisory | API unavailable, never bypass auth / ASGI + OpenAPI contract |
| PostgreSQL | Transactional metadata; compat_092 | PostgreSQL License; hardened image review | Supported major, controlled minors | Writes stop / repository ports and SQL schema |
| SQLAlchemy + Alembic | Persistence/migrations; compat_093 | MIT; pair compatibility review | Compatible minor pair, exact lock | Startup migration gate blocks / repository and migration ports |
| Temporal | Durable workflows; compat_096 | MIT components; server/SDK/image review | Server/SDK compatibility matrix; quarterly/advisory | No new dispatch / workflow and activity ports |
| OPA | Deterministic policy; compat_099 | Apache-2.0; bundle provenance review | Pinned image/binary and bundle schema | Deny all governed operations / policy decision port |
| OpenBao | Secret leases; compat_098 | MPL-2.0; deployment/plugin review | Supported pinned release/image | Credential jobs do not start / lease broker port |
| S3-compatible storage | Evidence objects; compat_097 | Provider deliberately deferred; license/security review mandatory | Pin provider and API profile | Evidence cannot commit / evidence object port |
| OpenTelemetry | Metrics/traces/log correlation; compat_102 | Apache-2.0; exporter review | Compatible SDK/collector pins; monthly | Bounded degradation without sensitive spill / telemetry ports |
| Keycloak | Local OIDC profile; compat_094 | Apache-2.0; realm/extension/image review | Supported pinned major/image | Deny new sessions / standards-based OIDC boundary |
| React | Operational UI; compat_095 | MIT; lockfile/audit/browser review | Supported major and exact lock; monthly | UI may fail but API auth remains authoritative / versioned API |
| Docker Compose | Local topology; compat_092 | Apache-2.0 implementation; image/host review | Pinned schema and image digests | Refuse partial startup / service topology contract |
| Kubernetes | Enterprise topology; compat_116 | Apache-2.0; distribution/admission/network review | Supported minor skew and pinned manifests | Pause/rollback rollout / portable workload contracts |

## Governance Rules

- Runtime and build dependencies must be pinned reproducibly and represented in SBOM/provenance evidence.
- Dependency owners record supported versions, upstream support windows, license decision, security advisories, upgrade rehearsal, data compatibility, and rollback before status changes from provisional.
- New dependencies require a concrete capability gap, owner, failure behavior, replacement interface, and removal plan; convenience alone is insufficient.
- S3 compatibility is selected before a provider to avoid silently accepting a license or deployment model that conflicts with enterprise distribution.
- AI providers and offensive tools are adapters, not trusted architecture dependencies. They require separate allow-list, certification, policy, and version controls.
