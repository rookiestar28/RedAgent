# Cloud Posture Policy

Date: 2026-07-08
Roadmap item: compat_039
Branch: `dev`

## Purpose

compat_039 defines read-only cloud, Kubernetes, container, and IaC posture controls. It does not connect to live cloud providers or Kubernetes clusters, mutate resources, detonate cloud techniques, create persistence, perform privilege escalation, run cleanup-dependent tests, execute scanner binaries, or upload private artifacts to external services.

## Required Scope

Cloud posture assessment requires:

- provider
- account, project, or cluster allowlist
- environment classification
- owner approval
- credential boundary
- read-only permission allowlist
- cost estimate
- blast-radius review

Missing scope fails closed.

## Initial Mode

The initial mode is read-only posture collection. Cloud detonation, resource mutation, persistence, privilege escalation, and cleanup-dependent tests are blocked by default.

## Kubernetes Coverage Areas

Kubernetes posture checks distinguish:

- control plane
- worker node
- namespace
- workload
- RBAC
- network policy
- sensitive configuration

## Artifact Evidence

IaC and container-image evidence must be secret-free. Private artifacts must not be uploaded to external services by default. Sensitive evidence requires redaction before storage.

## Finding Mapping

Cloud findings must include:

- cloud control domain
- affected resource id
- region and/or cluster context
- severity
- remediation guidance
- evidence redaction class
