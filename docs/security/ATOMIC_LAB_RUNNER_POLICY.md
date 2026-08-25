# Atomic Lab Runner Policy

Date: 2026-07-08
Roadmap item: compat_023
Branch: `dev`

## Purpose

compat_023 defines metadata-only atomic test import and lab-only runner preparation. It does not execute atomic command bodies, scripts, binaries, payloads, Docker builds, package lifecycle hooks, or external reference repository content.

## Metadata-Only Import

Atomic imports must store only reviewable metadata:

- test id and name
- ATT&CK tactic and technique mapping
- supported platforms
- executor name
- prerequisite, execution, and cleanup summaries
- expected telemetry sources
- safety flags

Raw command bodies and payload material must not be stored in product state.

## Lab-Only Runner Boundary

An atomic lab run can be prepared only when:

- target type is `LAB_TARGET`
- target is explicitly marked as a lab target
- target has an approving user id
- requested platform is supported or explicitly reviewed
- unsafe capability flags are either absent or explicitly reviewed

Non-lab targets must fail closed.

## Review-Required Flags

The lab runner blocks these flags unless a review explicitly allows them:

- external downloads
- elevated privileges
- destructive potential
- missing cleanup for destructive tests
- unsupported platform

## Phase Capture

Prepared lab runs capture these phases separately:

- prerequisite
- execution
- cleanup
- telemetry
- evidence

Phase capture is evidence planning and audit metadata. It is not shell execution.
