# Mobile Assessment Policy

Date: 2026-07-08
Roadmap item: compat_041
Branch: `dev`

## Purpose

compat_041 defines authorized mobile application assessment controls for static package and manifest/configuration review. It does not perform dynamic instrumentation, traffic interception, device control, public app-store scraping, real-user data capture, third-party app testing, scanner execution, or external reference repository content execution.

## Required Scope

Mobile assessment requires:

- app owner approval
- explicit app package allowlist
- test device or emulator lab boundary
- production account prohibition
- real-user data prohibition
- privacy and redaction rules

Missing scope fails closed.

## Initial Modes

Implemented first:

- static package review
- manifest/configuration review

Blocked by default:

- dynamic instrumentation
- traffic interception

## Forbidden Activities

These activities are blocked:

- third-party app testing
- bypassing user privacy controls
- real-user data capture
- public app-store scraping

## Evidence Categories

Mobile evidence must identify one category:

- static package finding
- runtime/lab finding
- API/backend finding
- device/environment metadata

## Finding Mapping

Findings must map to MASVS and MASTG controls and include reproducible lab-only steps.
