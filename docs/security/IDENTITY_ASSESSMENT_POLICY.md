# Identity Assessment Policy

Date: 2026-07-08
Roadmap item: compat_038
Branch: `dev`

## Purpose

compat_038 defines enterprise identity, IAM, and SSO assessment controls for read-only posture collection. It does not connect to live identity providers or run password spraying, brute force, token theft, credential dumping, phishing, privilege escalation, OAuth abuse, or other active identity attacks.

## Required Scope

Authenticated identity assessment requires:

- tenant id
- tenant owner
- approving user
- testing window
- principal allowlist
- resource allowlist
- read-only permission allowlist
- scoped credential boundary

Missing scope, approval, time window, or credential boundary fails closed.

## Initial Mode

The initial implemented mode is read-only configuration collection. The collection plan covers:

- SSO configuration
- OAuth applications
- MFA policy
- privileged access
- conditional access

Active identity testing is blocked until a later item-specific lab-only ROE explicitly authorizes a simulation.

## Forbidden Activities

These activities are blocked by default:

- password spraying
- brute force
- token theft
- credential dumping
- phishing
- live privilege escalation

## Finding Mapping

Identity findings must include:

- identity control area
- affected principal ids or affected resource ids
- evidence redaction class
- remediation guidance

Findings must not include raw secrets, tokens, cookies, or private identity-provider response bodies.
