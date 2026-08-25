# Authenticated Session Harness Policy

compat_020 models authenticated session metadata for future authorized tests. It does not log in, replay traffic, run browsers, or contact targets.

## Credential Boundary

Session contexts must reference compat_029 `CredentialLease` IDs only. They must not store raw cookies, bearer tokens, passwords, API keys, or credential values.

## Redaction Boundary

Captured request/response metadata must redact:

- `Authorization`
- `Cookie`
- `Set-Cookie`
- API key and token headers
- email-like personal data
- secret-like body excerpts

Redacted evidence is stored with compat_008 evidence metadata and reviewer-only access.

## Role Comparison

Role-based authorization cases compare role labels, session IDs, status codes, operation labels, and evidence IDs only. They must not expose session material or credential values.
