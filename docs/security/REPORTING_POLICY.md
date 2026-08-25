# Reporting Policy

Date: 2026-07-08
Roadmap item: compat_028

## Purpose

compat_028 defines deterministic executive and technical report generation from locked evidence and reviewed findings. Reports are controlled evidence exports and must preserve authorization, redaction, integrity, and claim-traceability boundaries.

## Required Sections

Report packages must include:

- executive summary
- technical findings
- ATT&CK coverage
- OWASP coverage
- risk trends
- scope
- methodology
- limitations
- appendix

## Claim Traceability

Every claim must either:

- cite one or more locked evidence IDs, or
- state an explicit assumption.

Reports must not imply that a control, detection, ATT&CK technique, OWASP category, or vulnerability was observed unless the claim links to evidence. Assumptions are acceptable for scope, methodology, limitations, and unavailable coverage inputs when clearly marked.

## Determinism

Report regeneration must be deterministic for the same input package. The report fingerprint is derived from report metadata, required sections, claims, redaction review metadata, and the locked evidence hash. The locked evidence hash is derived from sorted evidence IDs and integrity hashes.

## Redaction Review

Internal rendering is allowed while redaction review is pending. External sharing is blocked unless redaction review status is `approved`.

Reports must not include:

- raw request or response bodies
- cookies, tokens, API keys, passwords, private keys, session material, or live credential values
- unredacted sensitive evidence
- payload samples or exploit material
- canary markers used by tests

## Audit

Report generation emits an compat_008 `report_generation` audit event. Audit details include report audience, section count, evidence lock hash, report hash, and redaction review status. Audit details must not include raw report body, raw evidence content, connector secrets, credentials, or payload material.

## Future Export Formats

PDF, DOCX, HTML, email, portal publishing, and ticket attachments require separate roadmap planning. Future formats must preserve deterministic source packages, redaction review gates, claim traceability, and secret-free artifact tests.
