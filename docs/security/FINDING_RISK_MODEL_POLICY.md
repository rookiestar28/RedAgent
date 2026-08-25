# Finding and Risk Model Policy

Date: 2026-07-08
Roadmap item: compat_011

## Purpose

Findings normalize raw tool observations into reviewer-ready records. A finding is not raw evidence and must not become an uncontrolled store for request/response bodies, credentials, tokens, cookies, or payload material.

## Required Finding Fields

Findings must include:

- id
- title
- status
- severity
- confidence
- exploitability or exploit likelihood
- business impact
- CVE identifiers where applicable
- CWE identifiers where applicable
- CVSS score where applicable
- EPSS probability where applicable
- KEV status
- affected asset
- reproduction summary
- evidence links
- remediation
- owner

## Risk Factor Separation

Risk scoring must keep these fields separate:

- severity
- exploit likelihood
- asset criticality
- business impact

CVSS, EPSS, and KEV are vulnerability-intelligence inputs, not replacements for asset and business context.

## Duplicate Correlation

Duplicate correlation must be deterministic and based on normalized source, source rule id, affected asset, title, CVE ids, and CWE ids. Correlation keys must not depend on unordered input sequence.

## Export Safety

Finding exports may include evidence ids and integrity hashes, but must not include raw evidence content. Exports must reject obvious credential/token patterns and must reject sensitive evidence references unless the evidence is marked redacted or blocked.

Future reporting and issue-tracker connectors must preserve this boundary.
