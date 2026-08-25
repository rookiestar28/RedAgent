# Nuclei Metadata Review Policy

compat_016 imports Nuclei template metadata only. It does not execute Nuclei or preserve executable template bodies.

## Imported Fields

The importer stores only:

- template ID
- name
- severity
- tags
- references
- classification
- protocol types
- derived risk class
- high-risk reasons

Request definitions, matchers, extractors, payload bodies, flow logic, code, headless steps, and OAST callback behavior are not execution authorization.

## High-Risk Defaults

Templates are high-risk by default when metadata indicates:

- `code`, `javascript`, or `headless` protocol
- destructive, intrusive, OAST, interactsh, credential, brute-force, fuzzing, RCE, or SSRF tags
- high, critical, unknown, or unclear behavior

High-risk templates cannot be approved for general use in compat_016. Reviewers may reject them or require sandbox-only handling. Execution remains disabled in every compat_016 review state.
