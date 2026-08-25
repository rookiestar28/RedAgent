# Nuclei Controlled Execution Policy

Date: 2026-07-08
Roadmap item: compat_019
Branch: `dev`

## Purpose

compat_019 defines the controlled Nuclei execution-planning boundary after compat_016 and compat_017. It does not execute Nuclei, load executable template bodies, start subprocesses, contact targets, or call OAST/interactsh services.

## Required Gates

A Nuclei execution plan requires:

- an allowed compat_017 active policy decision and policy grant
- an compat_016 approved template review
- an approved template ID allowlist
- severity and risk-class allowlists
- protocol allowlist
- rate limit and timeout
- OAST policy decision
- output redaction requirement
- cancellation support

If any gate is missing or denied, the plan fails closed.

## Template Policy

compat_016 metadata remains the source of truth for template ID, severity, protocol types, tags, risk class, and review status. compat_019 must not treat executable template bodies, matchers, extractors, flows, or payload blocks as trusted input.

High-risk, sandbox-only, rejected, and pending templates cannot produce controlled execution plans in compat_019.

## Result Normalization

Supplied JSONL/SARIF-style result metadata may be normalized into:

- compat_008 scanner-output evidence with sanitized content
- compat_011 findings with Nuclei template ID as source rule ID

Raw request/response content, credential material, cookies, private keys, session values, and unredacted scanner output must not be stored.

## Future Live Execution

Future live Nuclei execution requires separate roadmap planning for runner isolation, executable template allowlisting, outbound allowlists, sandbox validation, OAST governance, process cancellation, and evidence redaction tests.
