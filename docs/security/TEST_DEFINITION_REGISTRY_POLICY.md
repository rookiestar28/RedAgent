# Test Definition Registry Policy

Date: 2026-07-08
Roadmap item: compat_009

## Purpose

The test definition registry stores reviewed metadata for future security tests. It is not an execution engine. Registry approval does not authorize a job, scanner run, adversary-emulation procedure, cloud action, or payload execution.

## Required Metadata

Every registry definition must include:

- id
- name
- version
- source
- source reference
- author
- reviewer
- target types
- execution mode
- risk class
- required permissions
- expected evidence
- cleanup behavior
- taxonomy mappings

## Supported Metadata Sources

compat_009 supports metadata-only imports for:

- Atomic-style test metadata.
- Nuclei template identifiers and metadata.
- ZAP rule identifiers and metadata.
- Custom internal test metadata.

Executable fields are forbidden during compat_009 import. Do not store command bodies, template request bodies, payloads, shell snippets, Docker instructions, package hooks, binary samples, or external repository content in the registry.

## Review and Execution Boundary

Imported definitions start as pending and disabled. A reviewer must approve a definition before it can be registered.

High-risk or destructive definitions are blocked from execution by default. Active execution still requires later roadmap gates, including compat_010 runner state management and compat_017 active testing policy approval.

## Audit Requirements

Registry changes emit compat_008 audit-chain events using the `test_definition_change` action. Audit details include source, reviewer, execution-enabled state, and risk class.

## Taxonomy Mapping

Definitions should map to one or more relevant taxonomies:

- MITRE ATT&CK
- OWASP WSTG
- OWASP ASVS
- OWASP API Top 10
- CWE
- internal controls
