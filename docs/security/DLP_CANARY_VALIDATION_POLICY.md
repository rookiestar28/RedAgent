# DLP Canary Validation Policy

compat_045 defines the local, fail-closed baseline for DLP and controlled exfiltration purple-team validation.

## Execution Boundary

compat_045 must not perform exfiltration, network transfer, protocol execution, file movement, DLP connector calls, SIEM/EDR/cloud queries, credential retrieval, or external service calls.

The module can only validate a proposed plan and export sanitized evidence.

## Dataset Boundary

Only synthetic and canary data is allowed. The following are forbidden:

- real secrets
- personal data
- customer data
- production credentials
- regulated data

Raw canary values must not be stored in evidence exports.

## ROE Requirements

Rules of engagement must define:

- source systems
- destination systems
- data labels
- volume caps
- record-count caps
- protocol limits
- time window and timezone
- detection stakeholders
- emergency stop conditions

## Approval and Monitoring

Exfiltration simulation remains disabled until explicit purple-team approval and monitoring readiness are recorded. Approval does not execute a simulation; it only allows a future workflow to enter a policy review queue.

## Evidence Boundary

Evidence may record detection outcome, telemetry source, alert latency, control owner, and remediation follow-up. It must not expose sensitive data or raw canary values.
