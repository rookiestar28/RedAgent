# Telemetry Feedback Policy

compat_026 defines local telemetry expectation, evidence comparison, and detection coverage reporting.

## Execution Boundary

The compat_026 module must not query SIEM, EDR, cloud audit, credential stores, networks, or external services. It compares already-sanitized local observations against expected telemetry declarations.

## Test Definition Requirements

Telemetry-enabled test definitions must declare:

- expected logs
- SIEM events
- EDR detections
- cloud audit events
- detection owner

## Evidence Boundary

Evidence records observed versus expected telemetry using evidence identifiers. It must not store raw sensitive logs or plaintext credentials.

## Reporting Boundary

Reports must separate observed telemetry from missing gaps and not-evaluated expectations. Unobserved controls must not be represented as passing.

## Integration Credentials

Telemetry integrations must use credential references. Plaintext SIEM, EDR, or cloud-audit credentials are forbidden.
