# Observability and Incident Response Policy

Date: 2026-07-08
Status: compat_033 baseline

## Purpose

This policy defines the minimum observability and incident-response coverage for the RedAgent platform before release acceptance. The platform must be able to detect misuse, preserve evidence, and guide operators through high-impact incidents without exposing sensitive values in logs.

## Required Metrics

The platform must track:

- job state;
- runner heartbeat;
- queue depth;
- scan volume;
- policy denials;
- auth events;
- audit writes;
- evidence writes; and
- connector failures.

## Required Alerts

Alerts must exist for:

- out-of-scope attempts;
- failed cleanup;
- runner anomalies;
- auth anomalies; and
- evidence integrity failures.

Every alert requires a signal, severity, route, enabled state, and runbook scenario.

## Incident Response Runbooks

Runbooks must cover:

- compromised account;
- rogue runner;
- leaked evidence;
- failed cleanup; and
- accidental production test.

Each runbook must include containment, evidence handling, escalation, and recovery steps.

## Log Safety

Operational logs must be validated as sensitive-value-free before they are accepted as release evidence. Validation must reject credential-like indicators such as bearer authorization material, API key labels, password assignments, token assignments, and similar sensitive markers.

Log streams must define owner, redaction status, sensitive-value validation status, and retention.

## Safety Boundary

compat_033 does not deploy telemetry infrastructure or query external systems. It models local observability and incident-response readiness that compat_034 must use as operational review evidence.
