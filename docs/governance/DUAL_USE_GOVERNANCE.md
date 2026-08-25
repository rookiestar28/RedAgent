# Dual-Use Governance Policy

Date: 2026-07-07
Status: Initial governance baseline

## Purpose

This repository builds an enterprise red-team testing platform. The platform is dual-use: the same concepts that help an authorized security team validate defenses can harm third parties if scope, authorization, execution controls, evidence handling, or cleanup are weak.

The default rule is therefore simple: no target activity is permitted unless the repository contains an explicit authorization record, approved scope, allowed test categories, safety limits, evidence handling rules, and stop conditions for that engagement.

## Binding Principles

1. Authorization before activity: every target must have a written authorization basis before any target interaction.
2. Scope before tools: operators must define allowed targets, forbidden targets, windows, modules, rate limits, and stop conditions before selecting a tool or technique.
3. Safe defaults: new execution paths are disabled until policy-approved and tested.
4. Least capability: runners receive only the target, capability, time window, and credentials required for a specific job.
5. Evidence integrity: every sensitive action must produce traceable audit and evidence records without leaking secrets.
6. Cleanup and reversibility: tests that create state require explicit cleanup and failure handling before approval.
7. No untrusted execution: external reference repositories are design inputs only and must not be executed.
8. Emergency stop: engagement owners and operators must be able to stop activity immediately.

## Authorization Levels

| Level | Meaning | Permitted activity |
| --- | --- | --- |
| `none` | No written authorization exists | Documentation and internal planning only |
| `draft` | User or owner has stated authorization, but minimum ROE fields are incomplete | Documentation and approval workflow only |
| `passive-approved` | ROE covers owner, targets, windows, contacts, passive categories, rate limits, and evidence handling | Approved passive checks only |
| `active-approved` | Passive approval plus compat_017 active policy gate, explicit active categories, and operator confirmation | Approved active checks only |
| `lab-only` | Target is approved only in a local or isolated lab | Lab execution only |
| `suspended` | Stop condition, ambiguity, incident, or owner request paused the engagement | No activity until reapproved |

## Minimum Engagement Record

An engagement record must define:

- authorization basis and approver
- target owner
- target allowlist
- forbidden targets and inherited exclusions
- target environment and sensitivity
- allowed test categories
- forbidden actions
- test windows and time zone
- rate limits and concurrency limits
- emergency contacts and stop authority
- evidence handling and retention
- credential handling, if any
- reporting recipients
- cleanup requirements
- sign-off status

If any minimum field is missing, the engagement stays at `draft` and no target interaction is allowed.

## Required Gates by Test Class

| Test class | Required roadmap gates before execution |
| --- | --- |
| Documentation-only planning | compat_001 baseline |
| Target scope and ROE creation | compat_001 baseline; compat_002 governance docs |
| Passive metadata checks | compat_006 authorization record; compat_013 passive module policy and tests |
| Passive ZAP-derived review | compat_006 authorization record; compat_015 passive adapter policy and tests |
| Controlled active DAST | compat_006 authorization record; compat_017 active policy gate; compat_018 adapter gate |
| Controlled Nuclei execution | compat_006 authorization record; compat_016 metadata review; compat_017 policy gate; compat_019 adapter gate |
| Authenticated testing | compat_006 authorization record; compat_017 policy gate; compat_020 credential/session controls |
| Adversary emulation | compat_022 planner; compat_017 policy gate; lab-only or separately approved runner gates |
| Cloud technique execution | compat_024 cloud lifecycle gate and explicit cloud account approval |
| Endpoint runner activity | compat_025 isolation design and later approved runner implementation |

## Prohibited by Default

The following are prohibited unless a later roadmap item explicitly implements and validates the required controls:

- internet-wide scanning
- testing third-party systems without written authorization
- destructive payloads
- malware handling or execution
- credential stuffing, password spraying, or brute force
- phishing or social engineering
- persistent endpoint agents
- production cloud detonation
- autonomous exploitation
- denial-of-service or resource exhaustion tests
- data exfiltration beyond deliberately approved proof points
- bypassing rate limits, WAFs, EDRs, or monitoring outside an approved test case

## Evidence Requirements

Every approved test must produce evidence that can answer:

- who approved the target and test class
- who started the activity
- what target was contacted
- what module or runner was used
- what policy decision allowed it
- when it started and stopped
- what data was collected
- what was redacted
- what cleanup ran
- what integrity hash protects the evidence

Evidence must not include secrets, session tokens, cookies, private keys, personal access material, or unnecessary personal data.

## Stop Conditions

Testing must stop immediately when any of the following occurs:

- target ownership or authorization is unclear
- an out-of-scope host, subdomain, IP, cloud account, or third-party service is reached
- a service outage, material degradation, or unexpected error spike is observed
- sensitive data, credentials, or personal data are exposed beyond approved evidence handling
- a defensive team, owner, legal contact, or incident responder requests a stop
- rate or concurrency limits cannot be enforced
- tool behavior diverges from the approved test class
- cleanup cannot be completed

## Current Repository Posture

Evidence anchors:

- `PUBLIC_RELEASE.md` defines scope-first and safe-default execution principles.
- `CONTRIBUTING.md` prohibits offensive execution without explicit authorization, target scope, safety gates, rollback, and evidence handling.
- `redagent_platform/safety.py` keeps external reference execution disabled and enforces `reference/` documentation-only safety.

Current state:

- compat_001 is accepted.
- compat_002 governance documentation is being established.
- compat_006 authorization engine is not implemented.
- compat_017 active testing policy gate is not implemented.
- No live target testing is permitted by the platform at this stage.
