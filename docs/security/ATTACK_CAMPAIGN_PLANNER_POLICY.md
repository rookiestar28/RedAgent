# ATT&CK Campaign Planner Policy

Date: 2026-07-08
Roadmap item: compat_022
Branch: `dev`

## Purpose

compat_022 defines reviewable adversary-emulation campaign planning. It does not execute campaigns, atomic tests, agents, payloads, cloud actions, or commands.

## Required Campaign Fields

Campaigns must define:

- ATT&CK tactic and technique selections
- prerequisites and required permissions
- target classes
- allowed time windows
- expected telemetry
- safety class
- risk class
- detection objectives
- cleanup needs

Missing fields fail validation.

## Preview Requirements

Campaign preview must show:

- blast radius
- target class count
- technique count
- required permissions
- cleanup needs
- detection objectives
- execution disabled flag

Preview exists to support review before later roadmap items consider lab-only execution.

## Reviewable Export

Exported campaign plans include ATT&CK mappings, expected telemetry, prerequisites, allowed windows, safety/risk class, preview, and deterministic plan hash. Exported plans must set `execution_enabled=false`.

## Execution Boundary

compat_022 must not include execution functions. compat_023 and later items may consume reviewable campaign plans, but any execution requires separate lab-only or active-policy gates, target scope, evidence handling, cleanup, and full validation.
