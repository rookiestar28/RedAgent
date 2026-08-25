# Job Queue and Runner Contract Policy

Date: 2026-07-08
Roadmap item: compat_010

## Purpose

The job queue and runner contract define safe orchestration boundaries before any scanner, runner, cloud technique, or adversary-emulation capability is enabled.

compat_010 is not an execution engine. It does not start processes, invoke shells, run scanners, contact targets, build containers, or call cloud APIs.

## Job Lifecycle

The required lifecycle states are:

- planned
- authorized
- queued
- dispatched
- running
- cleanup
- completed
- failed
- cancelled
- evidence-locked

Jobs require a current allow policy decision before authorization, queueing, dispatch, or retry.

## Runner Contract

Runner contracts must include:

- runner identity
- organization id
- capabilities
- policy token reference
- target scope
- timeout
- heartbeat interval
- result schema
- cleanup callback
- optional credential lease reference

Runner contracts contain references and metadata only. They must not contain credentials, raw payloads, shell commands, scanner command lines, or target interaction instructions.

## Callback Rules

Runner callbacks are structured state updates. Duplicate callbacks are rejected. Terminal jobs reject further callbacks. Timeout and cancellation move active jobs to cleanup when cleanup is required.

## Downstream Gates

Queue acceptance is still not active-testing approval. compat_006 scope authorization, compat_030 scheduler safety, compat_029 credential boundaries, compat_017 active policy gate, and adapter-specific approvals remain required before any execution module can interact with targets.
