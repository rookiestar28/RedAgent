# Scheduling, Quotas, and Safety Controls Policy

Date: 2026-07-08
Roadmap item: compat_030

## Purpose

Scheduling and quota controls prevent resource exhaustion, accidental broad scans, and noisy concurrent testing. compat_030 defines local policy contracts only; it does not dispatch runners or execute tests.

## Required Limits

The scheduler must enforce:

- maximum active jobs
- per-engagement concurrency
- per-target concurrency
- per-module concurrency
- per-runner concurrency
- maximum requests per job
- maximum duration per job
- cooldown windows

All limits fail closed when missing or invalid.

## Operator Controls

Operators can pause, resume, and cancel jobs only with an explicit reason. Control actions must produce audit events and preserve the actor and reason.

## Execution Boundary

Queue acceptance is not execution authorization. Future compat_010 job state management, compat_006 scope authorization, compat_017 active policy gate, and adapter-specific controls remain required before any runner dispatch or target interaction.
