# Active Testing Policy Gate

Date: 2026-07-08
Roadmap item: compat_017
Branch: `dev`

## Purpose

compat_017 defines the mandatory fail-closed policy gate for future active testing. It does not execute scans, templates, payloads, exploits, fuzzing, or adversary emulation. It only decides whether a future active job request is policy-authorized and provides a kill-switch cancellation plan.

## Required Active Authorization Inputs

An active job request must have:

- approved engagement scope
- exact target allowlist match
- active testing mode in the approved time window
- active module permission
- operator confirmation before request time
- rate limit
- max request count
- max duration
- payload class allowlist
- concurrency limit
- stop-condition policy
- emergency contact when required by stop conditions

If any required input is absent, invalid, expired, or out of scope, the policy gate must deny the request.

## Payload Class Policy

compat_017 supports payload-class decisions only. The gate recognizes safe metadata, standard active, authenticated active, intrusive, and destructive classes. Destructive payload class is denied in compat_017. Future intrusive or destructive testing requires separate roadmap planning, authorization, and tests.

## Stop Conditions

Stop conditions must include:

- stop on scope violation
- stop on error-rate threshold
- positive max error count
- emergency contact when required

Operators must acknowledge scope, risk, and stop conditions before an active request can be authorized.

## Kill Switch

The kill switch cancels queued, dispatched, and running active-gated jobs. It leaves passive and terminal jobs unchanged. Each kill-switch plan records an compat_008 `scheduler_control` audit event with reason and cancelled job count.

## Adapter Boundary

compat_018, compat_019, and any future active adapter must call the compat_017 policy gate before queueing or dispatching active work. No active adapter may treat a missing policy decision as approval.
