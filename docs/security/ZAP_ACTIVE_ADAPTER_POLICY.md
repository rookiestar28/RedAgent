# ZAP Active Adapter Policy

Date: 2026-07-08
Roadmap item: compat_018
Branch: `dev`

## Purpose

compat_018 defines the ZAP active adapter boundary after compat_017. It creates policy-gated scan plans and normalizes supplied ZAP active alert metadata. It does not start ZAP, call ZAP APIs, spider targets, active-scan targets, replay sessions, deliver payloads, or contact any network target.

## Required Gates

A ZAP active scan plan requires:

- an allowed compat_017 active policy decision and policy grant
- scan policy selection
- warning display and acknowledgement before plan confirmation
- target scope and active mode already authorized by compat_017
- timeout, request cap, and rate limit from the active request
- cancellation support
- lab validation before non-lab target plans
- authenticated context reference only when approved and target/mode matched

## Warning Acknowledgement

Active scan warnings must be presented and stored before plan confirmation. The acknowledgement records warning IDs, operator ID, acknowledgement timestamp, and display confirmation. Missing or incomplete acknowledgement denies the plan.

## Lab Validation

Enterprise target plans require a passed lab validation record for the selected scan policy. Lab validation evidence is referenced by ID only. Future live execution still requires separate runner and environment controls.

## Evidence and Finding Normalization

ZAP active alert metadata may be converted into:

- compat_008 scanner-output evidence with sanitized content
- compat_011 findings with scanner rule ID, risk, confidence, evidence links, and reproduction summary

Adapter output must not store raw credential material, cookies, private keys, session values, or unredacted active scanner output.

## Cancellation

Every scan plan must support cancellation. Cancellation creates an compat_008 `scheduler_control` audit event and returns a cancellation plan. Future runners must wire this plan into actual process/API cancellation before live scanning is enabled.
