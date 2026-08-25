# ZAP Passive Adapter Policy

compat_015 ingests supplied ZAP passive alert metadata. It does not start ZAP, call ZAP APIs, spider targets, active scan, browser-proxy, or contact targets.

## Allowed Input

The adapter may process only:

- compat_006-authorized `PASSIVE_SCAN` captures
- compat_006-authorized `LAB_ONLY_RUN` captures for `LAB_TARGET` values
- ZAP passive alert metadata supplied by an already approved capture pipeline

## Forbidden Activity

The adapter must not:

- call ZAP active scan APIs
- call ZAP spider APIs
- start or control a ZAP process
- send browser or HTTP traffic
- fuzz, brute force, exploit, or validate vulnerabilities

Active scan and spider entrypoints are explicit policy-denial stubs until a future compat_017/compat_018 implementation is accepted.

## Evidence and Findings

Request and response metadata must be redacted before evidence storage. Cookies, authorization values, API keys, tokens, passwords, and secret-like fields are replaced with `[redacted]`.

ZAP risk and confidence values are normalized into the internal compat_011 finding schema. ZAP `plugin_id` is preserved as `source_rule_id`, and evidence links preserve compat_008 integrity hashes.
