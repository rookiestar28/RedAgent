# Finding Review Workflow Policy

compat_021 defines the review workflow for scanner alerts and normalized findings. It does not execute retests.

## Review Decisions

Every review decision must include:

- reviewer user ID
- rationale
- timestamp
- source and destination status
- immutable compat_008 audit event

Decisions without rationale are invalid.

## Supported States

The workflow supports:

- `new`
- `needs_review`
- `confirmed`
- `false_positive`
- `risk_accepted`
- `fixed`
- `retest_requested`
- `retest_passed`
- `retest_failed`

Existing legacy states such as `raw_alert`, `retest_required`, and `remediated` remain accepted for compatibility and metrics mapping.

## Retest Planning

Retest jobs are planned metadata only. A retest plan must inherit:

- original target
- original test mode
- original engagement scope
- original policy decision ID
- original policy expiry
- original interaction and timeout limits

Retest execution requires later policy gates and item-specific adapters.
