# Rules of Engagement Template

Date: 2026-07-07
Status: Template baseline

Use this template for every engagement before any target interaction. Missing required fields keep the engagement in `draft` status.

## 1. Engagement Summary

| Field | Value |
| --- | --- |
| Engagement ID | `TBD` |
| Engagement name | `TBD` |
| Status | `draft` |
| Authorization level | `none`, `draft`, `passive-approved`, `active-approved`, `lab-only`, or `suspended` |
| Business owner | `TBD` |
| Security owner | `TBD` |
| Operator lead | `TBD` |
| Reviewer | `TBD` |
| Time zone | `TBD` |
| Start window | `TBD` |
| End window | `TBD` |

## 2. Authorization Basis

Required:

- Who approved testing.
- What authority they have over the target.
- Date and channel of approval.
- Scope version approved.
- Any contractual or legal constraints.

Approval statement:

```text
TBD
```

## 3. Target Scope

### In-Scope Targets

| Target | Type | Environment | Owner | Allowed categories | Notes |
| --- | --- | --- | --- | --- | --- |
| `TBD` | web origin/domain/API/cloud/lab | production/staging/lab | `TBD` | `TBD` | `TBD` |

### Explicitly Out-of-Scope

List all exclusions:

- third-party hosted systems not owned or explicitly authorized
- unrelated subdomains
- IP ranges not listed in the allowlist
- cloud accounts/projects/subscriptions not listed in the allowlist
- employee devices and personal accounts
- social media and third-party identity providers unless separately approved
- customer data, payment data, and personal data access beyond approved proof points

## 4. Allowed Test Categories

| Category | Status | Required gates |
| --- | --- | --- |
| Documentation and planning | Allowed when authorization exists | compat_001/compat_002 |
| Passive public-source research with no target traffic | Requires scope record | compat_002/compat_006 record |
| Passive target metadata checks | Requires passive approval | compat_006 plus compat_013 |
| Passive DAST review | Requires passive approval | compat_006 plus compat_015 |
| Active web/API testing | Disabled by default | compat_006 plus compat_017 plus adapter-specific gate |
| Authenticated testing | Disabled by default | compat_006 plus compat_017 plus compat_020 |
| Adversary emulation | Disabled by default | compat_022 plus compat_017 plus lab/runner gate |
| Cloud technique testing | Disabled by default | compat_024 and explicit cloud account approval |
| Endpoint runner activity | Disabled by default | compat_025 and later runner gate |

## 5. Forbidden Actions

Unless separately approved in writing and implemented behind tested roadmap gates, the following are forbidden:

- denial-of-service or stress testing
- destructive payloads
- malware handling or execution
- phishing or social engineering
- credential stuffing, password spraying, brute force, or MFA fatigue testing
- persistence, lateral movement, or endpoint agent deployment
- data exfiltration beyond approved proof-of-impact
- modifying production data
- bypassing logging, monitoring, WAF, EDR, or rate limits
- testing third-party systems or public demo systems
- vulnerability disclosure to third parties without owner approval

## 6. Rate, Volume, and Concurrency Limits

Required before target interaction:

| Limit | Value |
| --- | --- |
| Max requests per second | `TBD` |
| Max concurrent requests | `TBD` |
| Max total requests per job | `TBD` |
| Max job duration | `TBD` |
| Cooldown between jobs | `TBD` |
| Allowed user agents | `TBD` |

If limits are unknown, the engagement remains in `draft`.

## 7. Credentials and Data Handling

Required fields:

- credential source and owner
- storage method
- expiration
- rotation plan
- allowed roles
- redaction requirements
- prohibited evidence content

Rules:

- Do not store credentials in repository files, command logs, screenshots, or reports.
- Do not include cookies, tokens, private keys, API keys, or passwords in evidence.
- Use synthetic accounts and data where possible.

## 8. Evidence Handling

Each evidence item must record:

- engagement ID
- target
- test category
- operator
- timestamp
- command or module identity
- policy decision
- redaction status
- hash or integrity marker
- retention class

Evidence must be reviewed before report export.

## 9. Stop Conditions

Testing must stop immediately if:

- scope or ownership is ambiguous
- an out-of-scope target is contacted
- unexpected sensitive data appears
- target availability or performance degrades
- alerts or incidents indicate unintended impact
- an owner, responder, legal contact, or operator lead requests a stop
- rate limits cannot be enforced
- cleanup fails

## 10. Emergency Contacts

| Role | Name | Contact method | Stop authority |
| --- | --- | --- | --- |
| Business owner | `TBD` | `TBD` | yes/no |
| Security owner | `TBD` | `TBD` | yes/no |
| Incident responder | `TBD` | `TBD` | yes/no |
| Operator lead | `TBD` | `TBD` | yes/no |

Do not store personal phone numbers, private emails, tokens, or credentials in this repository unless the user explicitly approves and the data is proven safe to track.

## 11. Reporting

Required:

- report recipients
- classification level
- redaction requirements
- disclosure restrictions
- retention period
- follow-up workflow

## 12. Approval

| Role | Approval status | Date | Notes |
| --- | --- | --- | --- |
| Business owner | `TBD` | `TBD` | `TBD` |
| Security owner | `TBD` | `TBD` | `TBD` |
| Operator lead | `TBD` | `TBD` | `TBD` |

No target interaction is allowed until required approvals, contacts, windows, allowed categories, and rate limits are complete.
