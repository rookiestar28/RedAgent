# Email Resilience Policy

compat_043 defines the safe baseline for email domain-abuse and phishing-resilience assessment.

## Execution Boundary

The compat_043 module is policy and planning only. It must not perform DNS lookups, HTTP requests, SMTP actions, mailbox access, email sending, credential collection, attachment delivery, or campaign execution.

Read-only domain-control checks are represented as observations for:

- SPF
- DKIM
- DMARC
- MX
- HTTPS
- HSTS

## Simulation Gate

Any human-facing phishing simulation must be denied unless all of the following are recorded:

- executive approval
- legal/privacy review
- audience scope
- message review
- schedule
- opt-out and exception handling
- incident-response coordination

An approval decision only permits a future workflow to enter a review queue. It does not execute a campaign.

## Prohibited Activity

The module must block:

- credential collection
- malware attachments
- deceptive third-party branding
- unsanctioned external recipients

## Evidence Boundary

Evidence must avoid personal mailbox content. Campaign outcome evidence should use aggregate metrics where possible.

## Reporting Boundary

Reports must keep domain-control findings separate from human-facing campaign outcomes so infrastructure posture issues are not mixed with training or response outcomes.
