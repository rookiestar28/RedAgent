# Exception Planning Policy

compat_044 defines the planning-only governance boundary for specialized assessment domains that are high-risk and outside the MVP.

## Covered Domains

- Social engineering
- Physical security
- Wireless
- IoT
- OT

## Execution Boundary

compat_044 must not enable execution. It may create templates, validate required approval evidence, and route a plan to exception review. It must not conduct field activity, interact with devices, use RF capabilities, access facilities, contact human subjects, send messages, or run specialized tooling.

## Required Controls

Each specialized plan requires:

- owner
- legal/privacy review
- safety plan
- location/environment scope
- emergency stop method
- evidence boundary
- excluded actions

Wireless, IoT, OT, and physical planning also require:

- asset inventory
- safety constraints
- lab or non-production preference and rationale

Human-subject planning also requires:

- privacy-aware aggregate metrics
- personal-data minimization
- no unnecessary personal data collection

## MVP Boundary

These domains remain outside the MVP until a later explicit roadmap promotion decision. A promotion decision must be handled by a separate roadmap item with legal, privacy, safety, owner, and operational approval.
