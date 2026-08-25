# Local Lab Target Harness Policy

compat_012 defines the local lab target harness boundary. It does not start, stop, probe, scan, or reset lab applications by itself.

## Allowed Lab Targets

The harness may register only these lab target kinds:

- OWASP Juice Shop as `juice_shop`
- OWASP crAPI as `crapi`

Registration requires a current `SandboxApproval` that names the allowed lab target kind and allowed action. The registered origin must be loopback/local only, such as `http://localhost:3000` or `http://127.0.0.1:8888`.

## Forbidden Targets

The harness must reject:

- public demo instances
- non-local hosts
- origins containing credentials
- origins containing paths, query strings, or fragments
- enterprise production targets
- any target not covered by a current sandbox approval

## Lab-Only Classification

Every registered lab target must be classified as:

- `TargetType.LAB_TARGET`
- `EnvironmentType.LAB`
- `TestMode.LAB_ONLY_RUN`
- label `lab-only`

This prevents local lab services from being confused with enterprise web origins, domains, API specs, or production assets.

## Health Checks

compat_012 health checks are request metadata only. The harness can build `LabHealthCheckRequest` values that specify method, URL, expected statuses, and timeout. compat_012 must not execute the request.

## Reset and Teardown

Reset and teardown are documented as manual procedure metadata:

- reset: stop the local instance, reset local disposable state, restart, and generate a new approved health-check request
- teardown: stop the local instance, remove local disposable state, and record teardown evidence

Any future automation that starts, resets, or tears down lab services requires a separate sandbox plan and its own validation evidence.
