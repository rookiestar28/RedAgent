# Control Plane API Local SOP

Status: Maintained local operational baseline
Owner: Control-plane platform team
Safety boundary: local synthetic metadata only; no assessment target, scanner, runner, payload, or external connector

## Preconditions

- Use the repository-local `.venv` and Node 20.9+ on 20.x, 22.x, or 24+ where the full gate is required.
- Docker Desktop must be available with the compat_092 digest-pinned PostgreSQL and Keycloak images.
- The compat_093 server is intentionally loopback-only until compat_094 installs production OIDC/session enforcement. Do not proxy or expose it to another host.
- The deterministic test issuer accepts synthetic headers only when the operator explicitly supplies `--enable-test-issuer`. It is disabled by default.

## Start Dependencies and Apply the Reviewed Migration

```powershell
# Optional only before first start: choose a validated free loopback port. Omit for the default 58080.
$env:REDAGENT_KEYCLOAK_PORT = "58082"
.\.venv\Scripts\python.exe scripts\redagent_local_stack.py start --json

$env:REDAGENT_DATABASE_URL_FILE = (Resolve-Path ".local\redagent\runtime\database-url").Path
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current
```

When enabling the compat_094 identity runtime, use the generated `.local\redagent\runtime\identity-providers.json` path for `REDAGENT_IDENTITY_CONFIG_FILE`; do not use the tracked template for a runtime that selected an alternate Keycloak port. This is only the configuration-path substitution within a complete compat_094 identity setup: `REDAGENT_IDENTITY_CONFIG_FILE`, `REDAGENT_IDENTITY_PROVIDER_ID`, `REDAGENT_SESSION_KEY_FILE`, and `REDAGENT_PUBLIC_ORIGIN` must be supplied together, or startup fails closed with `identity_runtime_configuration_incomplete`.

Expected migration head: `0025_r123_closed_loop`. Application startup never runs migrations or `create_all`.

## Launch the API

Identity-denial baseline (recommended default):

```powershell
.\.venv\Scripts\python.exe scripts\redagent_control_plane_api.py --host 127.0.0.1 --port 58000
```

Explicit synthetic integration mode:

```powershell
.\.venv\Scripts\python.exe scripts\redagent_control_plane_api.py --host 127.0.0.1 --port 58000 --enable-test-issuer
```

The CLI rejects non-loopback binds and privileged ports. Database credentials remain in the ignored workspace-local URL file and must never be copied into commands or logs.

## Health and Request Guard Expectations

- `GET /health/live` proves process liveness.
- `GET /health/ready` proves PostgreSQL connectivity and the exact Alembic revision.
- Every `/api/v1` route requires a validated identity context and permission.
- Mutations also require `Idempotency-Key` and `X-RedAgent-Policy-Reference`.
- ROE approval and job routes additionally require `X-RedAgent-ROE-Version` matching the governed resource.
- The explicit compat_093 test issuer uses `X-RedAgent-Test-Subject`, `X-RedAgent-Test-Tenant`, and `X-RedAgent-Test-Permissions`. compat_094 replaces this issuer; callers must not treat it as production authentication.

OpenAPI is available at `/openapi.json`. Stable errors contain a code, public message, and correlation ID without SQL, credentials, stack traces, or cross-tenant existence details.

## Shutdown and Recovery

Stop the API with `Ctrl+C`, then stop dependencies without deleting volumes:

```powershell
.\.venv\Scripts\python.exe scripts\redagent_local_stack.py stop --json
```

If readiness reports a schema mismatch, stop the API, inspect `alembic current`, and apply only the reviewed migration path. Never let application startup repair schema automatically. Local destructive reset requires the separate explicit `reset --confirm-local-reset` flow and must not be used against non-local data.
