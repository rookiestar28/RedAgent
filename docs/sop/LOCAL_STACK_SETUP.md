# RedAgent Local Dependency Stack Setup

Architecture contract: compat_091-1
Roadmap owner: compat_092

## Supported Baseline

- Windows 10 22H2 or Windows 11 23H2+ with WSL 2.1.5+ and Docker Desktop using Linux containers, or a supported Linux/WSL environment with Docker Engine and Compose v2.
- Minimum 8 GB host RAM; 16 GB recommended for this and later RedAgent services.
- Python 3.11+, Node 18+, Docker 24+, Compose 2.20+.
- The compat_092 lock supports `linux/amd64` only. Other architectures fail before start until separately locked and tested.

Official prerequisites: https://docs.docker.com/desktop/setup/install/windows-install/ and https://docs.docker.com/desktop/features/wsl/

## One-Command Lifecycle

From the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\redagent_local_stack.py doctor --json
.\.venv\Scripts\python.exe scripts\redagent_local_stack.py start --json
```

`start` validates config and prerequisites, generates ignored local bootstrap credentials plus `.local/redagent/runtime/identity-providers.json`, validates Compose, pulls only digest-pinned PostgreSQL/Keycloak images, waits for health, and reports loopback endpoints. The generated identity configuration is non-secret and follows the effective persisted Keycloak port, including a bounded fallback port selected for a fresh implicit runtime. For a local compat_094 identity runtime, use that generated file instead of the tracked template. It does not start RedAgent application APIs, scanners, runners, targets, connectors, or AI providers.

Operations:

```powershell
.\.venv\Scripts\python.exe scripts\redagent_local_stack.py config --json
.\.venv\Scripts\python.exe scripts\redagent_local_stack.py status --json
.\.venv\Scripts\python.exe scripts\redagent_local_stack.py stop --json
.\.venv\Scripts\python.exe scripts\redagent_local_stack.py reset --confirm-local-reset --json
```

`stop` preserves local volumes. `reset` deletes only the validated selected Compose project's
volumes and its verified `.local/` runtime state; it requires explicit confirmation. Never copy
`.local/` into source control or support tickets.

## Configuration

Safe optional environment variables are `REDAGENT_BIND_HOST`, `REDAGENT_POSTGRES_PORT`,
`REDAGENT_KEYCLOAK_PORT`, `REDAGENT_TEMPORAL_PORT`, `REDAGENT_RUSTFS_PORT`,
`REDAGENT_COMPOSE_PROJECT_NAME`, `REDAGENT_STATE_DIR`, and lifecycle timeouts. The bind must be an
IPv4 loopback address, ports must be unique/unprivileged, the Compose project must match
`[a-z0-9][a-z0-9_-]{0,62}`, and the state directory must be a non-reparse named child of ignored
`.local/`; repository root and tracked directories are rejected before any runtime secret is written.

For parallel or separate checkouts, choose a unique Compose project name, state directory, and four
free loopback ports. The selected project identity is persisted with the runtime coordinates so a
later `status`, `stop`, or confirmed `reset` cannot fall back to another checkout's containers or
volumes.

Runtime state created before project identity was persisted is treated as unowned. For such a legacy
env, default `start`, `status`, `stop`, and confirmed `reset` fail before any Compose call. Migrate it
by setting a unique non-default `REDAGENT_COMPOSE_PROJECT_NAME` together with the matching
`REDAGENT_STATE_DIR`, then run `start`; the identity is written before Compose is accessed and later
lifecycle commands use only that stored identity. The read-only `doctor` and `config` commands do not
establish ownership or migrate state.

compat_092 rejects any `REDAGENT_*PASSWORD`, `*TOKEN`, `*SECRET`, non-local profile, or attempt to enable active targets, real scanners, privileged runners, or external delivery. Local credentials are generated into ignored state; there are no committed default passwords.

## Deterministic Diagnosis

- `docker_engine_unavailable`: start Docker Desktop/Linux engine and rerun `doctor`; the tool does not perform privileged installation.
- `docker_compose_version_unsupported`: install Compose 2.20+.
- `docker_engine_platform_unsupported`: use the locked `linux/amd64` profile.
- `port_conflict`: select another loopback port and rerun before start.
- `runtime_compose_project_missing`: the selected legacy state has no proven Compose ownership; set
  a unique non-default project name and rerun `start` to migrate it before lifecycle operations.
- `compose_*_failed`: inspect sanitized diagnostics; credentials are redacted.
- Keycloak import is skipped on restart when the realm already exists. Use the guarded reset only when discarding local synthetic identity state is intended.

## Dependency Updates

Re-query manifests with `docker buildx imagetools inspect`, update tag/index/platform digests together, review license/security/provenance, validate Compose, run live start/restart/stop/reset smoke, regenerate SBOM, and run the full repository gate. Do not substitute `latest` or a tag without a digest. Sigstore verification may be added only with a reviewed upstream certificate identity/issuer or key policy; digest pinning must remain mandatory.
