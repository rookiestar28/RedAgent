# Secure SDLC and Supply Chain Policy

Date: 2026-07-08
Status: compat_004 baseline

## Purpose

This policy defines the minimum secure software development and supply-chain controls for the RedAgent platform. The platform is dual-use, so engineering controls must prevent unsafe execution, secret leakage, unreviewed dependencies, and unverifiable build artifacts before feature velocity increases.

## Dependency Policy

- Dependencies must be declared in repo-tracked manifests: `requirements-dev.txt`, `pyproject.toml`, `package.json`, and `package-lock.json`.
- Runtime dependencies should be minimized. New production dependencies require a roadmap item, owner, reason, license review, and security review.
- Development dependencies must be limited to test, validation, formatting, and local tooling needs.
- Lockfiles must be committed for ecosystems that use lockfiles.
- Dependency updates must run the full repository gate before acceptance.
- External reference repositories under `reference/` are not dependencies and must not be executed.

## SBOM Generation

- Local SBOM generation is required as part of the full gate.
- The baseline SBOM is generated under ignored `.tmp/sbom/` by `scripts/validate_secure_sdlc.py`.
- SBOM output must not include secrets, tokens, cookies, private keys, target data, or raw evidence.
- Tracked reports may cite SBOM summaries, but generated SBOM artifacts remain local unless a later item defines a tracked export policy.

## Vulnerability Scanning

- `npm audit --audit-level=moderate` runs in the full gate for Node dependencies.
- Python dependency vulnerability scanning is documented as a follow-up expansion point once production Python dependencies exist or a dedicated scanner is selected.
- CISA KEV, EPSS, CVSS, and CWE references should be used for future vulnerability prioritization, not as replacements for package scanning.
- Vulnerability scan failures must be fixed, risk-accepted in an implementation record, or explicitly scoped out before acceptance.

## Secret Scanning

- `detect-secrets` runs in pre-commit and the full gate.
- Secrets must never appear in source files, command logs, generated reports, screenshots, traces, videos, evidence artifacts, SBOM output, or exported issues.
- If a secret is suspected, stop work, remove the material from tracked files, rotate the credential if applicable, and document the incident boundary without recording the secret value.

## License Review

- Package lock metadata must include license information where available.
- New third-party dependencies require license review before acceptance.
- Dependencies with unknown, custom, copyleft, source-available, or commercial-use-restricted licenses require explicit review before use.
- External reference projects may inform design but must not be copied, vendored, or treated as product dependencies.

## Build Artifact and Log Policy

- Build artifacts, dependency folders, caches, reports, screenshots, traces, videos, `.tmp/`, `.venv/`, `.venv-wsl/`, `node_modules/`, and `.pre-commit-cache/` remain untracked unless a later policy explicitly allows a sanitized artifact.
- Command logs must be repo-local under `.local/validation/` and secret-free.
- Full-gate logs must state whether target interaction or external reference execution occurred.

## Required Local Gate

The local full gate must run:

- reference directory safety check
- secure SDLC validator and local SBOM generation
- `detect-secrets`
- all pre-commit hooks
- unit tests
- Node version check
- `npm install`
- `npm audit --audit-level=moderate`
- Playwright E2E when frontend exists

## CI Baseline

Until remote CI is added, `scripts/run_full_tests_windows.ps1` and `scripts/run_full_tests_linux.sh` are the CI-parity gates. A later CI item must invoke the same checks or a stricter equivalent.
