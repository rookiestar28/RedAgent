# Development Environment Separation

This repository keeps ordinary product development separate from controlled security-tool
execution. Choose a local checkout path appropriate for your operating system; no specific drive,
user profile, or WSL distribution is required.

## Roles

| Environment | Role | Notes |
| --- | --- | --- |
| Primary workspace | Product development and repository validation | Use a trusted, project-local virtual environment and keep generated state ignored. |
| Linux compatibility environment | Cross-platform development and tests | Follow the public testing guide and use repository-local temporary directories. |
| Isolated security lab | Approved tool execution only | Do not use a security lab as the primary source checkout or general development environment. |

## Rules

- Keep ordinary development and security-tool execution in separate environments.
- Do not run security tools directly against the product checkout.
- Do not clone payload-bearing external offensive repositories into the product workspace.
- Exchange only explicitly approved, sanitized artifacts such as JSON, SARIF, text reports, or
  bounded local-lab outputs.
- A controlled runner or lab node requires an explicit authorization record, target scope, command
  boundary, evidence policy, cleanup procedure, and rollback plan.
- Never treat local tool installation or environment availability as authorization to execute a
  security assessment.

For repeatable local validation, see [Testing](TESTING.md) and [E2E Testing](E2E_TESTING.md).
