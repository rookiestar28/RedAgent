# RedAgent Operator Safety Gates

Use these gates before any RedAgent workflow.

## Gate 1: Repository Context

- Confirm the working directory is the RedAgent repository.
- Read `CONTRIBUTING.md`, `PUBLIC_RELEASE.md`, and the relevant `.local/validation/` item when implementation work is requested.
- Do not edit outside the workspace.

## Gate 2: Authorization

The skill does not authorize work. Required user-provided fields must be collected before command-contract preparation:

- owner label
- approver label
- operator label
- authorization label
- approved ROE status
- explicit authorization confirmation
- authorized targets
- excluded targets
- allowed categories
- forbidden actions
- testing window with timezone
- emergency stop method

Missing or conflicting authorization inputs block execute mode.

## Gate 3: Safety Boundaries

Default to dry-run unless all execute-mode requirements are complete.

Never:

- widen target scope
- infer target ownership
- build shell commands from free-form user input
- contact targets directly from the skill
- execute external reference repository code or content
- restore quarantined files
- store raw credentials or sensitive target data

## Gate 4: Evidence

Evidence paths must be repo-relative and must stay under `.local/validation`, `.tmp`, or `reports` as required by the command contract.

Evidence and reports must preserve:

- skill client
- request id
- specification summary
- confirmation state
- policy decision
- target scope
- timestamps
- redaction state
- artifact paths
