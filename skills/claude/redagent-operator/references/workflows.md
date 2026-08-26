# RedAgent Operator Workflows

## Specification Collection

Ask for missing fields in this order:

1. Engagement objective.
2. Assessment type.
3. Owner, approver, and operator labels.
4. Authorized targets.
5. Excluded targets.
6. Environment and sensitivity.
7. Allowed categories.
8. Forbidden actions.
9. Testing window and timezone.
10. Rate limit, concurrency cap, request cap, and timeout cap.
11. Credential or session requirements.
12. Evidence, command-log, and report paths.
13. Emergency stop method.
14. Data handling and redaction requirements.
15. Explicit authorization confirmation.

## Summary and Confirmation

Before execute mode, present:

- objective
- assessment type
- owner and approver
- operator
- authorized targets
- excluded targets
- window
- limits
- forbidden actions
- evidence paths
- emergency stop method
- policy decision requirement

Ask the user to confirm that the summary is accurate and authorized.

## Dry-Run Flow

1. Build JSON with `mode` set to `dry_run`.
2. Run the repo-local command contract.
3. Parse stdout JSON.
4. If denied, explain `refusal_reason` and request corrected fields.
5. If allowed, state what remains required for execute mode.

## Execute-Request Flow

1. Require final confirmation and current allow policy decision.
2. Run the repo-local command contract with `--mode execute`.
3. Treat `contract_authorized_delegate_not_invoked` as a handoff state, not a completed test.
4. Do not run the real assessment wrapper until a later roadmap item explicitly provides that integration.

## Evidence Review and Report Drafting

Use repo-local artifacts only. Do not claim exploitability unless evidence supports it.
