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

If the user provides all fields at once, validate them and ask only for missing or ambiguous values.

## Summary and Confirmation

Before execute mode, present a concise structured summary:

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

Ask the user to confirm that the summary is accurate and authorized. If the user does not confirm, run only dry-run validation or stop.

## Dry-Run Flow

1. Build a JSON request with `mode` set to `dry_run`.
2. Run the repo-local command contract.
3. Read stdout as JSON.
4. If denied, report the refusal reason and ask for corrected fields.
5. If allowed, summarize next steps and what is still required for execute mode.

## Execute-Request Flow

1. Require final confirmation and current allow policy decision in the JSON request.
2. Run the repo-local command contract with `--mode execute`.
3. Treat `contract_authorized_delegate_not_invoked` as an approval to hand off to a later reviewed integration, not as proof that a test ran.
4. Do not run the real assessment wrapper unless a later roadmap item explicitly provides that integration.

## Evidence Review and Report Drafting

Use repo-local artifacts only:

- `.local/validation/` command logs
- `.tmp/` summarized runtime artifacts when explicitly sanitized
- `reports/` assessment reports
- `docs/engagements/` approved engagement notes

Do not claim exploitability or confirmed vulnerabilities unless the evidence supports the claim.
