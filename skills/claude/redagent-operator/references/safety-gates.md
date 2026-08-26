# RedAgent Operator Safety Gates

These gates apply after `/redagent-operator` is invoked.

## Gate 1: Arguments Are Not Scope

`$ARGUMENTS` can describe the user's intent, but it is not an authorization record. Always collect and validate required fields before preparing a command-contract request.

## Gate 2: Required Authorization Inputs

Collect:

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

Missing or conflicting inputs block execute mode.

## Gate 3: Tool Permission Boundary

This skill does not declare `allowed-tools`. If a future version adds them, grants must be narrow and validated because they are convenience preapprovals, not a complete restriction layer.

## Gate 4: Safety Boundaries

Never:

- widen target scope
- infer ownership
- build shell commands from free-form user input
- contact targets directly from the skill
- execute external reference repository code or content
- restore quarantined files
- store raw credentials or sensitive target data

## Gate 5: Evidence

Evidence paths must be repo-relative and must stay under `.local/validation`, `.tmp`, or `reports` as required by the command contract.
