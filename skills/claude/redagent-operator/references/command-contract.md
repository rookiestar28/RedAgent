# RedAgent Command Contract Usage

Use the repo-local CLI:

```powershell
.venv\Scripts\python.exe scripts\redagent_skill_assess.py --request .tmp\skill-runs\<request-id>\request.json --mode dry_run
```

The CLI writes one JSON object to stdout. Diagnostics go to stderr.

## Request Rules

The request must include collected specifications, authorized targets, requested targets, excluded targets, window, limits, evidence paths, emergency stop method, redaction requirements, and explicit authorization confirmation.

Execute mode also requires:

- final user confirmation
- confirmed-by label
- confirmation timestamp
- current allow policy decision
- policy decision expiry after requested time

## Result Rules

- `decision: "allow"` means the command contract accepted the request.
- `decision: "deny"` means stop or ask for corrected input.
- `refusal_reason` is the user-facing reason to explain.
- `delegated: false` means no test ran.

Do not treat execute contract approval as evidence that a target-facing test occurred.
