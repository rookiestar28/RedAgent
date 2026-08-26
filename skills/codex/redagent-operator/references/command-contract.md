# RedAgent Command Contract Usage

Use the repo-local CLI:

```powershell
.venv\Scripts\python.exe scripts\redagent_skill_assess.py --request .tmp\skill-runs\<request-id>\request.json --mode dry_run
```

The CLI reads JSON and writes exactly one JSON object to stdout. Diagnostics go to stderr.

## Minimal Request Shape

```json
{
  "request_id": "req-example",
  "skill_client": "codex",
  "mode": "dry_run",
  "assessment_type": "passive_metadata",
  "requested_at": "2026-07-09T01:30:00+08:00",
  "organization_id": "org-example",
  "engagement_id": "eng-example",
  "owner_label": "Owner Name",
  "approver_label": "Approver Name",
  "operator_label": "Codex",
  "authorization_label": "Approved internal assessment",
  "roe_status": "approved",
  "authorization_confirmed": true,
  "authorized_targets": [{"target_type": "domain", "value": "example.test"}],
  "requested_targets": [{"target_type": "domain", "value": "example.test"}],
  "excluded_targets": [],
  "environment": "staging",
  "sensitivity": "metadata_only",
  "allowed_categories": ["passive_metadata"],
  "forbidden_actions": ["exploit", "brute_force", "fuzzing"],
  "window": {
    "start": "2026-07-09T01:00:00+08:00",
    "end": "2026-07-09T02:00:00+08:00"
  },
  "limits": {
    "rate_limit_per_second": 1,
    "max_concurrency": 1,
    "max_interactions": 50,
    "timeout_seconds": 900
  },
  "credential_requirement": "not_required",
  "output_paths": {
    "command_log_path": ".local/validation/automated-runs/req-example-COMMAND_LOG.md",
    "evidence_dir": ".tmp/skill-runs/req-example",
    "report_path": "reports/assessments/req-example-report.md"
  },
  "emergency_stop_method": "email",
  "data_handling": {
    "redaction_required": true,
    "retention_class": "metadata",
    "export_allowed": false
  },
  "user_confirmation": {
    "confirmed": false
  }
}
```

## Execute Mode Additions

Execute-mode requests must include:

- `user_confirmation.confirmed: true`
- `user_confirmation.confirmed_by`
- `user_confirmation.confirmed_at`
- `policy_decision.decision_id`
- `policy_decision.outcome: "allow"`
- `policy_decision.expires_at`

If these fields are missing, treat the denial as expected and ask for the missing approval or confirmation. Do not bypass the contract.

## Result Handling

Use stdout JSON only:

- `decision: "allow"` means the command contract accepted the request.
- `decision: "deny"` means the skill must stop or ask for corrected input.
- `refusal_reason` is the user-facing reason to explain.
- `next_action` tells the next safe step.
- `delegated: false` means no test ran.

Do not treat `execute` contract approval as evidence that a target-facing test has occurred.
