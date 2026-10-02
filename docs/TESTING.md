# Public Validation Procedure

Use the repository-local Python environment and Node.js 20.9+ on 20.x, 22.x, or 24+. The Windows full gate is the canonical forced-G2 runner for a complete local acceptance pass:

```powershell
powershell -File scripts/run_full_tests_windows.ps1
```

The historical full-test entry point remains a thin compatibility alias. It must produce the same canonical verification receipt and must not maintain a second legacy receipt format.

For Linux or WSL diagnostics:

```bash
bash scripts/run_full_tests_linux.sh
```

The complete gate includes secret detection, pre-commit validation, backend unit tests, and frontend Playwright tests. Dependencies must be provisioned into the repository-local virtual environment. Node.js must be version 18 or newer.

## Receipt verification

Verify an authoritative receipt by binding all expected claims:

```powershell
.venv\Scripts\python.exe scripts/run_validation_gate.py verify `
  --receipt .tmp/validation/verification.json `
  --source-revision <source-revision> `
  --base-revision <base-revision-or-none> `
  --expected-gate G2 `
  --expected-force-full true `
  --expected-ci-context local `
  --expected-mode risk_proportional
```

A modified worktree, mismatched revision, missing stage, or mismatched expected claim invalidates the receipt. Hosted CI is supplemental evidence and does not replace the exact local acceptance receipt.
