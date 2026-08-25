# Contributing

Use the repository-local Python environment and Node.js 18 or newer. Before submitting a change, run:

```powershell
powershell -File scripts/run_full_tests_windows.ps1
```

Changes must preserve authorization, target-scope, audit, evidence-redaction, and cleanup boundaries.
Do not commit credentials, environment files, local runtime state, third-party payloads, or generated
test output. Active testing against systems you do not own or lack explicit authorization to assess
is not accepted.
