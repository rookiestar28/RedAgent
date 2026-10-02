# Contributing

Use the repository-local Python environment and Node.js 20.9+ on 20.x, 22.x, or 24+. Before submitting a change, run:

```powershell
powershell -File scripts/run_full_tests_windows.ps1
```

Changes must preserve authorization, target-scope, audit, evidence-redaction, and cleanup boundaries.
Do not commit credentials, environment files, local runtime state, third-party payloads, or generated
test output. Active testing against systems you do not own or lack explicit authorization to assess
is not accepted.
