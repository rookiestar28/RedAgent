# Authorized Web Assessment SOP

Date: 2026-07-07
Status: Initial standard workflow

## 1. Purpose

This SOP standardizes the passive and progressive web-assessment workflow used by this repository for explicitly authorized targets.

It covers:

- engagement authorization review
- local log-console startup
- controlled execution
- log and artifact capture
- result analysis
- improvement recommendation report drafting
- closeout and validation

This SOP does not authorize testing by itself. Each target run still requires a current ROE with target allowlist, window, owner, allowed categories, rate limit, request cap, stop conditions, and evidence handling.

## 2. Roles and Responsibilities

| Role | Responsibility |
| --- | --- |
| Owner / approver | Approves target scope, time window, allowed categories, stop authority, and evidence rules. |
| Operator | Runs the automation, watches the log console, stops the run when limits or stop conditions are met. |
| Reviewer | Reviews sanitized output, separates confirmed observations from unvalidated risk hypotheses, and prepares recommendations. |
| Incident / stop authority | Can halt the run immediately. |

## 3. Preconditions

Before execution:

1. Confirm the target is owned or explicitly authorized.
2. Confirm ROE fields are complete:
   - hostnames
   - window with timezone or offset
   - allowed mode: `passive` or `progressive`
   - rate limit
   - total request cap
   - allowed methods and path discovery rules
   - forbidden actions
   - emergency stop contact method
   - evidence retention rules
3. Confirm the current time is inside the approved window.
4. Confirm WSL Kali is available when using the default wrapper.
5. Confirm the local repository has no unexpected external reference repository entries.
6. Confirm no secrets are placed in command arguments, config, logs, or reports.

## 4. Standard Automation Entry Point

Use the PowerShell wrapper from the repository root:

```powershell
& .\scripts\run_authorized_web_assessment.ps1 `
  -Mode progressive `
  -Targets @("agentique.io", "www.agentique.io") `
  -WindowStart $ApprovedWindowStart `
  -WindowEnd $ApprovedWindowEnd `
  -AuthorizationLabel "approved-engagement-id" `
  -MaxInteractions 50 `
  -MinDelaySeconds 1
```

Use PowerShell's direct call operator so target arrays remain arrays. Do not replay this workflow through a native `powershell.exe -File` command with comma-delimited targets. Use `-DisableDirectoryProbes` when the authorization excludes dictionary paths.

For dry-run validation that performs no target traffic:

```powershell
& .\scripts\run_authorized_web_assessment.ps1 `
  -Mode passive `
  -Targets @("example.test") `
  -WindowStart $ApprovedWindowStart `
  -WindowEnd $ApprovedWindowEnd `
  -AuthorizationLabel "approved-dry-run-id" `
  -DisableDirectoryProbes `
  -NoUi `
  -DryRun
```

Dry-run forces `-NoUi`, executes the runner's strict `--validate-only` config path through WSL, verifies the exact wrapper-recorded config SHA-256, and performs no localhost or target traffic.

## 5. Startup Flow

The wrapper performs these steps:

1. Resolve repository root.
2. Validate target hostnames and dictionary paths.
3. Parse and check the time window.
4. Create `.tmp/assessments/<run-id>/`.
5. Start or verify the local log console unless `-NoUi` is used.
6. Clear `.tmp/ui-terminal.log` only when UI mode is enabled.
7. Write immutable run metadata to `.tmp/assessments/<run-id>/runner.log` and mirror it to the UI log only in UI mode.
8. Write a JSON config under `.tmp/assessments/<run-id>/config.json`.
9. Reject symlink, junction, or reparse traversal for repository write paths, bind `validate_only` or `execute` intent into the hashed config, and pass the config SHA-256 to the runner for exact-byte verification.

The log console remains preview-only. It does not execute commands.

## 6. Execution Flow

The wrapper invokes the controlled runner through WSL Kali by default:

```powershell
wsl.exe -d kali-linux -- python3 scripts/authorized_web_assessment_runner.py [--validate-only] --expected-config-sha256 <sha256> <config>
```

The runner enforces:

- target allowlist
- exact CLI/config execution-intent match, rechecked before every target interaction
- time window
- request cap
- minimum delay after each target interaction
- automatic stop on the first 401/403 access denial, 429, or WAF challenge
- automatic stop on the second unexpected 5xx response
- automatic stop on a completed HTTP request over ten seconds or a network failure
- automatic in-memory stop for high-confidence private-key or credential-token shapes before evidence persistence; this is not general personal-data discovery
- `GET` and `HEAD` only for HTTP
- TLS certificate metadata only for TLS
- same-origin bounded crawl with in-memory robots `Disallow` filtering; query- or fragment-bearing discovered links are skipped rather than mutated
- limited dictionary path checks with encoded, ambiguous, and dot-segment paths rejected
- memory-only response bodies with persisted size and SHA-256, not raw content

The runner does not support:

- arbitrary shell commands
- scanner templates
- exploit payloads
- fuzzing
- brute force
- credential attacks
- authentication testing
- form submission
- parameter mutation
- DoS, load, stress, or availability testing

## 7. Result Analysis Flow

After the runner completes:

1. Review `.tmp/assessments/<run-id>/runner.log` for execution status, exit code, and total interactions.
2. Review `.tmp/assessments/<run-id>/summary.json`.
3. Review generated report under `reports/assessments/`.
4. Classify observations:
   - confirmed configuration fact
   - informational exposure
   - hardening opportunity
   - follow-up validation needed
   - out-of-scope / not tested
5. Do not claim vulnerabilities unless the approved test phase actually validated them.

## 8. Improvement Recommendation Report Flow

When recommendations are needed:

1. Use existing evidence reports and `summary.json`.
2. Create a report under `reports/`.
3. Include:
   - executive summary
   - scope and non-claims
   - prioritized recommendations
   - evidence references
   - risk rationale
   - remediation steps
   - acceptance checks
   - next approved testing phase
4. Avoid:
   - credentials
   - cookies
   - tokens
   - personal data
   - raw full bodies
   - private contact details
   - exploit payload output

## 9. Closeout Flow

After each real target run:

1. Confirm total interactions stayed below the approved cap.
2. Confirm no out-of-scope host was contacted.
3. Confirm raw artifacts remain under ignored `.tmp/`.
4. Confirm generated command logs and reports are secret-free.
5. Stage only sanitized repo artifacts.
6. Run at least:

```powershell
$env:PRE_COMMIT_HOME = Join-Path (Get-Location) '.pre-commit-cache'
.\.venv\Scripts\pre-commit.exe run --all-files --show-diff-on-failure
```

For code or script changes, run the full gate:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_full_tests_windows.ps1
```

## 10. Stop Conditions

Stop immediately if:

- stop authority requests halt
- the window expires
- interaction cap would be exceeded
- target ownership becomes unclear
- out-of-scope host would be contacted
- rate limit cannot be enforced
- unexpected sensitive data appears
- service instability, WAF blocks, or availability symptoms appear
- tool behavior deviates from this SOP or the approved ROE

## 11. Evidence Locations

| Artifact | Location | Tracking policy |
| --- | --- | --- |
| Per-run console log | `.tmp/assessments/<run-id>/runner.log` | Ignored runtime artifact |
| Optional UI mirror | `.tmp/ui-terminal.log` | Ignored mutable preview artifact |
| Raw per-run artifacts | `.tmp/assessments/<run-id>/artifacts/` | Ignored runtime artifact |
| Runner config | `.tmp/assessments/<run-id>/config.json` | Ignored runtime artifact |
| Summary JSON | `.tmp/assessments/<run-id>/summary.json` | Ignored runtime artifact unless explicitly sanitized and copied |
| Generated report | `reports/assessments/<run-id>-report.md` | Review before staging |
| Generated command log | `.local/validation/automated-runs/<run-id>-<mode>-COMMAND_LOG.md` | Review before staging |

## 12. Current Supported Modes

`passive`:

- TLS certificate metadata.
- Bounded `GET /robots.txt`, followed only by robots-allowed `HEAD /` and `HEAD /.well-known/security.txt`.

`progressive`:

- TLS certificate checks followed by robots-first HTTP discovery.
- Small metadata body retrieval for `robots.txt`, `security.txt`, sitemap, and homepage.
- Bounded same-origin crawl from the homepage after conservative in-memory robots filtering.
- Limited dictionary path existence checks.
- Non-intrusive technology fingerprinting.

Any higher-risk phase requires a separate ROE and future platform policy-gate work.
