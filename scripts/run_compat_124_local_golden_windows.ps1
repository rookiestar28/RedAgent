[CmdletBinding()]
param(
    [switch]$AllowDirtyDiagnostic
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $workspace

$python = Join-Path $workspace ".venv\Scripts\python.exe"
$databaseSecret = Join-Path $workspace ".local\redagent\runtime\database-url"
$receiptDirectory = Join-Path $workspace ".tmp\r124-golden"
$receiptPath = Join-Path $receiptDirectory "verification.json"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "r124_project_venv_required"
}
if (-not (Test-Path -LiteralPath $databaseSecret -PathType Leaf)) {
    throw "r124_database_url_file_required"
}
$nodeVersion = (& node -v).Trim()
if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^v(?<major>\d+)\.') {
    throw "r124_node_version_unavailable"
}
if ([int]$Matches.major -lt 18) {
    throw "r124_node_18_or_newer_required"
}

$referenceRoot = Join-Path $workspace "reference"
if (Test-Path -LiteralPath $referenceRoot) {
    $referenceChildren = @(Get-ChildItem -Force -LiteralPath $referenceRoot)
    if ($referenceChildren.Count -ne 1 -or $referenceChildren[0].Name -ne "docs" -or -not $referenceChildren[0].PSIsContainer) {
        throw "r124_external_reference_execution_boundary_invalid"
    }
}

$status = @(& git status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) {
    throw "r124_git_status_unavailable"
}
$acceptanceEligible = $status.Count -eq 0
if (-not $acceptanceEligible -and -not $AllowDirtyDiagnostic) {
    throw "r124_exact_candidate_must_be_clean"
}

$sourceRevision = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceRevision -notmatch '^[0-9a-f]{40}$') {
    throw "r124_source_revision_invalid"
}

$env:REDAGENT_DATABASE_URL_FILE = $databaseSecret
$env:REDAGENT_R123_LIVE_QUALIFICATION = "owned-loopback-v2"

$results = [System.Collections.Generic.List[object]]::new()

function Invoke-R124GoldenStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    $started = Get-Date
    & $Action
    $exitCode = $LASTEXITCODE
    $completed = Get-Date
    $results.Add([ordered]@{
        name = $Name
        exit_code = $exitCode
        duration_seconds = [math]::Round(($completed - $started).TotalSeconds, 3)
    })
    if ($exitCode -ne 0) {
        throw "r124_golden_step_failed:$Name"
    }
}

try {
    Invoke-R124GoldenStep "public_boundary_inventory" {
        & $python scripts/validate_public_release.py
    }
    Invoke-R124GoldenStep "r124_postgres_core" {
        & $python -m pytest tests/integration/test_compat_124_campaign_core.py -q
    }
    Invoke-R124GoldenStep "canonical_evidence_finding_retest" {
        & $python -m pytest tests/integration/test_compat_123_campaign_repository.py -q
    }
    Invoke-R124GoldenStep "temporal_api_worker_boundary" {
        & $python -m pytest tests/integration/test_compat_096_temporal_runtime.py `
            -k "test_real_temporal_encrypted_history_worker_restart_update_signal_and_replay or test_real_api_job_and_campaign_lifecycle_uses_temporal_and_postgres" -q
    }
    Invoke-R124GoldenStep "r123_temporal_campaign_boundary" {
        & $python -m pytest tests/integration/test_compat_123_temporal_workflow.py -q
    }
    Invoke-R124GoldenStep "real_owned_loopback_adapters" {
        & $python -m pytest tests/integration/test_compat_123_live_qualification.py -q
    }
    Invoke-R124GoldenStep "r124_browser_golden" {
        & npx playwright test tests/e2e/compat_124-campaign-core.spec.js --reporter=line
    }
}
finally {
    New-Item -ItemType Directory -Force -Path $receiptDirectory | Out-Null
    $passed = $results.Count -eq 7 -and @($results | Where-Object { $_.exit_code -ne 0 }).Count -eq 0
    $receipt = [ordered]@{
        schema = "redagent.r124-local-golden/v1"
        source_revision = $sourceRevision
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        environment = [ordered]@{
            platform = "windows"
            python = (& $python --version 2>&1).ToString().Trim()
            node = $nodeVersion
        }
        safety = [ordered]@{
            target_scope = "repository-owned-loopback-only"
            external_reference_executed = $false
            public_or_third_party_target_contacted = $false
            secret_values_recorded = $false
        }
        clean_candidate = $acceptanceEligible
        acceptance_eligible = $acceptanceEligible -and $passed
        results = $results
        passed = $passed
    }
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
}

Write-Output "r124_local_golden=passed"
Write-Output "receipt=$receiptPath"
