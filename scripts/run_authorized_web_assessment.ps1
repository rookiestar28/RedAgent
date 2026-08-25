param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("passive", "progressive")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string[]]$Targets,

    [Parameter(Mandatory = $true)]
    [string]$WindowStart,

    [Parameter(Mandatory = $true)]
    [string]$WindowEnd,

    [Parameter(Mandatory = $true)]
    [string]$AuthorizationLabel,

    [int]$MaxInteractions = 50,
    [int]$MinDelaySeconds = 1,
    [string]$WslDistribution = "kali-linux",
    [switch]$NoUi,
    [switch]$DryRun,
    [switch]$DisableDirectoryProbes,
    [string[]]$DirectoryDictionary = @(
        "/admin",
        "/login",
        "/signin",
        "/dashboard",
        "/api",
        "/docs",
        "/blog",
        "/pricing",
        "/contact",
        "/about"
    )
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($DryRun) {
    # IMPORTANT: dry-run is a strict local/WSL config check and must not start or contact the UI service.
    $NoUi = $true
}

$RepoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

function ConvertTo-WslPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full -notmatch "^([A-Za-z]):\\(.*)$") {
        throw "Cannot convert non-drive path to WSL path: $full"
    }
    $drive = $Matches[1].ToLowerInvariant()
    $tail = $Matches[2].Replace("\", "/")
    return "/mnt/$drive/$tail"
}

function Assert-RepoContainedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $repo = [System.IO.Path]::GetFullPath([string]$RepoRoot).TrimEnd("\")
    $repoItem = Get-Item -LiteralPath $repo -Force
    if (($repoItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "repository root is a reparse point"
    }
    $full = [System.IO.Path]::GetFullPath($Value)
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    if (-not $full.Equals($repo, $comparison) -and
        -not $full.StartsWith($repo + "\", $comparison)) {
        throw "$Label is outside the repository"
    }
    $relative = $full.Substring($repo.Length).TrimStart("\")
    $current = $repo
    foreach ($component in @($relative.Split("\", [System.StringSplitOptions]::RemoveEmptyEntries))) {
        $current = Join-Path $current $component
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label traverses a reparse point"
            }
        }
    }
    return $full
}

function Assert-Hostname {
    param([Parameter(Mandatory = $true)][string]$Value)
    $candidate = $Value.Trim().ToLowerInvariant()
    if ($candidate -notmatch "^[a-z0-9.-]{1,253}$" -or
        $candidate.StartsWith(".") -or
        $candidate.EndsWith(".") -or
        $candidate.Contains("..")) {
        throw "Invalid target hostname: $Value"
    }
    return $candidate
}

function ConvertFrom-ExplicitOffsetTimestamp {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Value -notmatch "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$") {
        throw "WindowStart and WindowEnd must be ISO-8601 values with explicit offsets"
    }
    $parsed = [System.DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::RoundtripKind
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    if (-not [System.DateTimeOffset]::TryParse($Value, $culture, $styles, [ref]$parsed)) {
        throw "$Label is not a valid ISO-8601 timestamp"
    }
    return $parsed
}

function Assert-DictionaryPath {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch "^/[A-Za-z0-9._~/-]{1,80}$" -or
        $Value.Contains("//") -or
        $Value.Contains("/../") -or
        $Value.EndsWith("/..")) {
        throw "Invalid dictionary path: $Value"
    }
    foreach ($segment in $Value.Split("/")) {
        if ($segment -eq "." -or $segment -eq "..") {
            throw "Dictionary path cannot contain dot segments: $Value"
        }
    }
    return $Value
}

function Test-LogConsole {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:4173/api/logs/status" -TimeoutSec 2 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Start-LogConsole {
    if (Test-LogConsole) {
        return "already-running"
    }
    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $npm) {
        $npm = Get-Command npm -ErrorAction Stop
    }
    Start-Process -FilePath $npm.Source -ArgumentList @("run", "dev") -WorkingDirectory $RepoRoot -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-LogConsole) {
            return "started"
        }
    }
    throw "Log console did not become ready on http://127.0.0.1:4173"
}

if ($MaxInteractions -lt 1 -or $MaxInteractions -gt 500) {
    throw "MaxInteractions must be between 1 and 500"
}
if ($MinDelaySeconds -lt 1 -or $MinDelaySeconds -gt 60) {
    throw "MinDelaySeconds must be between 1 and 60"
}
if ($DirectoryDictionary.Count -gt 20) {
    throw "DirectoryDictionary cannot exceed 20 entries"
}
if ($AuthorizationLabel -notmatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$") {
    throw "authorization_label must use the approved identifier grammar"
}
if ($WslDistribution -notmatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$") {
    throw "WslDistribution must use the approved identifier grammar"
}
if ($Targets.Count -lt 1 -or $Targets.Count -gt 10) {
    throw "Targets must contain between 1 and 10 unique hostnames"
}

$NormalizedTargets = @($Targets | ForEach-Object { Assert-Hostname $_ } | Sort-Object -Unique)
if ($NormalizedTargets.Count -ne $Targets.Count) {
    throw "Targets must contain between 1 and 10 unique hostnames"
}
if ($DisableDirectoryProbes) {
    $ValidatedDictionary = @()
} else {
    $ValidatedDictionary = @($DirectoryDictionary | ForEach-Object { Assert-DictionaryPath $_ })
}

$Start = ConvertFrom-ExplicitOffsetTimestamp -Value $WindowStart -Label "WindowStart"
$End = ConvertFrom-ExplicitOffsetTimestamp -Value $WindowEnd -Label "WindowEnd"
if ($End -le $Start) {
    throw "WindowEnd must be later than WindowStart"
}
$Now = [System.DateTimeOffset]::Now
if ($Now -lt $Start -or $Now -gt $End) {
    throw "Current time $($Now.ToString("o")) is outside approved window $($Start.ToString("o")) - $($End.ToString("o"))"
}
$WslCandidates = @(Get-Command wsl.exe -CommandType Application -ErrorAction Stop)
$SystemWslPath = [System.IO.Path]::GetFullPath((Join-Path $env:SystemRoot "System32\wsl.exe"))
$WslCommand = @($WslCandidates | Where-Object {
    [System.IO.Path]::GetFullPath($_.Path).Equals(
        $SystemWslPath,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}) | Select-Object -First 1
if ($null -eq $WslCommand) {
    throw "trusted System32 wsl.exe was not found"
}

$RunId = (Get-Date -Format "yyyyMMdd-HHmmssfff") + "-$Mode-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
$RunRoot = Join-Path $RepoRoot ".tmp\assessments\$RunId"
$ArtifactRoot = Join-Path $RunRoot "artifacts"
$ReportRoot = Join-Path $RepoRoot "reports\assessments"
$AutomatedLogRoot = Join-Path $RepoRoot ".local\validation\automated-runs"
$UiLogPath = Join-Path $RepoRoot ".tmp\ui-terminal.log"
$RunLogPath = Join-Path $RunRoot "runner.log"

$RunRoot = Assert-RepoContainedPath -Value $RunRoot -Label "RunRoot"
$ArtifactRoot = Assert-RepoContainedPath -Value $ArtifactRoot -Label "ArtifactRoot"
$ReportRoot = Assert-RepoContainedPath -Value $ReportRoot -Label "ReportRoot"
$AutomatedLogRoot = Assert-RepoContainedPath -Value $AutomatedLogRoot -Label "AutomatedLogRoot"
$UiLogPath = Assert-RepoContainedPath -Value $UiLogPath -Label "UiLogPath"
$RunLogPath = Assert-RepoContainedPath -Value $RunLogPath -Label "RunLogPath"

New-Item -ItemType Directory -Force -Path $ReportRoot, $AutomatedLogRoot | Out-Null
New-Item -ItemType Directory -Path $RunRoot | Out-Null
New-Item -ItemType Directory -Path $ArtifactRoot | Out-Null
$RunRoot = Assert-RepoContainedPath -Value $RunRoot -Label "RunRoot"
$ArtifactRoot = Assert-RepoContainedPath -Value $ArtifactRoot -Label "ArtifactRoot"
$ReportRoot = Assert-RepoContainedPath -Value $ReportRoot -Label "ReportRoot"
$AutomatedLogRoot = Assert-RepoContainedPath -Value $AutomatedLogRoot -Label "AutomatedLogRoot"

$UiState = "disabled"
if (-not $NoUi) {
    $UiState = Start-LogConsole
    Invoke-WebRequest -UseBasicParsing -Method POST -Uri "http://127.0.0.1:4173/api/logs/clear" -TimeoutSec 5 | Out-Null
}

$ReportPath = Join-Path $ReportRoot "$RunId-report.md"
$SummaryPath = Join-Path $RunRoot "summary.json"
$ConfigPath = Join-Path $RunRoot "config.json"
$CommandLogPath = Join-Path $AutomatedLogRoot "$RunId-COMMAND_LOG.md"
$ReportPath = Assert-RepoContainedPath -Value $ReportPath -Label "ReportPath"
$SummaryPath = Assert-RepoContainedPath -Value $SummaryPath -Label "SummaryPath"
$ConfigPath = Assert-RepoContainedPath -Value $ConfigPath -Label "ConfigPath"
$CommandLogPath = Assert-RepoContainedPath -Value $CommandLogPath -Label "CommandLogPath"
$ExecutionIntent = if ($DryRun) { "validate_only" } else { "execute" }

$Config = [ordered]@{
    run_id = $RunId
    mode = $Mode
    execution_intent = $ExecutionIntent
    targets = $NormalizedTargets
    window_start = $Start.ToString("o")
    window_end = $End.ToString("o")
    authorization_label = $AuthorizationLabel
    max_interactions = $MaxInteractions
    min_delay_seconds = $MinDelaySeconds
    directory_dictionary = $ValidatedDictionary
    output_dir = ConvertTo-WslPath $RunRoot
    report_path = ConvertTo-WslPath $ReportPath
    summary_path = ConvertTo-WslPath $SummaryPath
    user_agent = "RedAgentAuthorizedAutomation/0.1"
}

$Config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
$ConfigSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ConfigPath).Hash.ToLowerInvariant()

$prefix = @(
    "=== Authorized web assessment automation ===",
    "run_id: $RunId",
    "mode: $Mode",
    "execution_intent: $ExecutionIntent",
    "targets: $($NormalizedTargets -join ', ')",
    "window: $($Start.ToString("o")) - $($End.ToString("o"))",
    "limits: max $MaxInteractions interactions; min delay ${MinDelaySeconds}s; concurrency 1",
    "automatic stops: first 401/403/429/WAF; second 5xx; completed HTTP over 10s",
    "config_sha256: $ConfigSha256",
    "directory probes disabled: $DisableDirectoryProbes",
    "directory probe count: $($ValidatedDictionary.Count)",
    "ui: $UiState",
    "dry_run: $DryRun",
    ""
) -join [Environment]::NewLine
Set-Content -LiteralPath $RunLogPath -Value $prefix -Encoding UTF8
if (-not $NoUi) {
    Set-Content -LiteralPath $UiLogPath -Value $prefix -Encoding UTF8
}

$StartedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
$ExitCode = $null
$RunnerWsl = ConvertTo-WslPath (Join-Path $RepoRoot "scripts\authorized_web_assessment_runner.py")
$ConfigWsl = ConvertTo-WslPath $ConfigPath
$RunnerArguments = @($RunnerWsl)
if ($DryRun) {
    $RunnerArguments += "--validate-only"
}
$RunnerArguments += @("--expected-config-sha256", $ConfigSha256, $ConfigWsl)

$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
# IMPORTANT: a script-local LASTEXITCODE shadows the native process value in Windows PowerShell 5.1.
$global:LASTEXITCODE = $null
$script:ConfigVerified = $false
try {
    # IMPORTANT: Windows PowerShell surfaces native WSL stderr as ErrorRecord objects;
    # the native exit code remains the authoritative success/failure boundary.
    & $WslCommand.Source -d $WslDistribution -- python3 @RunnerArguments 2>&1 |
        ForEach-Object {
            $line = if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $_.Exception.Message
            } else {
                [string]$_
            }
            if ($line -eq "CONFIG SHA256 VERIFIED: $ConfigSha256" -or
                $line -eq "config_sha256: $ConfigSha256") {
                $script:ConfigVerified = $true
            }
            Add-Content -LiteralPath $RunLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
            if (-not $NoUi) {
                Add-Content -LiteralPath $UiLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
            }
            Write-Host $line
        }
    if ($null -eq $global:LASTEXITCODE -or $global:LASTEXITCODE -isnot [int]) {
        throw "native runner invocation did not provide a valid exit code"
    }
    $ExitCode = [int]$global:LASTEXITCODE
} catch {
    $ExitCode = 1
    $line = "NATIVE INVOCATION FAILURE: runner did not complete with a valid exit code"
    Add-Content -LiteralPath $RunLogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not $NoUi) {
        Add-Content -LiteralPath $UiLogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    Write-Host $line
} finally {
    $ErrorActionPreference = $PreviousErrorActionPreference
}
$ConfigVerified = [bool]$script:ConfigVerified
if ($ExitCode -eq 0 -and -not $ConfigVerified) {
    $ExitCode = 1
    $line = "CONFIG VERIFICATION FAILURE: runner did not confirm the expected digest"
    Add-Content -LiteralPath $RunLogPath -Value $line -Encoding UTF8
    if (-not $NoUi) {
        Add-Content -LiteralPath $UiLogPath -Value $line -Encoding UTF8
    }
    Write-Host $line
}

$EndedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
$suffix = @("", "exit code: $ExitCode", "end: $EndedAt")
Add-Content -LiteralPath $RunLogPath -Value $suffix -Encoding UTF8
if (-not $NoUi) {
    Add-Content -LiteralPath $UiLogPath -Value $suffix -Encoding UTF8
}

$ReplayTargets = ($NormalizedTargets | ForEach-Object { '"' + $_ + '"' }) -join ", "
if ($DisableDirectoryProbes) {
    $DirectoryArgument = " -DisableDirectoryProbes"
} else {
    $ReplayDictionary = ($ValidatedDictionary | ForEach-Object { '"' + $_ + '"' }) -join ", "
    $DirectoryArgument = " -DirectoryDictionary @($ReplayDictionary)"
}
$NoUiArgument = if ($NoUi) { " -NoUi" } else { "" }
$DryRunArgument = if ($DryRun) { " -DryRun" } else { "" }
$ConfigVerificationStatement = if ($ConfigVerified) {
    "- Runner output confirmed the exact wrapper-recorded config SHA-256."
} else {
    "- Config verification was not confirmed; this run is failed and inadmissible."
}

$commandLog = @"
# Automated Authorized Assessment Command Log

Run ID: $RunId
Mode: $Mode
Started: $StartedAt
Ended: $EndedAt
Targets: $($NormalizedTargets -join ', ')
Window: $($Start.ToString("o")) - $($End.ToString("o"))
Authorization label: $AuthorizationLabel
Max interactions: $MaxInteractions
Minimum delay seconds: $MinDelaySeconds
Directory probes disabled: $DisableDirectoryProbes
Directory probe count: $($ValidatedDictionary.Count)
WSL distribution: $WslDistribution
UI state: $UiState
Dry run: $DryRun
Execution intent: $ExecutionIntent
Exit code: $ExitCode
Config SHA-256: $ConfigSha256
Config verification observed: $ConfigVerified

## Command

~~~powershell
& .\scripts\run_authorized_web_assessment.ps1 -Mode $Mode -Targets @($ReplayTargets) -WindowStart "$($Start.ToString("o"))" -WindowEnd "$($End.ToString("o"))" -AuthorizationLabel "$AuthorizationLabel" -MaxInteractions $MaxInteractions -MinDelaySeconds $MinDelaySeconds -WslDistribution "$WslDistribution"$DirectoryArgument$NoUiArgument$DryRunArgument
~~~

## Artifacts

- Run log: .tmp/assessments/$RunId/runner.log
- Run root: .tmp/assessments/$RunId
- Config: .tmp/assessments/$RunId/config.json
- Summary (actual run only): .tmp/assessments/$RunId/summary.json
- Generated report (actual run only): reports/assessments/$RunId-report.md

## Safety Statement

- Target hostnames were validated before execution.
- The time window was checked before execution.
- The wrapper is configured to require the strict runner config loader for dry-run and actual-run paths.
$ConfigVerificationStatement
- Automatic ROE stops cover first 401/403/429/WAF, second unexpected 5xx, network failure, and completed HTTP over ten seconds.
- Progressive discovery retains robots restrictions only in memory and skips disallowed discretionary paths.
- The runner exposes no arbitrary command, scanner, exploit, payload, fuzzing, brute-force, authentication, or form-submission path.
- Raw artifacts are written under ignored .tmp/.
- Review generated reports before staging.
"@
Set-Content -LiteralPath $CommandLogPath -Value $commandLog -Encoding UTF8

if ($ExitCode -ne 0) {
    throw "Assessment runner exited with code $ExitCode. See $RunLogPath and $CommandLogPath."
}

Write-Host "Authorized assessment automation completed."
Write-Host "Run ID: $RunId"
Write-Host "Run log: $RunLogPath"
Write-Host "Command log: $CommandLogPath"
if (-not $DryRun) {
    Write-Host "Report: $ReportPath"
}
