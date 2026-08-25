$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot
foreach ($PythonStartupVariable in @(
    "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONSTARTUP", "PYTHONINSPECT",
    "PYTHONWARNINGS", "PYTHONBREAKPOINT", "PYTHONPLATLIBDIR", "PYTHONCASEOK", "PYTHONEXECUTABLE",
    "PYTHONPYCACHEPREFIX"
)) {
    Remove-Item -LiteralPath "Env:$PythonStartupVariable" -ErrorAction SilentlyContinue
}
$env:PYTHONNOUSERSITE = "1"
$env:PYTHONSAFEPATH = "1"
$env:PYTHONDONTWRITEBYTECODE = "1"

function Assert-NativeSuccess([string]$Stage) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Stage failed with exit code $LASTEXITCODE"
    }
}

function Assert-SafeAncestor([string]$Target) {
    $RootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    $TargetFull = [System.IO.Path]::GetFullPath($Target)
    $RootPrefix = $RootFull + [System.IO.Path]::DirectorySeparatorChar
    if ($TargetFull -ne $RootFull -and -not $TargetFull.StartsWith($RootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "validation path escaped the repository: $TargetFull"
    }
    $Relative = if ($TargetFull -eq $RootFull) { "" } else { $TargetFull.Substring($RootPrefix.Length) }
    $Current = $RootFull
    foreach ($Part in $Relative.Split([System.IO.Path]::DirectorySeparatorChar, [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $Current = Join-Path $Current $Part
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force
            if ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "validation path ancestor must not be a reparse point: $Current"
            }
        }
    }
}

Assert-SafeAncestor (Join-Path $RepoRoot ".venv")
if (-not (Test-Path -LiteralPath ".venv")) {
    # CRITICAL: first-run creation is a mutable writer operation; the helper owns the shared lease.
    python -I scripts/prepare_validation_venv.py --target windows
    Assert-NativeSuccess "prepare leased project virtual environment"
}

$ExpectedVenv = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot ".venv"))
$VenvItem = Get-Item -LiteralPath ".venv" -Force
$ResolvedVenv = [System.IO.Path]::GetFullPath($VenvItem.FullName)
if ($ResolvedVenv -ne $ExpectedVenv -or ($VenvItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw "existing .venv must be a real directory contained in the repository"
}
$Python = Join-Path $ResolvedVenv "Scripts\python.exe"
$VenvScripts = Join-Path $ResolvedVenv "Scripts"
$VenvConfig = Join-Path $ResolvedVenv "pyvenv.cfg"
$VenvSitePackages = Join-Path $ResolvedVenv "Lib\site-packages"
Assert-SafeAncestor $VenvScripts
Assert-SafeAncestor $VenvConfig
Assert-SafeAncestor $VenvSitePackages
Assert-SafeAncestor $Python
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "existing .venv is incomplete; remove only the repo-local .venv and rerun"
}
foreach ($RequiredPath in @($VenvScripts, $VenvConfig, $VenvSitePackages, $Python)) {
    if (-not (Test-Path -LiteralPath $RequiredPath)) {
        throw "existing .venv is incomplete; missing $RequiredPath"
    }
    $RequiredItem = Get-Item -LiteralPath $RequiredPath -Force
    if ($RequiredItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "project venv contains a reparse point: $RequiredPath"
    }
}
if ((Get-Item -LiteralPath $VenvConfig -Force).Length -gt 16384) {
    throw "project venv pyvenv.cfg exceeds the bounded size"
}
$SystemSiteSettings = @(
    Get-Content -LiteralPath $VenvConfig |
        Where-Object { $_ -match '^\s*include-system-site-packages\s*=' }
)
if ($SystemSiteSettings.Count -ne 1 -or
    $SystemSiteSettings[0] -notmatch '^\s*include-system-site-packages\s*=\s*false\s*$') {
    throw "project venv must set include-system-site-packages = false exactly once"
}
& $Python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
Assert-NativeSuccess "validate project Python 3.11+"
& $Python scripts/verify_venv_boundary.py --expected $ResolvedVenv
Assert-NativeSuccess "attest project venv boundary"
& $Python -m pip --version
Assert-NativeSuccess "validate project pip"
# Explicit provisioning is intentionally separate from a selected gate: it
# creates no verification receipt and never converts G0/G1 into hidden G2 work.
if ($args.Count -eq 1 -and $args[0] -eq "--provision-dependencies") {
    & $Python scripts/run_validation_gate.py provision
    Assert-NativeSuccess "provision validation dependencies"
    Write-Host "Validation dependencies provisioned."
    return
}
# CRITICAL: keep all validation intent in the closed Python registry; adding stages
# here recreates cross-platform drift and duplicate security checks.
# Pass --legacy-full to exercise the canonical forced-G2 compatibility entrypoint.
$GateArgs = @($args)
if ($args.Count -eq 0) {
    $GateArgs = @("--force-full")
}
if ($GateArgs -contains "--legacy-full") {
    $LegacyArgs = @($GateArgs | Where-Object { $_ -ne "--legacy-full" })
    if ($LegacyArgs.Count -ne 0) {
        throw "legacy full compatibility entrypoint does not accept additional runner arguments"
    }
    & $Python scripts/run_legacy_full_gate.py
    Assert-NativeSuccess "legacy full compatibility validation gate"
    Write-Host "Full Windows legacy gate passed."
    return
}
& $Python scripts/run_validation_gate.py run @GateArgs
Assert-NativeSuccess "risk-proportional validation gate"

Write-Host "Full Windows gate passed."
