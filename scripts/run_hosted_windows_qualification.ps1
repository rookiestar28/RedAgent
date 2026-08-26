$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

function Assert-NativeSuccess([string]$Stage) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Stage failed with exit code $LASTEXITCODE"
    }
}

# This lane is intentionally Windows-specific qualification. It cannot emit or
# substitute for the repository's authoritative full-gate receipt.
powershell -File scripts/run_full_tests_windows.ps1 --provision-dependencies
Assert-NativeSuccess "provision project-local validation dependencies"

$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "project-local validation interpreter is unavailable"
}

$Tests = @(
    "tests/unit/test_hosted_validation_portability.py",
    "tests/unit/test_compat_098_openbao_topology.py",
    "tests/unit/test_compat_099_opa_conformance.py",
    "tests/unit/test_compat_118_validation_bootstrap.py",
    "tests/unit/test_compat_118_validation_workflow.py",
    "tests/unit/test_local_stack.py"
)
& $Python -m pytest -q -ra -p no:cacheprovider @Tests
Assert-NativeSuccess "run hosted Windows portability regressions"

& $Python scripts/validate_public_release.py
Assert-NativeSuccess "validate public release trace boundary"
& $Python scripts/validate_public_release.py --check-commit-message
Assert-NativeSuccess "validate public commit-message trace boundary"

git diff --check
Assert-NativeSuccess "validate diff whitespace"
$Status = @(git status --porcelain=v1 --untracked-files=normal)
Assert-NativeSuccess "read final worktree state"
if ($Status.Count -ne 0) {
    throw "hosted Windows qualification modified the worktree"
}

Write-Host "hosted_windows_qualification=true"
