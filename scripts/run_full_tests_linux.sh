#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
unset PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT PYTHONWARNINGS \
  PYTHONBREAKPOINT PYTHONPLATLIBDIR PYTHONCASEOK PYTHONEXECUTABLE PYTHONPYCACHEPREFIX
export PYTHONNOUSERSITE=1
export PYTHONSAFEPATH=1
export PYTHONDONTWRITEBYTECODE=1

assert_safe_ancestor() {
  local target="$1"
  case "$target" in
    "$repo_root"|"$repo_root"/*) ;;
    *) echo "validation path escaped the workspace: $target" >&2; exit 1 ;;
  esac
  local relative="${target#"$repo_root"/}"
  local current="$repo_root"
  local part
  IFS='/' read -r -a parts <<< "$relative"
  for part in "${parts[@]}"; do
    current="$current/$part"
    if [[ -e "$current" || -L "$current" ]]; then
      if [[ -L "$current" ]]; then
        echo "validation path ancestor must not be a symlink: $current" >&2
        exit 1
      fi
      case "$(readlink -f -- "$current")" in
        "$repo_root"|"$repo_root"/*) ;;
        *) echo "validation path ancestor escaped the workspace: $current" >&2; exit 1 ;;
      esac
    fi
  done
}

assert_safe_ancestor "$repo_root/.venv-wsl"
python_cmd=""
if [[ -e .venv-wsl || -L .venv-wsl ]]; then
  if [[ ! -d .venv-wsl || -L .venv-wsl || "$(readlink -f .venv-wsl)" != "$repo_root/.venv-wsl" ]]; then
    echo "existing .venv-wsl must be a real directory contained in the repository." >&2
    exit 1
  fi
  assert_safe_ancestor "$repo_root/.venv-wsl/bin"
  assert_safe_ancestor "$repo_root/.venv-wsl/pyvenv.cfg"
  if [[ ! -x .venv-wsl/bin/python ]]; then
    echo "existing .venv-wsl is incomplete; remove only the repo-local .venv-wsl and rerun." >&2
    exit 1
  fi
else
  for candidate in python3.14 python3.13 python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1; then
      python_cmd="$candidate"
      break
    fi
  done
  if [[ -z "$python_cmd" ]]; then
    echo "Python 3.11+ is required; install a supported interpreter and its venv module." >&2
    exit 1
  fi
  # CRITICAL: first-run creation is a mutable writer operation; the helper owns the shared lease.
  "$python_cmd" -I scripts/prepare_validation_venv.py --target posix
fi
venv_python="$repo_root/.venv-wsl/bin/python"
assert_safe_ancestor "$repo_root/.venv-wsl/bin"
assert_safe_ancestor "$repo_root/.venv-wsl/pyvenv.cfg"
bash scripts/verify_posix_venv_layout.sh
"$venv_python" scripts/verify_venv_boundary.py --expected "$repo_root/.venv-wsl"
if ! .venv-wsl/bin/python -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "existing .venv-wsl uses incompatible Python; remove only the repo-local .venv-wsl and rerun." >&2
  exit 1
fi
if ! .venv-wsl/bin/python -m pip --version >/dev/null 2>&1; then
  echo "existing .venv-wsl is incomplete; remove only the repo-local .venv-wsl and rerun." >&2
  exit 1
fi

# Explicit provisioning is intentionally separate from a selected gate: it
# creates no verification receipt and never converts G0/G1 into hidden G2 work.
if [[ "$#" -eq 1 && "$1" == "--provision-dependencies" ]]; then
  "$venv_python" scripts/run_validation_gate.py provision
  echo "Validation dependencies provisioned."
  exit 0
fi

# CRITICAL: keep all validation intent in the closed Python registry; adding stages
# here recreates cross-platform drift and duplicate security checks.
# Pass --legacy-full to exercise the canonical forced-G2 compatibility entrypoint.
if [[ "$#" -eq 0 ]]; then
  set -- --force-full
fi
if [[ "$#" -eq 1 && "$1" == "--legacy-full" ]]; then
  "$venv_python" scripts/run_legacy_full_gate.py
  echo "Full Linux/WSL legacy gate passed."
  exit 0
fi
"$venv_python" scripts/run_validation_gate.py run "$@"

echo "Full Linux/WSL gate passed."
