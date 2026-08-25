#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv="$repo_root/.venv-wsl"

assert_contained_real_path() {
  local target="$1"
  case "$target" in
    "$repo_root"|"$repo_root"/*) ;;
    *) echo "POSIX venv path escaped the workspace: $target" >&2; exit 1 ;;
  esac
  local relative="${target#"$repo_root"/}"
  local current="$repo_root"
  local part
  IFS='/' read -r -a parts <<< "$relative"
  for part in "${parts[@]}"; do
    current="$current/$part"
    if [[ -L "$current" ]]; then
      echo "POSIX venv startup path must not contain a symlink: $current" >&2
      exit 1
    fi
    if [[ -e "$current" ]]; then
      case "$(readlink -f -- "$current")" in
        "$repo_root"|"$repo_root"/*) ;;
        *) echo "POSIX venv startup path escaped the workspace: $current" >&2; exit 1 ;;
      esac
    fi
  done
}

assert_exact_lib64_compatibility_link() {
  local link="$venv/lib64"
  local target="$venv/lib"
  if [[ ! -L "$link" || "$(readlink -- "$link")" != "lib" ]]; then
    echo "POSIX venv lib64 compatibility link must target the sibling lib directory." >&2
    exit 1
  fi
  if [[ ! -d "$target" || -L "$target" ]]; then
    echo "POSIX venv lib64 compatibility target must be a real directory." >&2
    exit 1
  fi
  assert_contained_real_path "$target"
  if [[ "$(readlink -f -- "$link")" != "$(readlink -f -- "$target")" ]]; then
    echo "POSIX venv lib64 compatibility link escaped its exact target." >&2
    exit 1
  fi
}

assert_contained_real_path "$venv"
venv_config="$venv/pyvenv.cfg"
assert_contained_real_path "$venv_config"
if [[ ! -f "$venv_config" || -L "$venv_config" || "$(wc -c < "$venv_config")" -gt 16384 ]]; then
  echo "POSIX venv pyvenv.cfg must be a bounded real file." >&2
  exit 1
fi
system_site_count="$(grep -Eic '^[[:space:]]*include-system-site-packages[[:space:]]*=' "$venv_config" || true)"
false_site_count="$(grep -Eic '^[[:space:]]*include-system-site-packages[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$venv_config" || true)"
if [[ "$system_site_count" -ne 1 || "$false_site_count" -ne 1 ]]; then
  echo "POSIX venv must set include-system-site-packages = false exactly once." >&2
  exit 1
fi
for base in "$venv/lib" "$venv/local" "$venv/local/lib" "$venv/local/lib64"; do
  if [[ -e "$base" || -L "$base" ]]; then
    assert_contained_real_path "$base"
  fi
done
lib64_is_compatibility_link=false
if [[ -L "$venv/lib64" ]]; then
  assert_exact_lib64_compatibility_link
  lib64_is_compatibility_link=true
elif [[ -e "$venv/lib64" ]]; then
  assert_contained_real_path "$venv/lib64"
fi

# CRITICAL: Debian/Ubuntu site.py also scans dist-packages under local/lib and
# version-short paths; lib64 is valid on other CPython platforms. Validate all
# existing startup directories natively before any venv Python can process .pth.
shopt -s nullglob
startup_sites=(
  "$venv"/lib/python*/site-packages
  "$venv"/lib/python*/dist-packages
  "$venv"/local/lib/python*/site-packages
  "$venv"/local/lib/python*/dist-packages
  "$venv"/local/lib64/python*/site-packages
  "$venv"/local/lib64/python*/dist-packages
)
if [[ "$lib64_is_compatibility_link" == false ]]; then
  startup_sites+=(
    "$venv"/lib64/python*/site-packages
    "$venv"/lib64/python*/dist-packages
  )
fi
shopt -u nullglob
for versionless in \
  "$venv/lib/site-packages" "$venv/lib/dist-packages"; do
  if [[ -e "$versionless" || -L "$versionless" ]]; then
    startup_sites+=("$versionless")
  fi
done
if [[ "$lib64_is_compatibility_link" == false ]]; then
  for versionless in "$venv/lib64/site-packages" "$venv/lib64/dist-packages"; do
    if [[ -e "$versionless" || -L "$versionless" ]]; then
      startup_sites+=("$versionless")
    fi
  done
fi

if [[ "${#startup_sites[@]}" -eq 0 ]]; then
  echo "POSIX venv has no bounded site-packages or dist-packages directory." >&2
  exit 1
fi
for site_dir in "${startup_sites[@]}"; do
  if [[ ! -d "$site_dir" || -L "$site_dir" ]]; then
    echo "POSIX venv startup directory is not a real directory: $site_dir" >&2
    exit 1
  fi
  assert_contained_real_path "$site_dir"
done
if [[ "$lib64_is_compatibility_link" == true ]]; then
  # CRITICAL: revalidate the one allowed link immediately before venv execution.
  assert_exact_lib64_compatibility_link
fi

echo "posix_venv_layout_ok=true"
