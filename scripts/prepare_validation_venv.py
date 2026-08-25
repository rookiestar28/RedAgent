#!/usr/bin/env python3
"""Create the canonical project validation venv under the authoritative lease."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.gate_lease import (  # noqa: E402
    ValidationLease,
    ValidationLeaseError,
    bind_authoritative_validation_platform,
    validated_authoritative_validation_lease_path,
)
from redagent_platform.gate_runtime import GateRuntimeError, attest_project_venv_layout  # noqa: E402


_TARGETS = {"windows": ".venv", "posix": ".venv-wsl"}
VENV_CREATION_TIMEOUT_SECONDS = 300


class VenvPreparationError(RuntimeError):
    """Raised when the one-time project venv creation cannot be completed safely."""


def _target_name(target: str) -> str:
    expected = "windows" if sys.platform == "win32" else "posix"
    if target != expected:
        raise VenvPreparationError("validation venv target does not match the active platform")
    return _TARGETS[target]


def _create_project_venv(path: Path) -> Path:
    if sys.version_info < (3, 11):
        raise VenvPreparationError("Python 3.11+ with venv support is required")
    # CRITICAL: creating a venv can invoke ensurepip; keep its full process tree
    # within the same bounded executor used by the authoritative validation gate.
    from redagent_platform.validation.stages import Stage, StageRunner

    print(
        f"[started] validation-venv-preparation (timeout {VENV_CREATION_TIMEOUT_SECONDS}s)",
        flush=True,
    )
    result = StageRunner(ROOT, inherited_environment=dict(os.environ)).run(
        Stage(
            id="validation-venv-preparation",
            argv=(sys.executable, "-I", "-m", "venv", str(path)),
            gates=("G0", "G1", "G2"),
            timeout_seconds=VENV_CREATION_TIMEOUT_SECONDS,
        )
    )
    if result.status == "timed_out":
        raise VenvPreparationError("project venv creation timed out")
    if result.status != "passed":
        raise VenvPreparationError(
            "project venv creation failed; install the Python venv support package and rerun"
        )
    return path


def prepare_project_venv(target: str) -> Path:
    """Create or attest the one platform-specific project venv while holding the writer lease."""

    name = _target_name(target)
    path = ROOT / name
    # CRITICAL: fail before binding the durable platform context when the host
    # cannot create a supported project venv.
    if not (path.exists() or path.is_symlink()) and sys.version_info < (3, 11):
        raise VenvPreparationError("Python 3.11+ with venv support is required")
    try:
        with ValidationLease(validated_authoritative_validation_lease_path(ROOT)) as lease:
            bind_authoritative_validation_platform(ROOT, lease.capability())
            if path.exists() or path.is_symlink():
                # A concurrent creator must leave a complete, attested venv; never repair or delete it.
                return attest_project_venv_layout(ROOT, name)
            _create_project_venv(path)
            return attest_project_venv_layout(ROOT, name)
    except (GateRuntimeError, ValidationLeaseError) as exc:
        raise VenvPreparationError(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Create the leased project validation virtual environment")
    parser.add_argument("--target", choices=tuple(sorted(_TARGETS)), required=True)
    args = parser.parse_args()
    try:
        prepared = prepare_project_venv(args.target)
    except VenvPreparationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"validation_venv_ready={prepared.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
