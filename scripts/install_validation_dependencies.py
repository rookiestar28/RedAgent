#!/usr/bin/env python3
"""Install the locked validation dependencies with bounded subprocess execution."""

from __future__ import annotations

import inspect
import math
import os
from pathlib import Path
import sys
import time
from typing import Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.gate_lease import (
    ValidationLeaseError,
    require_authoritative_validation_lease,
)

DEFAULT_TIMEOUT_SECONDS = 900
LOCKED_REQUIREMENTS = (
    ROOT / "requirements-runtime.lock",
    ROOT / "requirements-dev.lock",
)
_LOCK_FILENAMES = tuple(path.name for path in LOCKED_REQUIREMENTS)
# Existing focused tests and downstream wrappers may provide a historical
# two-argument runner.  New runners can additionally accept the absolute
# deadline as either a keyword or a third positional argument.
BootstrapCommandRunner = Callable[..., str]


class DependencyInstallError(RuntimeError):
    """Raised when the bounded validation bootstrap cannot complete."""


def _validated_timeout(timeout_seconds: int) -> int:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise DependencyInstallError("dependency installation timeout must be a positive integer")
    return timeout_seconds


def _validated_deadline(deadline_monotonic: float | None) -> float | None:
    if deadline_monotonic is None:
        return None
    if (
        isinstance(deadline_monotonic, bool)
        or not isinstance(deadline_monotonic, (int, float))
        or not math.isfinite(float(deadline_monotonic))
    ):
        raise DependencyInstallError("dependency installation deadline must be a finite monotonic timestamp")
    return float(deadline_monotonic)


def _validated_requirements(requirements: Sequence[Path], root: Path) -> tuple[Path, ...]:
    paths = tuple(Path(path).absolute() for path in requirements)
    expected = tuple((root / name).absolute() for name in _LOCK_FILENAMES)
    if paths != expected:
        raise DependencyInstallError("dependency bootstrap requires the exact reviewed lock set")
    if any(not path.is_file() for path in paths):
        raise DependencyInstallError("locked requirements file is unavailable")
    return paths


def _run_with_stage_runner(
    command: tuple[str, ...],
    timeout_seconds: int,
    deadline_monotonic: float | None = None,
) -> str:
    """Run one bootstrap command with the validation runner's tree containment."""

    # IMPORTANT: import the mutable current runner only for the current-gate
    # default. Compatibility aliases use this same canonical contained executor.
    from redagent_platform.validation.stages import (
        PIP_BOOTSTRAP_FIXED_ENVIRONMENT,
        Stage,
        StageRunner,
    )

    runner = StageRunner(
        ROOT,
        inherited_environment=dict(os.environ),
        fixed_environment=PIP_BOOTSTRAP_FIXED_ENVIRONMENT,
    )
    stage = Stage(
        id="validation-dependency-bootstrap",
        argv=command,
        # Bootstrap is a full-gate prerequisite.  G0/G1 must fail fast on
        # an unprepared venv instead of spending their feedback budget here.
        gates=("G2",),
        timeout_seconds=timeout_seconds,
    )
    if deadline_monotonic is None:
        result = runner.run(stage)
    else:
        result = runner.run(stage, deadline_monotonic=deadline_monotonic)
    return result.status


def _runner_accepts_keyword_deadline(
    command_runner: BootstrapCommandRunner,
    command: tuple[str, ...],
    timeout_seconds: int,
    deadline_monotonic: float,
) -> bool:
    """Check compatibility without executing a custom runner twice."""

    try:
        inspect.signature(command_runner).bind(
            command,
            timeout_seconds,
            deadline_monotonic=deadline_monotonic,
        )
    except (TypeError, ValueError):
        return False
    return True


def _runner_accepts_positional_deadline(
    command_runner: BootstrapCommandRunner,
    command: tuple[str, ...],
    timeout_seconds: int,
    deadline_monotonic: float,
) -> bool:
    try:
        inspect.signature(command_runner).bind(command, timeout_seconds, deadline_monotonic)
    except (TypeError, ValueError):
        return False
    return True


def _run(
    command: tuple[str, ...],
    timeout_seconds: int,
    command_runner: BootstrapCommandRunner,
    *,
    deadline_monotonic: float | None = None,
) -> None:
    if deadline_monotonic is not None and _runner_accepts_keyword_deadline(
        command_runner,
        command,
        timeout_seconds,
        deadline_monotonic,
    ):
        status = command_runner(
            command,
            timeout_seconds,
            deadline_monotonic=deadline_monotonic,
        )
    elif deadline_monotonic is not None and _runner_accepts_positional_deadline(
        command_runner,
        command,
        timeout_seconds,
        deadline_monotonic,
    ):
        status = command_runner(command, timeout_seconds, deadline_monotonic)
    else:
        status = command_runner(command, timeout_seconds)
    if status == "timed_out":
        raise DependencyInstallError("locked dependency installation timed out")
    if status != "passed":
        raise DependencyInstallError("locked dependency installation failed")


def install_locked_dependencies(
    requirements: Sequence[Path],
    *,
    lease_capability: object,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    command_runner: BootstrapCommandRunner | None = None,
    root: Path = ROOT,
    deadline_monotonic: float | None = None,
) -> None:
    """Install reviewed locks within one bounded total budget held by the writer lease."""

    try:
        root = Path(root).absolute()
        require_authoritative_validation_lease(lease_capability, root)
    except ValidationLeaseError as exc:
        raise DependencyInstallError(str(exc)) from exc
    timeout = _validated_timeout(timeout_seconds)
    caller_deadline = _validated_deadline(deadline_monotonic)
    locks = _validated_requirements(requirements, root)
    runner = command_runner or _run_with_stage_runner
    deadline = time.monotonic() + timeout
    if caller_deadline is not None:
        deadline = min(deadline, caller_deadline)
    commands = tuple(
        (
            "python",
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--require-virtualenv",
            "--no-cache-dir",
            "-r",
            str(requirement),
        )
        for requirement in locks
    )
    for command in commands:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DependencyInstallError("locked dependency installation timed out")
        # Do not round a compatibility runner's integer timeout up past the
        # caller's absolute deadline.  The built-in runners also receive the
        # exact deadline below, but older two-argument test runners cannot.
        bounded_remaining = int(remaining)
        if bounded_remaining <= 0:
            raise DependencyInstallError("locked dependency installation timed out")
        print(
            f"[started] validation-dependency-bootstrap (remaining {bounded_remaining}s)",
            flush=True,
        )
        _run(
            command,
            bounded_remaining,
            runner,
            deadline_monotonic=deadline,
        )


def main() -> int:
    # CRITICAL: a standalone bootstrap would race the authoritative writer's venv.
    print(
        "validation dependency bootstrap must be invoked by an authoritative gate holding its lease",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
