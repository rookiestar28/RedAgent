"""Hard, code-owned wall-clock budgets for authoritative validation gates."""

from __future__ import annotations

import time


# These budgets include mutable runtime preparation, dependency bootstrap, and
# all selected stages.  They deliberately fit the reusable CI job's 60-minute
# outer timeout, while G0/G1 align with the compat_118 feedback acceptance limits.
GATE_EXECUTION_BUDGET_SECONDS = {
    "G0": 600,
    "G1": 1_500,
    "G2": 2_700,
}


class GateDeadlineError(RuntimeError):
    """Raised when a caller supplies an unknown authoritative gate."""


def budget_seconds(gate: str) -> int:
    """Return the closed, positive wall-clock budget for a selected gate."""

    try:
        return GATE_EXECUTION_BUDGET_SECONDS[gate]
    except (KeyError, TypeError) as exc:
        raise GateDeadlineError("authoritative validation gate is unknown") from exc


def start_deadline(gate: str) -> float:
    """Start a monotonic deadline immediately after a writer owns its lease."""

    return time.monotonic() + budget_seconds(gate)


def bounded_timeout(deadline: float, cap_seconds: int) -> int:
    """Clip one child process timeout to the remaining gate-wide budget."""

    if isinstance(cap_seconds, bool) or not isinstance(cap_seconds, int) or cap_seconds <= 0:
        raise GateDeadlineError("validation timeout cap must be a positive integer")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 0
    # Floor rather than round up: a child cannot extend the enclosing deadline.
    return min(cap_seconds, int(remaining))
