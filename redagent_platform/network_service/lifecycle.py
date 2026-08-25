"""Fail-closed compat_107 cancellation, stop, and cleanup ordering."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum


class NetworkRunState(str, Enum):
    RUNNING = "running"
    CANCELLING = "cancelling"
    CLEANING = "cleaning"
    CANCELLED = "cancelled"


@dataclass(frozen=True, kw_only=True)
class NetworkRunLifecycle:
    run_id: str
    state: NetworkRunState
    gateway_blocked: bool
    worker_stop_acknowledged: bool
    cooperative_stop: bool | None
    residual_resource_count: int | None
    events: tuple[str, ...]

    @classmethod
    def start(cls, run_id: str) -> "NetworkRunLifecycle":
        if not run_id or not run_id.strip():
            raise ValueError("network_run_id_required")
        return cls(
            run_id=run_id.strip(), state=NetworkRunState.RUNNING,
            gateway_blocked=False, worker_stop_acknowledged=False,
            cooperative_stop=None, residual_resource_count=None,
            events=("run_started",),
        )

    def request_cancel(self) -> "NetworkRunLifecycle":
        if self.state is not NetworkRunState.RUNNING:
            raise ValueError("network_cancel_state_invalid")
        # CRITICAL: block new network connections before asking the worker to stop.
        return replace(
            self, state=NetworkRunState.CANCELLING, gateway_blocked=True,
            events=self.events + ("gateway_blocked",),
        )

    def acknowledge_worker_stop(self, *, cooperative: bool) -> "NetworkRunLifecycle":
        if self.state is not NetworkRunState.CANCELLING or not self.gateway_blocked:
            raise ValueError("network_worker_stop_before_gateway_block")
        event = "worker_stop_acknowledged" if cooperative else "worker_forced_termination"
        return replace(
            self, state=NetworkRunState.CLEANING, worker_stop_acknowledged=True,
            cooperative_stop=cooperative, events=self.events + (event,),
        )

    def complete_cleanup(
        self, *, container_count: int, network_count: int, transient_file_count: int
    ) -> "NetworkRunLifecycle":
        if self.state is not NetworkRunState.CLEANING or not self.worker_stop_acknowledged:
            raise ValueError("network_cleanup_before_stop")
        counts = (container_count, network_count, transient_file_count)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise ValueError("network_cleanup_count_invalid")
        residual = sum(counts)
        if residual:
            raise ValueError("network_cleanup_residual_resources")
        return replace(
            self, state=NetworkRunState.CANCELLED, residual_resource_count=0,
            events=self.events + ("cleanup_zero_residual",),
        )
