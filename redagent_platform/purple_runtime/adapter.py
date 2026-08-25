"""Typed owned marker adapter; contains no shell, subprocess, network, or caller payload."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import Path

from redagent_platform.purple_runtime.catalog import MARKER_BYTES
from redagent_platform.purple_runtime.compiler import CompiledAbilityPlan, verify_plan_integrity


@dataclass(frozen=True, kw_only=True)
class PrepareReceipt:
    run_id: str; before_entry_count: int; inventory_sha256: str; occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class ExecuteReceipt:
    run_id: str; marker_path: str; marker_sha256: str; network_contact_count: int
    subprocess_count: int; privilege_use_count: int; occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class CleanupReceipt:
    run_id: str; residual_resource_count: int; teardown_verified: bool; inventory_sha256: str; occurred_at: datetime


class OwnedMarkerAdapter:
    def __init__(self, *, workspace_root: Path) -> None:
        self._root = workspace_root.resolve()

    def prepare(self, *, plan: CompiledAbilityPlan, run_id: str, occurred_at: datetime) -> PrepareReceipt:
        marker = self._marker(plan); marker.parent.mkdir(parents=True, exist_ok=True)
        entries = (marker.name,) if marker.exists() else ()
        return PrepareReceipt(run_id=run_id, before_entry_count=len(entries), inventory_sha256=_inventory(entries), occurred_at=occurred_at)

    def execute(self, *, plan: CompiledAbilityPlan, run_id: str, occurred_at: datetime) -> ExecuteReceipt:
        marker = self._marker(plan)
        marker.parent.mkdir(parents=True, exist_ok=True)
        # CRITICAL: this fixed direct write must never become a shell or caller-supplied command/content path.
        marker.write_bytes(MARKER_BYTES)
        if hashlib.sha256(marker.read_bytes()).hexdigest() != plan.marker_sha256:
            raise ValueError("purple_marker_integrity_invalid")
        return ExecuteReceipt(run_id=run_id, marker_path=str(marker), marker_sha256=plan.marker_sha256,
            network_contact_count=0, subprocess_count=0, privilege_use_count=0, occurred_at=occurred_at)

    def cleanup(self, *, plan: CompiledAbilityPlan, run_id: str, occurred_at: datetime) -> CleanupReceipt:
        marker = self._marker(plan)
        marker.unlink(missing_ok=True)
        residual = (marker.name,) if marker.exists() else ()
        try:
            marker.parent.rmdir()
        except OSError:
            pass
        if residual:
            raise ValueError("purple_cleanup_residual_resources")
        return CleanupReceipt(run_id=run_id, residual_resource_count=0, teardown_verified=True,
            inventory_sha256=_inventory(residual), occurred_at=occurred_at)

    def _marker(self, plan: CompiledAbilityPlan) -> Path:
        verify_plan_integrity(plan)
        expected = (self._root / ".local" / "r111-labs" / plan.lab_binding_id / "r111-file-stage-marker-v1.marker").resolve()
        boundary = (self._root / ".local" / "r111-labs").resolve()
        if expected.name != plan.marker_relative_path or boundary not in expected.parents:
            raise ValueError("purple_marker_path_invalid")
        return expected


def _inventory(entries: tuple[str, ...]) -> str:
    return hashlib.sha256("\n".join(sorted(entries)).encode()).hexdigest()
