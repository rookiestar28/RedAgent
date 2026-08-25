"""N-1 compatible expand/backfill/contract upgrade state machine."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
import re


class UpgradePhase(str, Enum):
    PLANNED = "planned"
    BACKUP_VERIFIED = "backup_verified"
    EXPANDED = "expanded"
    BACKFILLED = "backfilled"
    N_MINUS_ONE_ACTIVE = "n_minus_one_active"
    RAMP_VERIFIED = "ramp_verified"
    OLD_WORKER_DRAINED = "old_worker_drained"
    CONTRACTED = "contracted"
    COMPLETED = "completed"
    ROLLBACK_REQUIRED = "rollback_required"


class UpgradeEvent(str, Enum):
    BACKUP_VERIFIED = "backup_verified"
    EXPAND_APPLIED = "expand_applied"
    BACKFILL_VERIFIED = "backfill_verified"
    NEW_WORKER_STARTED = "new_worker_started"
    RAMP_VERIFIED = "ramp_verified"
    OLD_WORKER_DRAINED = "old_worker_drained"
    CONTRACT_APPLIED = "contract_applied"
    COMPLETED = "completed"
    MIGRATION_FAILED = "migration_failed"


@dataclass(frozen=True, kw_only=True)
class UpgradeState:
    current_version: str
    target_version: str
    current_schema: int
    expanded_schema: int
    contract_schema: int
    old_worker_build: str
    new_worker_build: str
    phase: UpgradePhase
    old_worker_reachable: bool
    new_worker_ramp_percent: int
    evidence_sha256s: tuple[str, ...]
    recovery_decision: str
    started_at: datetime
    production_qualified: bool = False


_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_ORDER: dict[UpgradePhase, tuple[UpgradeEvent, UpgradePhase]] = {
    UpgradePhase.PLANNED: (UpgradeEvent.BACKUP_VERIFIED, UpgradePhase.BACKUP_VERIFIED),
    UpgradePhase.BACKUP_VERIFIED: (UpgradeEvent.EXPAND_APPLIED, UpgradePhase.EXPANDED),
    UpgradePhase.EXPANDED: (UpgradeEvent.BACKFILL_VERIFIED, UpgradePhase.BACKFILLED),
    UpgradePhase.BACKFILLED: (UpgradeEvent.NEW_WORKER_STARTED, UpgradePhase.N_MINUS_ONE_ACTIVE),
    UpgradePhase.N_MINUS_ONE_ACTIVE: (UpgradeEvent.RAMP_VERIFIED, UpgradePhase.RAMP_VERIFIED),
    UpgradePhase.RAMP_VERIFIED: (UpgradeEvent.OLD_WORKER_DRAINED, UpgradePhase.OLD_WORKER_DRAINED),
    UpgradePhase.OLD_WORKER_DRAINED: (UpgradeEvent.CONTRACT_APPLIED, UpgradePhase.CONTRACTED),
    UpgradePhase.CONTRACTED: (UpgradeEvent.COMPLETED, UpgradePhase.COMPLETED),
}


def plan_upgrade(
    *,
    current_version: str,
    target_version: str,
    current_schema: int,
    expanded_schema: int,
    contract_schema: int,
    old_worker_build: str,
    new_worker_build: str,
    now: datetime,
) -> UpgradeState:
    _aware(now)
    current = _parse(current_version)
    target = _parse(target_version)
    if target <= current or target[0] != current[0] or target[1] - current[1] > 1:
        raise ValueError("upgrade_n_minus_one_compatibility_required")
    if not current_schema < expanded_schema <= contract_schema:
        raise ValueError("upgrade_schema_sequence_invalid")
    if not old_worker_build or not new_worker_build or old_worker_build == new_worker_build:
        raise ValueError("upgrade_worker_builds_invalid")
    return UpgradeState(
        current_version=current_version,
        target_version=target_version,
        current_schema=current_schema,
        expanded_schema=expanded_schema,
        contract_schema=contract_schema,
        old_worker_build=old_worker_build,
        new_worker_build=new_worker_build,
        phase=UpgradePhase.PLANNED,
        old_worker_reachable=True,
        new_worker_ramp_percent=0,
        evidence_sha256s=(),
        recovery_decision="rollback_compatible_code_before_contract",
        started_at=now,
    )


def advance_upgrade(
    state: UpgradeState,
    event: UpgradeEvent,
    *,
    evidence_sha256: str,
    occurred_at: datetime,
) -> UpgradeState:
    _aware(occurred_at)
    if occurred_at < state.started_at or not _sha(evidence_sha256):
        raise ValueError("upgrade_evidence_invalid")
    if event is UpgradeEvent.MIGRATION_FAILED:
        decision = (
            "forward_recovery_required_after_contract"
            if state.phase in {UpgradePhase.CONTRACTED, UpgradePhase.COMPLETED}
            else "rollback_compatible_code_and_preserve_expanded_schema"
        )
        return replace(
            state,
            phase=UpgradePhase.ROLLBACK_REQUIRED,
            recovery_decision=decision,
            evidence_sha256s=(*state.evidence_sha256s, evidence_sha256),
        )
    expected = _ORDER.get(state.phase)
    if expected is None or expected[0] is not event:
        raise ValueError("upgrade_event_out_of_order")
    values: dict[str, object] = {
        "phase": expected[1],
        "evidence_sha256s": (*state.evidence_sha256s, evidence_sha256),
    }
    if event is UpgradeEvent.NEW_WORKER_STARTED:
        values["new_worker_ramp_percent"] = 1
    elif event is UpgradeEvent.RAMP_VERIFIED:
        values["new_worker_ramp_percent"] = 100
    elif event is UpgradeEvent.OLD_WORKER_DRAINED:
        values["old_worker_reachable"] = False
    elif event is UpgradeEvent.CONTRACT_APPLIED:
        values["recovery_decision"] = "forward_recovery_required_after_contract"
    return replace(state, **values)


def _parse(value: str) -> tuple[int, int, int]:
    match = _VERSION.fullmatch(value)
    if match is None:
        raise ValueError("upgrade_version_invalid")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _sha(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("upgrade_time_timezone_required")
