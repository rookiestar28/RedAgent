from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redagent_platform.deployment_release.upgrade import (
    UpgradeEvent,
    UpgradePhase,
    advance_upgrade,
    plan_upgrade,
)


NOW = datetime(2026, 7, 12, 10, tzinfo=UTC)


def test_n_minus_one_upgrade_enforces_expand_backfill_ramp_drain_contract_order() -> None:
    state = plan_upgrade(
        current_version="1.8.4",
        target_version="1.9.0",
        current_schema=22,
        expanded_schema=23,
        contract_schema=24,
        old_worker_build="worker-1.8.4",
        new_worker_build="worker-1.9.0",
        now=NOW,
    )
    assert state.phase is UpgradePhase.PLANNED
    for event in (
        UpgradeEvent.BACKUP_VERIFIED,
        UpgradeEvent.EXPAND_APPLIED,
        UpgradeEvent.BACKFILL_VERIFIED,
        UpgradeEvent.NEW_WORKER_STARTED,
        UpgradeEvent.RAMP_VERIFIED,
        UpgradeEvent.OLD_WORKER_DRAINED,
        UpgradeEvent.CONTRACT_APPLIED,
        UpgradeEvent.COMPLETED,
    ):
        state = advance_upgrade(state, event, evidence_sha256="2" * 64, occurred_at=NOW)
    assert state.phase is UpgradePhase.COMPLETED
    assert state.production_qualified is False
    assert state.old_worker_reachable is False


def test_contract_and_old_worker_removal_fail_before_backfill_and_drain() -> None:
    state = plan_upgrade(
        current_version="1.8.4", target_version="1.9.0", current_schema=22,
        expanded_schema=23, contract_schema=24, old_worker_build="old", new_worker_build="new", now=NOW,
    )
    with pytest.raises(ValueError, match="upgrade_event_out_of_order"):
        advance_upgrade(state, UpgradeEvent.CONTRACT_APPLIED, evidence_sha256="2" * 64, occurred_at=NOW)
    with pytest.raises(ValueError, match="upgrade_event_out_of_order"):
        advance_upgrade(state, UpgradeEvent.OLD_WORKER_DRAINED, evidence_sha256="2" * 64, occurred_at=NOW)


def test_unsupported_major_jump_and_failed_migration_produce_safe_recovery_decision() -> None:
    with pytest.raises(ValueError, match="upgrade_n_minus_one_compatibility_required"):
        plan_upgrade(
            current_version="1.8.4", target_version="3.0.0", current_schema=22,
            expanded_schema=23, contract_schema=24, old_worker_build="old", new_worker_build="new", now=NOW,
        )
    state = plan_upgrade(
        current_version="1.8.4", target_version="1.9.0", current_schema=22,
        expanded_schema=23, contract_schema=24, old_worker_build="old", new_worker_build="new", now=NOW,
    )
    failed = advance_upgrade(state, UpgradeEvent.MIGRATION_FAILED, evidence_sha256="2" * 64, occurred_at=NOW)
    assert failed.phase is UpgradePhase.ROLLBACK_REQUIRED
    assert failed.recovery_decision == "rollback_compatible_code_and_preserve_expanded_schema"
