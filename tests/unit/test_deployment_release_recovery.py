from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from redagent_platform.deployment_release.recovery import (
    DrillEvent,
    RecoveryComponent,
    advance_recovery_drill,
    build_recovery_catalog,
    build_restore_plan,
    start_recovery_drill,
    validate_recovery_catalog,
)


NOW = datetime(2026, 7, 12, 9, tzinfo=UTC)


def test_complete_catalog_builds_dependency_ordered_isolated_restore_plan() -> None:
    catalog = build_recovery_catalog(created_at=NOW - timedelta(minutes=15))
    validation = validate_recovery_catalog(catalog, now=NOW)
    plan = build_restore_plan(catalog, now=NOW)

    assert validation.accepted
    assert plan.isolated_environment_required
    assert plan.steps.index(RecoveryComponent.POSTGRESQL) < plan.steps.index(RecoveryComponent.TEMPORAL)
    assert plan.steps.index(RecoveryComponent.OPENBAO) < plan.steps.index(RecoveryComponent.APPLICATION_CONFIG)
    assert set(plan.steps) == set(RecoveryComponent)
    assert plan.production_qualified is False


def test_incomplete_stale_or_tampered_backup_catalog_is_rejected() -> None:
    catalog = build_recovery_catalog(created_at=NOW - timedelta(minutes=15))
    incomplete = replace(catalog, artifacts=catalog.artifacts[:-1])
    assert "missing_backup_component:application_config" in validate_recovery_catalog(incomplete, now=NOW).gaps

    stale = replace(catalog, created_at=NOW - timedelta(minutes=catalog.rpo_minutes + 1))
    assert "backup_set_outside_rpo" in validate_recovery_catalog(stale, now=NOW).gaps

    altered = replace(catalog.artifacts[0], observed_sha256="0" * 64)
    tampered = replace(catalog, artifacts=(altered, *catalog.artifacts[1:]))
    assert f"backup_digest_mismatch:{altered.component.value}" in validate_recovery_catalog(tampered, now=NOW).gaps


def test_recovery_drill_requires_integrity_semantic_audit_and_cleanup_evidence() -> None:
    plan = build_restore_plan(build_recovery_catalog(created_at=NOW - timedelta(minutes=5)), now=NOW)
    drill = start_recovery_drill(plan, started_at=NOW)

    with pytest.raises(ValueError, match="recovery_drill_event_out_of_order"):
        advance_recovery_drill(drill, DrillEvent.SEMANTIC_VERIFIED, evidence_sha256="1" * 64, occurred_at=NOW)

    for event in (
        DrillEvent.INTEGRITY_VERIFIED,
        DrillEvent.ISOLATED_RESTORE_COMPLETED,
        DrillEvent.SEMANTIC_VERIFIED,
        DrillEvent.AUDIT_VERIFIED,
        DrillEvent.CLEANUP_VERIFIED,
    ):
        drill = advance_recovery_drill(drill, event, evidence_sha256="1" * 64, occurred_at=NOW)
    assert drill.completed
    assert drill.production_qualified is False
    assert len(drill.evidence_sha256s) == 5
