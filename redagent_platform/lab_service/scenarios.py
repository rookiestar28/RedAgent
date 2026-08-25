"""Fixed compat_103 golden scenario registry and restart-safe state transitions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum


REQUIRED_GOLDEN_SCENARIOS = frozenset({
    "fresh_install_first_campaign", "authorize_deny", "independent_approval",
    "workflow_restart", "duplicate_retry", "evidence_redaction",
    "finding_ingest_dedup", "synthetic_summary", "cancel_kill", "hard_quota",
    "credential_revoke", "policy_update", "dependency_outage",
    "local_backup_restore", "schema_migration", "incident_telemetry",
    "emergency_stop", "verified_teardown",
})


class ScenarioStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    COMPENSATING = "compensating"
    CLEANED = "cleaned"


@dataclass(frozen=True, kw_only=True)
class GoldenScenarioDefinition:
    scenario_id: str
    prerequisites: tuple[str, ...]
    expected_receipts: tuple[str, ...]
    compensation_steps: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True, kw_only=True)
class ScenarioState:
    run_id: str
    scenario_id: str
    status: ScenarioStatus
    current_step: int
    version: int
    last_action_id: str | None
    reason_code: str


def golden_scenario_registry() -> dict[str, GoldenScenarioDefinition]:
    specialized = {
        "evidence_redaction": ("evidence",),
        "finding_ingest_dedup": ("finding", "evidence"),
        "synthetic_summary": ("finding",),
        "dependency_outage": ("incident",),
        "incident_telemetry": ("incident",),
        "emergency_stop": ("incident",),
    }
    return {
        scenario_id: GoldenScenarioDefinition(
            scenario_id=scenario_id,
            prerequisites=("local_stack_ready", "lab_attestation_current"),
            expected_receipts=("audit", "outbox", "telemetry", "cleanup") + specialized.get(scenario_id, ()),
            compensation_steps=("stop_new_dispatch", "revoke_lab_lease", "verify_cleanup"),
            timeout_seconds=300 if scenario_id in {
                "fresh_install_first_campaign", "local_backup_restore", "schema_migration",
            } else 120,
        )
        for scenario_id in sorted(REQUIRED_GOLDEN_SCENARIOS)
    }


def advance_scenario(
    state: ScenarioState, *, action_id: str, expected_version: int,
    next_status: ScenarioStatus, reason_code: str,
) -> ScenarioState:
    if state.scenario_id not in REQUIRED_GOLDEN_SCENARIOS:
        raise ValueError("scenario_id_unknown")
    if state.last_action_id == action_id:
        return state
    if expected_version != state.version:
        raise ValueError("scenario_version_conflict")
    allowed = {
        ScenarioStatus.PENDING: {ScenarioStatus.RUNNING},
        ScenarioStatus.RUNNING: {
            ScenarioStatus.SUCCEEDED, ScenarioStatus.FAILED, ScenarioStatus.COMPENSATING,
        },
        ScenarioStatus.FAILED: {ScenarioStatus.COMPENSATING},
        ScenarioStatus.COMPENSATING: {ScenarioStatus.CLEANED},
        ScenarioStatus.SUCCEEDED: {ScenarioStatus.CLEANED},
        ScenarioStatus.CLEANED: set(),
    }
    if next_status not in allowed[state.status]:
        raise ValueError("scenario_transition_invalid")
    return replace(
        state, status=next_status, current_step=state.current_step + 1,
        version=state.version + 1, last_action_id=action_id, reason_code=reason_code,
    )
