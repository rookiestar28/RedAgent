"""Closed compat_111 compiler binding reviewed ability, approval, lab, and authorization."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json

from redagent_platform.purple_runtime.contracts import AbilityApproval, AbilityAuthorization, AbilityManifest, LabBinding, manifest_sha256


@dataclass(frozen=True, kw_only=True)
class CompiledAbilityPlan:
    ability_id: str; ability_sha256: str; attack_technique_id: str; adapter_id: str; adapter_sha256: str
    lab_binding_id: str; target_id: str; runner_id: str; lab_snapshot_sha256: str; telemetry_collector_id: str
    detection_strategy_id: str; analytic_id: str; event_schema: str; marker_relative_path: str; marker_sha256: str
    timeout_seconds: int; lease_id: str; kill_switch_id: str; network_allowed: bool; subprocess_allowed: bool
    external_content_allowed: bool; plan_sha256: str


def compile_ability_plan(*, ability: AbilityManifest, approval: AbilityApproval, lab: LabBinding,
                         authorization: AbilityAuthorization, now: datetime) -> CompiledAbilityPlan:
    _active(now, approval.approved_at, approval.expires_at, "purple_approval_inactive")
    _active(now, authorization.approved_at, authorization.expires_at, "purple_authorization_inactive")
    if now >= lab.expires_at:
        raise ValueError("purple_lab_binding_inactive")
    if not lab.disposable or lab.production or lab.egress_allowed:
        raise ValueError("purple_lab_boundary_invalid")
    digest = manifest_sha256(ability)
    if approval.ability_id != ability.ability_id or approval.ability_sha256 != digest or authorization.ability_sha256 != digest:
        raise ValueError("purple_approval_digest_mismatch")
    if approval.adapter_sha256 != ability.adapter_sha256:
        raise ValueError("purple_adapter_digest_mismatch")
    if approval.lab_binding_id != lab.binding_id or approval.lab_snapshot_sha256 != lab.snapshot_sha256 or authorization.lab_snapshot_sha256 != lab.snapshot_sha256:
        raise ValueError("purple_lab_snapshot_mismatch")
    if approval.executor_id != lab.runner_id or ability.detection.collector_id != lab.telemetry_collector_id:
        raise ValueError("purple_runner_or_collector_mismatch")
    values = dict(ability_id=ability.ability_id, ability_sha256=digest, attack_technique_id=ability.attack_technique_id,
        adapter_id=ability.adapter_id, adapter_sha256=ability.adapter_sha256, lab_binding_id=lab.binding_id,
        target_id=lab.target_id, runner_id=lab.runner_id, lab_snapshot_sha256=lab.snapshot_sha256,
        telemetry_collector_id=lab.telemetry_collector_id, detection_strategy_id=ability.detection.strategy_id,
        analytic_id=ability.detection.analytic_id, event_schema=ability.detection.event_schema,
        marker_relative_path=ability.marker_relative_path, marker_sha256=ability.marker_sha256,
        timeout_seconds=ability.timeout_seconds, lease_id=authorization.lease_id, kill_switch_id=authorization.kill_switch_id,
        network_allowed=False, subprocess_allowed=False, external_content_allowed=False)
    return CompiledAbilityPlan(**values, plan_sha256=_plan_digest(values))


def verify_plan_integrity(plan: CompiledAbilityPlan) -> None:
    values = asdict(plan); asserted = values.pop("plan_sha256")
    if asserted != _plan_digest(values):
        raise ValueError("purple_plan_integrity_invalid")
    if plan.network_allowed or plan.subprocess_allowed or plan.external_content_allowed:
        raise ValueError("purple_plan_execution_boundary_invalid")


def _plan_digest(values: dict[str, object]) -> str:
    material = {"schema": "redagent.r111-ability-plan/v1", **values}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _active(now: datetime, start: datetime, end: datetime, error: str) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("purple_time_invalid")
    if now < start or now >= end:
        raise ValueError(error)
