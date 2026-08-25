"""Deterministic compat_111 fixtures shared by tests and owned qualification tooling."""

from datetime import datetime, timedelta

from redagent_platform.purple_runtime.catalog import certified_abilities
from redagent_platform.purple_runtime.compiler import CompiledAbilityPlan, compile_ability_plan
from redagent_platform.purple_runtime.contracts import AbilityApproval, AbilityAuthorization, LabBinding, manifest_sha256


def compiled_marker_plan(*, now: datetime) -> CompiledAbilityPlan:
    ability = certified_abilities()["r111-file-stage-marker-v1"]; digest = manifest_sha256(ability)
    lab = LabBinding(binding_id="lab-r111", target_id="target-r111-owned", runner_id="runner-r111",
        snapshot_sha256="b" * 64, telemetry_collector_id="collector-r111-owned", disposable=True,
        production=False, egress_allowed=False, expires_at=now + timedelta(minutes=10))
    approval = AbilityApproval(approval_id="approval-r111", ability_id=ability.ability_id, ability_sha256=digest,
        adapter_sha256=ability.adapter_sha256, lab_binding_id=lab.binding_id, lab_snapshot_sha256=lab.snapshot_sha256,
        requester_id="operator-r111", approver_id="reviewer-r111", executor_id=lab.runner_id,
        approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    authorization = AbilityAuthorization(authorization_id="auth-r111", policy_decision_id="policy-r111",
        policy_revision="r111-v1", roe_revision="roe-r111", reservation_id="reservation-r111", lease_id="lease-r111",
        kill_switch_id="kill-r111", quota_id="quota-r111", ability_sha256=digest,
        lab_snapshot_sha256=lab.snapshot_sha256, approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    return compile_ability_plan(ability=ability, approval=approval, lab=lab, authorization=authorization, now=now)
