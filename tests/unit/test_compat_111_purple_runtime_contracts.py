from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.purple_runtime.catalog import certified_abilities
from redagent_platform.purple_runtime.compiler import compile_ability_plan
from redagent_platform.purple_runtime.contracts import AbilityApproval, AbilityAuthorization, LabBinding, manifest_sha256


NOW = datetime(2026, 7, 11, 15, 0, tzinfo=timezone.utc)


def _inputs(**approval_overrides):
    ability = certified_abilities()["r111-file-stage-marker-v1"]
    digest = manifest_sha256(ability)
    approval_values = dict(approval_id="approval-r111", ability_id=ability.ability_id, ability_sha256=digest,
        adapter_sha256=ability.adapter_sha256, lab_binding_id="lab-r111", lab_snapshot_sha256="b" * 64,
        requester_id="operator-r111", approver_id="reviewer-r111", executor_id="runner-r111",
        approved_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=10))
    approval_values.update(approval_overrides)
    lab = LabBinding(binding_id="lab-r111", target_id="target-r111-owned", runner_id="runner-r111",
        snapshot_sha256="b" * 64, telemetry_collector_id="collector-r111-owned",
        disposable=True, production=False, egress_allowed=False, expires_at=NOW + timedelta(minutes=10))
    authorization = AbilityAuthorization(authorization_id="auth-r111", policy_decision_id="policy-r111",
        policy_revision="r111-v1", roe_revision="roe-r111", reservation_id="reservation-r111",
        lease_id="lease-r111", kill_switch_id="kill-r111", quota_id="quota-r111",
        ability_sha256=digest, lab_snapshot_sha256="b" * 64,
        approved_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=10))
    return ability, AbilityApproval(**approval_values), lab, authorization


def test_certified_ability_compiles_to_deterministic_closed_plan():
    ability, approval, lab, authorization = _inputs()
    first = compile_ability_plan(ability=ability, approval=approval, lab=lab, authorization=authorization, now=NOW)
    second = compile_ability_plan(ability=ability, approval=approval, lab=lab, authorization=authorization, now=NOW)
    assert first == second
    assert first.attack_technique_id == "T1074.001"
    assert first.network_allowed is False and first.subprocess_allowed is False
    assert first.marker_relative_path == "r111-file-stage-marker-v1.marker"


def test_compiler_rejects_self_approval_digest_drift_production_and_expiry():
    with pytest.raises(ValueError, match="purple_approval_separation_invalid"):
        _inputs(approver_id="operator-r111")
    ability, approval, lab, authorization = _inputs(ability_sha256="c" * 64)
    with pytest.raises(ValueError, match="purple_approval_digest_mismatch"):
        compile_ability_plan(ability=ability, approval=approval, lab=lab, authorization=authorization, now=NOW)
    ability, approval, lab, authorization = _inputs()
    bad_lab = LabBinding(**{**lab.__dict__, "production": True})
    with pytest.raises(ValueError, match="purple_lab_boundary_invalid"):
        compile_ability_plan(ability=ability, approval=approval, lab=bad_lab, authorization=authorization, now=NOW)
    with pytest.raises(ValueError, match="purple_authorization_inactive"):
        compile_ability_plan(ability=ability, approval=approval, lab=lab,
            authorization=AbilityAuthorization(**{**authorization.__dict__, "expires_at": NOW}), now=NOW)
