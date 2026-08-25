from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.purple_runtime.catalog import certified_abilities
from redagent_platform.purple_runtime.compiler import compile_ability_plan
from redagent_platform.purple_runtime.contracts import AbilityApproval, AbilityAuthorization, LabBinding, manifest_sha256
from redagent_platform.purple_runtime.provisioning import register_purple_capability
from redagent_platform.purple_runtime.repository import PurpleRuntimeRepository


ROOT = Path(__file__).resolve().parents[2]


def test_r111_repository_persists_exact_approval_plan_run_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    now = datetime(2026, 7, 12, tzinfo=timezone.utc); tenant = f"tenant-r111-{uuid4().hex[:8]}"
    ability = certified_abilities()["r111-file-stage-marker-v1"]; digest = manifest_sha256(ability)
    lab = LabBinding(binding_id="lab-r111", target_id="target-r111-owned", runner_id="runner-r111", snapshot_sha256="b" * 64,
        telemetry_collector_id="collector-r111-owned", disposable=True, production=False, egress_allowed=False, expires_at=now + timedelta(minutes=10))
    approval = AbilityApproval(approval_id="approval-r111", ability_id=ability.ability_id, ability_sha256=digest,
        adapter_sha256=ability.adapter_sha256, lab_binding_id=lab.binding_id, lab_snapshot_sha256=lab.snapshot_sha256,
        requester_id="operator-r111", approver_id="reviewer-r111", executor_id=lab.runner_id,
        approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    authorization = AbilityAuthorization(authorization_id="auth-r111", policy_decision_id="policy-r111", policy_revision="r111-v1",
        roe_revision="roe-r111", reservation_id="reservation-r111", lease_id="lease-r111", kill_switch_id="kill-r111",
        quota_id="quota-r111", ability_sha256=digest, lab_snapshot_sha256=lab.snapshot_sha256,
        approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    compiled = compile_ability_plan(ability=ability, approval=approval, lab=lab, authorization=authorization, now=now)
    settings = load_database_settings(ROOT, env=os.environ); engine = create_async_engine(settings.url); factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory.begin() as session:
            registered = await register_purple_capability(session, workspace=ROOT, tenant_id=tenant,
                actor_user_id="operator-r111", correlation_id="corr-r111-capability", occurred_at=now)
            assert registered["capability_id"] == "purple-lab"
            repository = PurpleRuntimeRepository(session, tenant_id=tenant, actor_user_id="operator-r111", correlation_id="corr-r111")
            foundation = await repository.certify_foundation(occurred_at=now); assert foundation["ability"]["ability_sha256"] == digest
            await repository.register_lab(lab=lab, occurred_at=now); await repository.store_approval(approval=approval, occurred_at=now)
            await repository.store_plan(plan_id="plan-r111", compiled=compiled, approval=approval, authorization=authorization, occurred_at=now)
            run = await repository.create_run(run_id="run-r111", plan_id="plan-r111", job_id="job-r111", runner_id="runner-r111", occurred_at=now)
            killed = await repository.request_kill(run_id="run-r111", expected_version=run["version"], occurred_at=now)
            assert killed["dispatch_blocked"] is True and killed["run_state"] == "kill_requested"
            dashboard = await repository.dashboard(); assert len(dashboard["abilities"]) == 1 and len(dashboard["runs"]) == 1
            assert len(dashboard["lab_options"]) == 1
            assert dashboard["lab_options"][0]["binding_state"] == "active-disposable-owned"
            assert len(dashboard["approval_options"]) == 1
            assert dashboard["approval_options"][0]["approval_state"] == "approved-exact"
            assert dashboard["runner_options"] == [] and dashboard["job_options"] == [] and dashboard["reservation_options"] == []
        async with factory.begin() as session:
            other = await PurpleRuntimeRepository(session, tenant_id=f"other-{tenant}", actor_user_id="operator-r111", correlation_id="corr-r111-other").dashboard()
            assert all(not rows for rows in other.values())
    finally:
        await engine.dispose()
